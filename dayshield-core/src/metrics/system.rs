//! System metrics collector: CPU, RAM, load average, temperature and uptime.
//!
//! All data is read directly from the Linux `/proc` and `/sys` virtual
//! file-systems; no external crates beyond `tokio` are required.

use tokio::fs;
use tracing::warn;

use crate::metrics::SystemMetrics;

// ---------------------------------------------------------------------------
// CPU usage
// ---------------------------------------------------------------------------

/// Raw `/proc/stat` CPU-time counters for the first line (`cpu` aggregate).
#[derive(Clone, Copy, Default)]
pub struct CpuStat {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuStat {
    /// Total time (all ticks).
    pub fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    /// Idle time (idle + iowait).
    pub fn idle_total(&self) -> u64 {
        self.idle + self.iowait
    }
}

/// Parse the first line of `/proc/stat` into a [`CpuStat`].
///
/// The format is: `cpu  user nice system idle iowait irq softirq steal …`
pub fn parse_cpu_stat(content: &str) -> Option<CpuStat> {
    let line = content.lines().find(|l| l.starts_with("cpu "))?;
    let mut parts = line.split_whitespace().skip(1);
    let user = parts.next()?.parse().ok()?;
    let nice = parts.next()?.parse().ok()?;
    let system = parts.next()?.parse().ok()?;
    let idle = parts.next()?.parse().ok()?;
    let iowait = parts.next()?.parse().unwrap_or(0);
    let irq = parts.next()?.parse().unwrap_or(0);
    let softirq = parts.next()?.parse().unwrap_or(0);
    let steal = parts.next()?.parse().unwrap_or(0);
    Some(CpuStat { user, nice, system, idle, iowait, irq, softirq, steal })
}

/// Calculate CPU usage percentage given two consecutive [`CpuStat`] readings.
pub fn cpu_percent(prev: &CpuStat, curr: &CpuStat) -> f64 {
    let total_delta = curr.total().saturating_sub(prev.total());
    let idle_delta = curr.idle_total().saturating_sub(prev.idle_total());
    if total_delta == 0 {
        return 0.0;
    }
    let used = total_delta.saturating_sub(idle_delta);
    (used as f64 / total_delta as f64) * 100.0
}

// ---------------------------------------------------------------------------
// Memory usage
// ---------------------------------------------------------------------------

/// Parse `/proc/meminfo` and return `(percent, used_bytes, total_bytes)`.
///
/// Returns `(0.0, 0, 0)` if parsing fails.
pub fn parse_ram_metrics(content: &str) -> (f64, u64, u64) {
    let mut total: Option<u64> = None;
    let mut available: Option<u64> = None;

    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            total = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
        } else if line.starts_with("MemAvailable:") {
            available = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
        }
        if total.is_some() && available.is_some() {
            break;
        }
    }

    match (total, available) {
        (Some(t), Some(a)) if t > 0 => {
            let used = t.saturating_sub(a);
            let percent = (used as f64 / t as f64) * 100.0;
            (percent, used * 1024, t * 1024)  // Convert from KiB to bytes
        }
        _ => (0.0, 0, 0),
    }
}

/// Parse `/proc/meminfo` and return RAM utilisation as a percentage.
///
/// Returns `0.0` if parsing fails.
pub fn parse_ram_percent(content: &str) -> f64 {
    let (percent, _, _) = parse_ram_metrics(content);
    percent
}

// ---------------------------------------------------------------------------
// Load average
// ---------------------------------------------------------------------------

/// Parse `/proc/loadavg` and return `(load1, load5, load15)`.
///
/// Returns `(0.0, 0.0, 0.0)` on parse failure.
pub fn parse_loadavg(content: &str) -> (f64, f64, f64) {
    let mut parts = content.split_whitespace();
    let l1 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let l5 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let l15 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    (l1, l5, l15)
}

// ---------------------------------------------------------------------------
// Temperature
// ---------------------------------------------------------------------------

/// Read the first available CPU temperature from `/sys/class/thermal`.
///
/// Returns `0.0` if no thermal zone is available or all reads fail.
pub async fn read_temperature_c() -> f64 {
    let base = "/sys/class/thermal";
    let mut read_dir = match fs::read_dir(base).await {
        Ok(d) => d,
        Err(_) => return 0.0,
    };

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("thermal_zone") {
            continue;
        }

        // Check type — look for "x86_pkg_temp" or "cpu-thermal" first.
        let type_path = format!("{}/{}/type", base, name_str);
        let zone_type = fs::read_to_string(&type_path).await.unwrap_or_default();
        let zone_type = zone_type.trim();

        // Temperature in milli-Celsius.
        let temp_path = format!("{}/{}/temp", base, name_str);
        if let Ok(raw) = fs::read_to_string(&temp_path).await {
            if let Ok(milli) = raw.trim().parse::<i64>() {
                let celsius = milli as f64 / 1000.0;
                // Prefer known CPU thermal zones.
                if zone_type == "x86_pkg_temp" || zone_type.contains("cpu") {
                    return celsius;
                }
                // Fall back to any zone that looks like a sane temperature.
                if celsius > 0.0 && celsius < 150.0 {
                    return celsius;
                }
            }
        }
    }

    0.0
}

// ---------------------------------------------------------------------------
// Disk usage
// ---------------------------------------------------------------------------

/// Parse `df -B1` output for root filesystem usage.
///
/// Returns `(percent, used_bytes, total_bytes)` or `(0.0, 0, 0)` on failure.
pub fn parse_disk_usage(content: &str) -> (f64, u64, u64) {
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 2 {
        return (0.0, 0, 0);
    }

    let parts: Vec<&str> = lines[1].split_whitespace().collect();
    if parts.len() < 4 {
        return (0.0, 0, 0);
    }

    let total_bytes = parts[1].parse::<u64>().unwrap_or(0);
    let used_bytes = parts[2].parse::<u64>().unwrap_or(0);
    let percent_str = parts[4].trim_end_matches('%');
    let percent = percent_str.parse::<f64>().unwrap_or(0.0);

    (percent, used_bytes, total_bytes)
}

/// Read root-filesystem usage by calling `df -B1 /`.
pub async fn read_disk_usage() -> (f64, u64, u64) {
    let output = tokio::process::Command::new("df")
        .args(["-B1", "/"])
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            parse_disk_usage(&text)
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            warn!("metrics/system: df command failed: {}", stderr);
            (0.0, 0, 0)
        }
        Err(e) => {
            warn!("metrics/system: df command error: {}", e);
            (0.0, 0, 0)
        }
    }
}

// ---------------------------------------------------------------------------

/// Parse `/proc/uptime` and return uptime in whole seconds.
///
/// Returns `0` on failure.
pub fn parse_uptime(content: &str) -> u64 {
    content
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0) as u64
}

// ---------------------------------------------------------------------------
// Top-level collector
// ---------------------------------------------------------------------------

/// Collect a fresh [`SystemMetrics`] reading.
///
/// `prev_cpu` is the CPU stat from the previous collection tick.  Pass `None`
/// on the very first call; CPU usage will be reported as `0.0`.
pub async fn collect_system(prev_cpu: Option<&CpuStat>) -> (SystemMetrics, CpuStat) {
    // --- CPU ---
    let cpu_content = fs::read_to_string("/proc/stat").await.unwrap_or_default();
    let curr_cpu = parse_cpu_stat(&cpu_content).unwrap_or_default();
    let cpu_pct = match prev_cpu {
        Some(prev) => cpu_percent(prev, &curr_cpu),
        None => 0.0,
    };

    // --- RAM ---
    let mem_content = fs::read_to_string("/proc/meminfo").await.unwrap_or_default();
    let (ram_pct, ram_used_bytes, ram_total_bytes) = parse_ram_metrics(&mem_content);

    // --- Load average ---
    let load_content = fs::read_to_string("/proc/loadavg").await.unwrap_or_default();
    let (l1, l5, l15) = parse_loadavg(&load_content);

    // --- Temperature ---
    let temp = read_temperature_c().await;

    // --- Uptime ---
    let uptime_content = fs::read_to_string("/proc/uptime").await.unwrap_or_default();
    let uptime = parse_uptime(&uptime_content);

    // --- Disk ---
    let (disk_percent, disk_used_bytes, disk_total_bytes) = read_disk_usage().await;

    if cpu_pct.is_nan() || cpu_pct < 0.0 {
        warn!("metrics/system: unexpected CPU percent value: {}", cpu_pct);
    }

    (
        SystemMetrics {
            cpu_percent: cpu_pct.clamp(0.0, 100.0),
            ram_percent: ram_pct.clamp(0.0, 100.0),
            ram_used_bytes,
            ram_total_bytes,
            loadavg_1: l1,
            loadavg_5: l5,
            loadavg_15: l15,
            temperature_c: temp,
            uptime_seconds: uptime,
            disk_percent,
            disk_used_bytes,
            disk_total_bytes,
        },
        curr_cpu,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpu_stat_basic() {
        let content = "cpu  1000 200 300 4000 50 10 5 0 0 0\ncpu0 500 100 150 2000 25 5 2 0\n";
        let stat = parse_cpu_stat(content).expect("should parse cpu line");
        assert_eq!(stat.user, 1000);
        assert_eq!(stat.nice, 200);
        assert_eq!(stat.system, 300);
        assert_eq!(stat.idle, 4000);
        assert_eq!(stat.iowait, 50);
        assert_eq!(stat.irq, 10);
        assert_eq!(stat.softirq, 5);
        assert_eq!(stat.steal, 0);
    }

    #[test]
    fn test_cpu_percent_calculation() {
        let prev = CpuStat { user: 1000, nice: 0, system: 200, idle: 3800, iowait: 0, irq: 0, softirq: 0, steal: 0 };
        // 200ms of work out of 1000ms total → 20%
        let curr = CpuStat { user: 1150, nice: 0, system: 250, idle: 4550, iowait: 50, irq: 0, softirq: 0, steal: 0 };
        let pct = cpu_percent(&prev, &curr);
        // total_delta = 200; idle_delta = 800; used = -600 → clamped to 0 — wait, let me recalc
        // prev.total = 1000+200+3800 = 5000; curr.total = 1150+250+4550+50 = 6000 → delta = 1000
        // prev.idle_total = 3800; curr.idle_total = 4550+50 = 4600 → idle_delta = 800
        // used = 1000 - 800 = 200; pct = 20.0
        assert!((pct - 20.0).abs() < 0.01, "Expected ~20% got {}", pct);
    }

    #[test]
    fn test_cpu_percent_zero_delta() {
        let stat = CpuStat::default();
        assert_eq!(cpu_percent(&stat, &stat), 0.0);
    }

    #[test]
    fn test_parse_ram_percent() {
        let content = "MemTotal:       8000000 kB\nMemFree:        1000000 kB\nMemAvailable:   2000000 kB\n";
        let pct = parse_ram_percent(content);
        // used = 8_000_000 - 2_000_000 = 6_000_000; pct = 75.0
        assert!((pct - 75.0).abs() < 0.01, "Expected 75.0 got {}", pct);
    }

    #[test]
    fn test_parse_ram_percent_no_available() {
        let content = "MemTotal: 0 kB\n";
        assert_eq!(parse_ram_percent(content), 0.0);
    }

    #[test]
    fn test_parse_loadavg() {
        let content = "0.52 1.05 0.78 1/234 5678\n";
        let (l1, l5, l15) = parse_loadavg(content);
        assert!((l1 - 0.52).abs() < 0.001);
        assert!((l5 - 1.05).abs() < 0.001);
        assert!((l15 - 0.78).abs() < 0.001);
    }

    #[test]
    fn test_parse_uptime() {
        assert_eq!(parse_uptime("12345.67 23456.78\n"), 12345);
        assert_eq!(parse_uptime(""), 0);
    }
}
