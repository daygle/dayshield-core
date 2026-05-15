//! NTP status queries.
//!
//! Reads live timing metrics from whichever NTP daemon is currently active.
//!
//! # Daemon selection
//!
//! 1. If `chrony` or `chronyd` is active, parse `chronyc tracking`.
//! 2. Otherwise fall back to `timedatectl show-timesync --no-pager` plus
//!    `timedatectl show --property=SystemClockSynchronized --value`.
//!
//! Both paths populate the same [`NtpStatus`] struct so callers do not need
//! to know which daemon is running.

use chrono::Utc;
use tokio::process::Command;
use tracing::debug;

use crate::ntp::model::NtpStatus;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Query the currently active NTP daemon and return a [`NtpStatus`] snapshot.
///
/// Returns a zeroed/unsynchronised status when no NTP daemon is running or
/// when the queries fail.
pub async fn ntp_status() -> NtpStatus {
    if chrony_is_active().await {
        debug!("NTP status: using chrony");
        chrony_status().await
    } else {
        debug!("NTP status: using systemd-timesyncd");
        timesyncd_status().await
    }
}

// ---------------------------------------------------------------------------
// Daemon detection
// ---------------------------------------------------------------------------

async fn chrony_is_active() -> bool {
    for unit in ["chrony", "chronyd"] {
        if matches!(
            Command::new("systemctl")
                .args(["is-active", "--quiet", unit])
                .status()
                .await,
            Ok(s) if s.success()
        ) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// chronyc tracking parser
// ---------------------------------------------------------------------------

/// Query `chronyc tracking` and parse the output into an [`NtpStatus`].
async fn chrony_status() -> NtpStatus {
    let mut status = NtpStatus {
        synchronized: false,
        server: None,
        offset_ms: 0.0,
        jitter_ms: 0.0,
        stratum: 0,
        last_sync: None,
        daemon: "chrony".into(),
    };

    let output = match Command::new("chronyc").arg("tracking").output().await {
        Ok(o) => o,
        Err(e) => {
            debug!(error = %e, "Failed to run chronyc tracking");
            return status;
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    parse_chronyc_tracking(&text, &mut status);
    status
}

/// Parse the text output of `chronyc tracking` into `status`.
///
/// Example output lines we care about:
/// ```text
/// Reference ID    : C0000101 (192.0.1.1)
/// System time     : 0.000012345 seconds slow of NTP time
/// RMS offset      : 0.000045678 seconds
/// Leap status     : Normal
/// ```
fn parse_chronyc_tracking(text: &str, status: &mut NtpStatus) {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Reference ID") {
            // "Reference ID    : C0000101 (192.0.1.1)"
            // Extract the hostname/IP in parentheses, if present.
            if let (Some(open), Some(close)) = (rest.find('('), rest.find(')')) {
                let host = rest[open + 1..close].trim().to_string();
                if !host.is_empty() && host != "0.0.0.0" {
                    status.server = Some(host);
                }
            }
        } else if line.starts_with("Stratum") {
            if let Some(raw) = line.split(':').nth(1) {
                if let Ok(stratum) = raw.trim().parse::<u8>() {
                    status.stratum = stratum;
                }
            }
        } else if line.starts_with("System time") {
            // "System time     : 0.000012345 seconds slow of NTP time"
            if let Some(offset_ms) = parse_system_time_line(line) {
                status.offset_ms = offset_ms;
            }
        } else if line.starts_with("RMS offset") {
            // "RMS offset      : 0.000045678 seconds"
            if let Some(val) = extract_seconds_value(line) {
                status.jitter_ms = val * 1000.0;
            }
        } else if line.starts_with("Leap status") {
            // "Leap status     : Normal"
            if let Some(val) = line.split(':').nth(1) {
                let leap = val.trim();
                status.synchronized = matches!(leap, "Normal" | "Insert second" | "Delete second");
            }
        }
    }

    if status.synchronized {
        status.last_sync = Some(Utc::now().to_rfc3339());
    }
}

/// Parse "System time     : 0.000012345 seconds slow of NTP time".
///
/// Returns the offset in milliseconds (positive = ahead, negative = behind).
fn parse_system_time_line(line: &str) -> Option<f64> {
    let after_colon = line.split(':').nth(1)?;
    let parts: Vec<&str> = after_colon.split_whitespace().collect();
    // parts[0] = numeric seconds value
    // parts[1] = "seconds"
    // parts[2] = "slow" | "fast"
    let secs: f64 = parts.first()?.parse().ok()?;
    let direction = parts.get(2).copied().unwrap_or("slow");
    let ms = secs * 1000.0;
    if direction == "fast" {
        Some(ms)
    } else {
        Some(-ms)
    }
}

/// Extract a floating-point seconds value from a `"Label : N.NNN seconds"` line.
fn extract_seconds_value(line: &str) -> Option<f64> {
    let after_colon = line.split(':').nth(1)?;
    after_colon
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
}

// ---------------------------------------------------------------------------
// timedatectl show-timesync parser
// ---------------------------------------------------------------------------

/// Query `timedatectl show-timesync` and parse the output into an [`NtpStatus`].
async fn timesyncd_status() -> NtpStatus {
    let mut status = NtpStatus {
        synchronized: false,
        server: None,
        offset_ms: 0.0,
        jitter_ms: 0.0,
        stratum: 0,
        last_sync: None,
        daemon: "systemd-timesyncd".into(),
    };

    let output = match Command::new("timedatectl")
        .args(["show-timesync", "--no-pager"])
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            debug!(error = %e, "Failed to run timedatectl show-timesync");
            return status;
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    parse_timedatectl_timesync(&text, &mut status);

    if !status.synchronized {
        refresh_timedatectl_system_sync_state(&mut status).await;
    }

    status
}

async fn refresh_timedatectl_system_sync_state(status: &mut NtpStatus) {
    let output = match Command::new("timedatectl")
        .args(["show", "--property=SystemClockSynchronized", "--value"])
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            debug!(error = %e, "Failed to run timedatectl show for sync state");
            return;
        }
    };

    let value = String::from_utf8_lossy(&output.stdout);
    if value.trim().eq_ignore_ascii_case("yes") {
        status.synchronized = true;
        if status.last_sync.is_none() {
            status.last_sync = Some(Utc::now().to_rfc3339());
        }
    }
}

/// Parse the key=value output of `timedatectl show-timesync`.
///
/// Relevant keys:
/// ```text
/// ServerName=0.pool.ntp.org
/// NTPMessage=...
/// Frequency=...
/// TimeOffsetUSec=123456us
/// ```
fn parse_timedatectl_timesync(text: &str, status: &mut NtpStatus) {
    for line in text.lines() {
        if let Some((key, val)) = line.split_once('=') {
            match key.trim() {
                "ServerName" => {
                    let v = val.trim().to_string();
                    if !v.is_empty() {
                        status.server = Some(v);
                    }
                }
                "TimeOffsetUSec" => {
                    // Value looks like "123456us" or just "123456"
                    let digits: String = val.chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect();
                    if let Ok(us) = digits.parse::<i64>() {
                        status.offset_ms = us as f64 / 1000.0;
                    }
                }
                "RootDistanceUSec" => {
                    let digits: String = val.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(us) = digits.parse::<u64>() {
                        status.jitter_ms = us as f64 / 1000.0;
                    }
                }
                "Stratum" => {
                    if let Ok(stratum) = val.trim().parse::<u8>() {
                        status.stratum = stratum;
                    }
                }
                "Synchronized" => {
                    status.synchronized = val.trim().eq_ignore_ascii_case("yes");
                }
                "NTPSynchronized" => {
                    // Some versions use NTPSynchronized instead of Synchronized.
                    if val.trim().eq_ignore_ascii_case("yes") {
                        status.synchronized = true;
                    }
                }
                "LastSyncTime" => {
                    let v = val.trim().to_string();
                    if !v.is_empty() && v != "0" {
                        status.last_sync = Some(v);
                    }
                }
                _ => {}
            }
        }
    }

    if status.synchronized && status.last_sync.is_none() {
        status.last_sync = Some(Utc::now().to_rfc3339());
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_status() -> NtpStatus {
        NtpStatus {
            synchronized: false,
            server: None,
            offset_ms: 0.0,
            jitter_ms: 0.0,
            stratum: 0,
            last_sync: None,
            daemon: "chrony".into(),
        }
    }

    #[test]
    fn parse_chronyc_normal() {
        let text = "\
Reference ID    : C0000101 (192.0.1.1)\n\
Stratum         : 2\n\
Ref time (UTC)  : Sat Jan 01 12:00:00 2000\n\
System time     : 0.000012345 seconds slow of NTP time\n\
Last offset     : +0.000011234 seconds\n\
RMS offset      : 0.000045678 seconds\n\
Frequency       : 10.000 ppm slow\n\
Residual freq   : +0.001 ppm\n\
Skew            : 0.003 ppm\n\
Root delay      : 0.010000000 seconds\n\
Root dispersion : 0.001000000 seconds\n\
Update interval : 64.0 seconds\n\
Leap status     : Normal\n";

        let mut s = make_status();
        parse_chronyc_tracking(text, &mut s);

        assert_eq!(s.server.as_deref(), Some("192.0.1.1"));
        assert_eq!(s.stratum, 2);
        assert!(s.synchronized);
        // offset should be negative (slow = behind)
        assert!(s.offset_ms < 0.0, "offset_ms should be negative for 'slow'");
        assert!(s.jitter_ms > 0.0, "jitter_ms should be positive");
    }

    #[test]
    fn parse_chronyc_fast_offset() {
        let text = "\
System time     : 0.000100000 seconds fast of NTP time\n\
RMS offset      : 0.000010000 seconds\n\
Leap status     : Normal\n";

        let mut s = make_status();
        parse_chronyc_tracking(text, &mut s);
        assert!(s.offset_ms > 0.0, "fast offset should be positive");
    }

    #[test]
    fn parse_chronyc_not_synchronized() {
        let text = "\
Leap status     : Not synchronised\n";

        let mut s = make_status();
        parse_chronyc_tracking(text, &mut s);
        assert!(!s.synchronized);
    }

    #[test]
    fn parse_timedatectl_basic() {
        let text = "\
ServerName=0.pool.ntp.org\n\
Stratum=3\n\
TimeOffsetUSec=1234us\n\
NTPSynchronized=yes\n\
LastSyncTime=2024-01-01T00:00:00Z\n";

        let mut s = NtpStatus {
            synchronized: false,
            server: None,
            offset_ms: 0.0,
            jitter_ms: 0.0,
            stratum: 0,
            last_sync: None,
            daemon: "systemd-timesyncd".into(),
        };
        parse_timedatectl_timesync(text, &mut s);

        assert!(s.synchronized);
        assert_eq!(s.server.as_deref(), Some("0.pool.ntp.org"));
        assert_eq!(s.stratum, 3);
        assert!((s.offset_ms - 1.234).abs() < 0.001);
        assert_eq!(s.last_sync.as_deref(), Some("2024-01-01T00:00:00Z"));
    }
}
