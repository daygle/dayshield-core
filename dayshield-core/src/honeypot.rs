use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::JoinHandle,
    time::{timeout, Duration},
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    ai_engine::FlowMetadata,
    config::models::{HoneypotConfig, HoneypotListenerConfig, HoneypotType},
    state::{AppState, SVC_HONEYPOT},
};

const HONEYPOT_EVENTS_TREE: &str = "honeypot_events";
const HONEYPOT_EVENTS_BY_ID_TREE: &str = "honeypot_events_by_id";
const READ_TIMEOUT_SECONDS: u64 = 2;
const MAX_CAPTURE_BYTES: usize = 1024;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotEvent {
    pub id: String,
    pub timestamp: u64,
    pub listener_id: String,
    pub listener_name: String,
    pub honeypot_type: HoneypotType,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes_received: usize,
    pub payload_preview: Option<String>,
    pub user_agent: Option<String>,
    pub risk_score: f64,
    pub ai_threat_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HoneypotSourceIp {
    pub ip: String,
    pub last_seen: u64,
    pub event_count: usize,
    pub last_listener_id: String,
    pub last_listener_name: String,
    pub last_honeypot_type: HoneypotType,
    pub last_ai_threat_event_id: Option<String>,
}

#[derive(Clone)]
pub struct HoneypotRuntime {
    store: Arc<HoneypotEventStore>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    started: Arc<AtomicBool>,
}

impl HoneypotRuntime {
    pub fn new(config_dir: &Path) -> Self {
        let primary_path = config_dir.join("honeypots").join("events.db");
        let store = HoneypotEventStore::open(&primary_path).unwrap_or_else(|e| {
            warn!(error = %e, path = %primary_path.display(), "honeypot: falling back to temporary event store");
            HoneypotEventStore::temporary().expect("failed to create temporary honeypot event store")
        });

        Self {
            store: Arc::new(store),
            tasks: Arc::new(Mutex::new(Vec::new())),
            started: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start_background_tasks(&self, state: Arc<AppState>) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }

        let runtime = self.clone();
        tokio::spawn(async move {
            let config = state
                .config_store
                .load_honeypot_config()
                .unwrap_or_else(|e| {
                    warn!(error = %e, "honeypot: failed to load config, using disabled defaults");
                    HoneypotConfig::default()
                });

            if let Err(e) = runtime.apply_config(Arc::clone(&state), config).await {
                warn!(error = %e, "honeypot: failed to apply startup config");
            }
        });
    }

    pub async fn apply_config(&self, state: Arc<AppState>, config: HoneypotConfig) -> Result<()> {
        let old_tasks = {
            let mut tasks = self.tasks.lock().await;
            tasks.drain(..).collect::<Vec<_>>()
        };
        for task in old_tasks {
            task.abort();
            let _ = task.await;
        }

        state.set_unhealthy(SVC_HONEYPOT).await;

        if !config.enabled {
            info!("honeypot: disabled");
            return Ok(());
        }

        let mut handles = Vec::new();
        for listener in config
            .listeners
            .into_iter()
            .filter(|listener| listener.enabled)
        {
            let runtime = self.clone();
            let state_clone = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                run_listener(runtime, state_clone, listener).await;
            }));
        }

        let listener_count = handles.len();
        let mut tasks = self.tasks.lock().await;
        *tasks = handles;
        info!(listener_count, "honeypot: listeners scheduled");
        Ok(())
    }

    pub fn recent_events(&self, limit: usize) -> Result<Vec<HoneypotEvent>> {
        self.store.list_recent(limit)
    }

    pub fn source_ips(&self, limit: usize) -> Result<Vec<HoneypotSourceIp>> {
        let mut by_ip: HashMap<String, HoneypotSourceIp> = HashMap::new();
        for event in self.store.list_recent(limit)? {
            by_ip
                .entry(event.src_ip.clone())
                .and_modify(|entry| {
                    entry.event_count = entry.event_count.saturating_add(1);
                    if event.timestamp > entry.last_seen {
                        entry.last_seen = event.timestamp;
                        entry.last_listener_id = event.listener_id.clone();
                        entry.last_listener_name = event.listener_name.clone();
                        entry.last_honeypot_type = event.honeypot_type.clone();
                        entry.last_ai_threat_event_id = event.ai_threat_event_id.clone();
                    }
                })
                .or_insert_with(|| HoneypotSourceIp {
                    ip: event.src_ip.clone(),
                    last_seen: event.timestamp,
                    event_count: 1,
                    last_listener_id: event.listener_id.clone(),
                    last_listener_name: event.listener_name.clone(),
                    last_honeypot_type: event.honeypot_type.clone(),
                    last_ai_threat_event_id: event.ai_threat_event_id.clone(),
                });
        }

        let mut out: Vec<HoneypotSourceIp> = by_ip.into_values().collect();
        out.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then_with(|| a.ip.cmp(&b.ip)));
        Ok(out)
    }

    pub fn count_events_since(&self, min_timestamp: u64) -> Result<usize> {
        self.store.count_since(min_timestamp)
    }

    async fn record_connection(
        &self,
        state: &Arc<AppState>,
        listener: &HoneypotListenerConfig,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<HoneypotEvent> {
        let timestamp = now_unix_secs();
        let payload_preview = preview_payload(payload);
        let user_agent = extract_user_agent(payload);
        let risk_score = listener.risk_score.clamp(0.0, 1.0);
        let src_ip = remote_addr.ip().to_string();
        let dst_ip = local_addr.ip().to_string();

        let flow = FlowMetadata {
            timestamp,
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port: Some(remote_addr.port()),
            dst_port: Some(listener.port),
            protocol: "tcp".to_string(),
            event_source: format!("honeypot:{}", listener.honeypot_type.as_str()),
            action: Some("connection".to_string()),
        };

        let mut reasons = vec![
            format!(
                "source connected to {} honeypot listener {:?}",
                listener.honeypot_type.display_name(),
                listener.name
            ),
            "honeypot interaction is high-confidence unsolicited traffic".to_string(),
        ];
        if payload_preview.is_some() {
            reasons.push("client sent an application payload to the honeypot".to_string());
        }

        let signature = Some(format!(
            "{} honeypot connection on {}",
            listener.honeypot_type.display_name(),
            listener.name
        ));

        let ai_threat_event_id = match state
            .ai_runtime
            .submit_risk_assessment(state, flow, risk_score, reasons, signature, Some(1))
            .await
        {
            Ok(event) => Some(event.id),
            Err(e) => {
                warn!(
                    listener_id = %listener.id,
                    src_ip = %src_ip,
                    error = %e,
                    "honeypot: failed to submit hit to AI Threat Engine"
                );
                None
            }
        };

        let event = HoneypotEvent {
            id: Uuid::new_v4().to_string(),
            timestamp,
            listener_id: listener.id.clone(),
            listener_name: listener.name.clone(),
            honeypot_type: listener.honeypot_type.clone(),
            src_ip,
            src_port: remote_addr.port(),
            dst_ip,
            dst_port: listener.port,
            protocol: "tcp".to_string(),
            bytes_received: payload.len(),
            payload_preview,
            user_agent,
            risk_score,
            ai_threat_event_id,
        };

        self.store.insert_event(&event)?;
        Ok(event)
    }
}

pub async fn start_background_tasks(state: Arc<AppState>) {
    let runtime = state.honeypot_runtime.clone();
    runtime.start_background_tasks(state);
}

async fn run_listener(
    runtime: HoneypotRuntime,
    state: Arc<AppState>,
    listener: HoneypotListenerConfig,
) {
    let ip = match listener.bind_address.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(e) => {
            warn!(
                listener_id = %listener.id,
                bind_address = %listener.bind_address,
                error = %e,
                "honeypot: invalid bind address"
            );
            return;
        }
    };
    let bind_addr = SocketAddr::new(ip, listener.port);
    let server = match TcpListener::bind(bind_addr).await {
        Ok(server) => server,
        Err(e) => {
            warn!(
                listener_id = %listener.id,
                bind = %bind_addr,
                error = %e,
                "honeypot: failed to bind listener"
            );
            return;
        }
    };

    state.set_healthy(SVC_HONEYPOT).await;
    info!(
        listener_id = %listener.id,
        honeypot_type = listener.honeypot_type.as_str(),
        bind = %bind_addr,
        "honeypot: listener active"
    );

    loop {
        match server.accept().await {
            Ok((stream, remote_addr)) => {
                let runtime = runtime.clone();
                let state = Arc::clone(&state);
                let listener = listener.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_connection(runtime, state, listener, stream, remote_addr).await
                    {
                        warn!(error = %e, "honeypot: failed to handle connection");
                    }
                });
            }
            Err(e) => {
                warn!(listener_id = %listener.id, error = %e, "honeypot: accept failed");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}

async fn handle_connection(
    runtime: HoneypotRuntime,
    state: Arc<AppState>,
    listener: HoneypotListenerConfig,
    mut stream: TcpStream,
    remote_addr: SocketAddr,
) -> Result<()> {
    let local_addr = stream.local_addr().unwrap_or_else(|_| {
        let ip = listener
            .bind_address
            .parse::<IpAddr>()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        SocketAddr::new(ip, listener.port)
    });

    if let Some(banner) = initial_banner_for(&listener) {
        let _ = stream.write_all(banner.as_bytes()).await;
    }

    let mut buf = vec![0u8; MAX_CAPTURE_BYTES];
    let bytes_read = match timeout(
        Duration::from_secs(READ_TIMEOUT_SECONDS),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            warn!(error = %e, "honeypot: read failed");
            0
        }
        Err(_) => 0,
    };
    buf.truncate(bytes_read);

    if let Some(response) = final_response_for(&listener, bytes_read) {
        let _ = stream.write_all(response.as_bytes()).await;
    }

    let event = runtime
        .record_connection(&state, &listener, remote_addr, local_addr, &buf)
        .await?;

    info!(
        listener_id = %event.listener_id,
        src_ip = %event.src_ip,
        bytes_received = event.bytes_received,
        ai_threat_event_id = ?event.ai_threat_event_id,
        "honeypot: captured connection"
    );

    Ok(())
}

fn initial_banner_for(listener: &HoneypotListenerConfig) -> Option<String> {
    if let Some(custom) = &listener.banner {
        if !custom.is_empty() {
            return Some(custom.clone());
        }
    }

    match listener.honeypot_type {
        HoneypotType::Ssh => Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n".to_string()),
        HoneypotType::Telnet => Some("login: ".to_string()),
        HoneypotType::Ftp => Some("220 ProFTPD Server ready\r\n".to_string()),
        HoneypotType::Smtp => Some("220 mail.local ESMTP Postfix\r\n".to_string()),
        HoneypotType::Http | HoneypotType::Mysql | HoneypotType::Rdp | HoneypotType::GenericTcp => {
            None
        }
    }
}

fn final_response_for(
    listener: &HoneypotListenerConfig,
    bytes_read: usize,
) -> Option<&'static str> {
    match listener.honeypot_type {
        HoneypotType::Http => Some(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
        HoneypotType::Telnet if bytes_read > 0 => Some("Password: "),
        HoneypotType::Ftp if bytes_read > 0 => Some("530 Login incorrect.\r\n"),
        HoneypotType::Smtp if bytes_read > 0 => Some("550 5.7.1 Access denied\r\n"),
        _ => None,
    }
}

fn preview_payload(payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        return None;
    }

    let mut out = String::new();
    for byte in payload.iter().take(256) {
        match *byte {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(*byte as char),
            _ => out.push('.'),
        }
    }
    Some(out)
}

fn extract_user_agent(payload: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(payload);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("user-agent") {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.chars().take(256).collect());
                }
            }
        }
    }
    None
}

struct HoneypotEventStore {
    events: sled::Tree,
    by_id: sled::Tree,
}

impl HoneypotEventStore {
    fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let db = sled::open(path)
            .with_context(|| format!("failed to open sled db at {}", path.display()))?;

        Ok(Self {
            events: db.open_tree(HONEYPOT_EVENTS_TREE)?,
            by_id: db.open_tree(HONEYPOT_EVENTS_BY_ID_TREE)?,
        })
    }

    fn temporary() -> Result<Self> {
        let db = sled::Config::new().temporary(true).open()?;
        Ok(Self {
            events: db.open_tree(HONEYPOT_EVENTS_TREE)?,
            by_id: db.open_tree(HONEYPOT_EVENTS_BY_ID_TREE)?,
        })
    }

    fn insert_event(&self, event: &HoneypotEvent) -> Result<()> {
        let key = format!("{:020}-{}", event.timestamp, event.id);
        let bytes = serde_json::to_vec(event)?;
        self.events.insert(key.as_bytes(), bytes)?;
        self.by_id.insert(event.id.as_bytes(), key.as_bytes())?;
        self.events.flush()?;
        self.by_id.flush()?;
        Ok(())
    }

    fn list_recent(&self, limit: usize) -> Result<Vec<HoneypotEvent>> {
        let mut out = Vec::new();
        for item in self.events.iter().rev().take(limit) {
            let (_k, v) = item?;
            let evt = serde_json::from_slice::<HoneypotEvent>(&v)?;
            out.push(evt);
        }
        Ok(out)
    }

    fn count_since(&self, min_timestamp: u64) -> Result<usize> {
        let mut count = 0usize;
        for item in self.events.iter().rev() {
            let (_k, v) = item?;
            let evt = serde_json::from_slice::<HoneypotEvent>(&v)?;
            if evt.timestamp < min_timestamp {
                break;
            }
            count = count.saturating_add(1);
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(ts: u64, ip: &str) -> HoneypotEvent {
        HoneypotEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: ts,
            listener_id: "ssh-default".to_string(),
            listener_name: "SSH honeypot".to_string(),
            honeypot_type: HoneypotType::Ssh,
            src_ip: ip.to_string(),
            src_port: 44444,
            dst_ip: "192.0.2.10".to_string(),
            dst_port: 2222,
            protocol: "tcp".to_string(),
            bytes_received: 4,
            payload_preview: Some("test".to_string()),
            user_agent: None,
            risk_score: 0.95,
            ai_threat_event_id: Some("threat-id".to_string()),
        }
    }

    #[test]
    fn payload_preview_escapes_control_bytes() {
        assert_eq!(
            preview_payload(b"GET /\r\nUser-Agent:\tbot\x01"),
            Some("GET /\\r\\nUser-Agent:\\tbot.".to_string())
        );
    }

    #[test]
    fn extracts_user_agent_case_insensitively() {
        assert_eq!(
            extract_user_agent(b"GET / HTTP/1.1\r\nuser-agent: scanner\r\n\r\n"),
            Some("scanner".to_string())
        );
    }

    #[test]
    fn event_store_insert_and_list_roundtrip() {
        let store = HoneypotEventStore::temporary().unwrap();
        let event = sample_event(1_700_000_000, "203.0.113.10");
        store.insert_event(&event).unwrap();

        let recent = store.list_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].id, event.id);
        assert_eq!(recent[0].src_ip, "203.0.113.10");
    }

    #[test]
    fn count_since_respects_timestamp_window() {
        let store = HoneypotEventStore::temporary().unwrap();
        store
            .insert_event(&sample_event(1_700_000_000, "203.0.113.10"))
            .unwrap();
        store
            .insert_event(&sample_event(1_700_000_100, "203.0.113.11"))
            .unwrap();

        assert_eq!(store.count_since(1_700_000_050).unwrap(), 1);
    }
}
