//! UI log ingestion and live-stream support.

use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    sync::{broadcast, mpsc::Sender},
};
use tracing::{info, warn};

use crate::live_logs::LogEvent;

/// Durable UI log file stored alongside core logs.
pub const DAYSHIELD_UI_LOG_PATH: &str = "/var/log/dayshield/ui.log";

const UI_LOG_CHANNEL_CAPACITY: usize = 256;

static UI_LOG_BROADCAST: OnceLock<broadcast::Sender<LogEvent>> = OnceLock::new();

/// Browser/UI event record persisted to disk and replayed into live logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiLogRecord {
    pub timestamp: String,
    pub component: String,
    pub level: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl UiLogRecord {
    pub fn into_event(self) -> LogEvent {
        let UiLogRecord {
            timestamp,
            component,
            level,
            message,
            route,
            url,
            stack,
            details,
        } = self;

        LogEvent::UiEvent {
            timestamp,
            component,
            level,
            message,
            route,
            url,
            stack,
            details,
        }
    }

    pub fn parse_line(line: &str) -> Option<LogEvent> {
        serde_json::from_str::<UiLogRecord>(line)
            .ok()
            .map(UiLogRecord::into_event)
    }
}

pub fn subscribe() -> broadcast::Receiver<LogEvent> {
    ui_log_sender().subscribe()
}

pub fn publish(event: LogEvent) {
    let _ = ui_log_sender().send(event);
}

pub async fn append_record(record: &UiLogRecord) -> Result<(), std::io::Error> {
    if let Some(parent) = std::path::Path::new(DAYSHIELD_UI_LOG_PATH).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(DAYSHIELD_UI_LOG_PATH)
        .await?;

    let line = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    file.write_all(&line).await?;
    file.write_all(b"\n").await?;
    file.flush().await?;
    Ok(())
}

/// Forward UI events from the in-memory broadcast channel into the live log stream.
pub async fn stream_ui(tx: Sender<LogEvent>) {
    info!("ui: live UI log subscriber connected");
    let mut rx = subscribe();

    loop {
        match rx.recv().await {
            Ok(event) => {
                if tx.send(event).await.is_err() {
                    info!("ui: live UI log subscriber disconnected");
                    break;
                }
            }
            Err(broadcast::error::RecvError::Closed) => {
                info!("ui: broadcast channel closed");
                break;
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(skipped, "ui: lagged behind live UI log stream");
            }
        }
    }
}

fn ui_log_sender() -> &'static broadcast::Sender<LogEvent> {
    UI_LOG_BROADCAST.get_or_init(|| {
        let (sender, _) = broadcast::channel(UI_LOG_CHANNEL_CAPACITY);
        sender
    })
}

pub fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
}