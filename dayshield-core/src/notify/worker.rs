//! Background notification worker.
//!
//! Spawns a Tokio task that drains the [`NotifyQueue`] receiver, applies
//! rate limiting, and either sends each event immediately or buffers them
//! for a 5-minute digest, depending on the configuration.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, warn};

use super::model::NotifyEvent;
use super::rate_limit::RateLimiter;
use super::smtp::send_email_with_ipv6;
use crate::config::models::NotifyConfig;
use crate::state::AppState;

/// Digest flush interval - events are batched for this duration when
/// `digest_mode` is enabled.
const DIGEST_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Load the current [`NotifyConfig`] from the config store, returning
/// `None` when notifications are disabled or not yet configured.
fn load_config(state: &Arc<AppState>) -> Option<NotifyConfig> {
    let cfg = state.config_store.load_notify_config().ok()??;
    if cfg.enabled {
        Some(cfg)
    } else {
        None
    }
}

fn load_ipv6_enabled(state: &Arc<AppState>) -> bool {
    state
        .config_store
        .load_system_settings()
        .map(|settings| settings.ipv6_enabled)
        .unwrap_or(false)
}

/// Compose a digest email from a batch of events.
fn compose_digest(events: &[NotifyEvent]) -> (String, String) {
    let subject = format!("[DayShield] Notification digest ({} events)", events.len());
    let mut body = format!(
        "DayShield Notification Digest\n\
         ==============================\n\
         {} events collected.\n\n",
        events.len()
    );
    for evt in events {
        let ts = evt.timestamp;
        body.push_str(&format!(
            "--- [{ts}] {:?} ---\n{}\n{}\n",
            evt.category, evt.subject, evt.body
        ));
    }
    (subject, body)
}

/// Start the background notification worker.
///
/// Spawns a Tokio task; returns immediately.  The task runs for the lifetime
/// of the process.
pub async fn start_notify_worker(state: Arc<AppState>, mut rx: mpsc::Receiver<NotifyEvent>) {
    tokio::spawn(async move {
        info!("Notification worker started");

        let mut digest_buffer: Vec<NotifyEvent> = Vec::new();
        let mut digest_timer = interval(DIGEST_INTERVAL);
        digest_timer.tick().await; // discard the immediate first tick

        // The rate limiter is re-created if the config changes.
        let mut rate_limiter_opt: Option<RateLimiter> = None;

        loop {
            tokio::select! {
                // New event arrived on the channel.
                maybe_event = rx.recv() => {
                    let Some(event) = maybe_event else {
                        info!("Notification channel closed; worker shutting down");
                        break;
                    };

                    let Some(cfg) = load_config(&state) else {
                        debug!("Notifications disabled; dropping event");
                        continue;
                    };

                    // Skip events whose category is not enabled.
                    if !cfg.categories.contains(&event.category) {
                        debug!(category = ?event.category, "Event category not in notify config; skipping");
                        continue;
                    }

                    // Ensure the rate limiter matches the current config.
                    let rl = rate_limiter_opt.get_or_insert_with(|| RateLimiter::new(cfg.rate_limit_per_minute));
                    if rl.max_per_minute != cfg.rate_limit_per_minute {
                        *rl = RateLimiter::new(cfg.rate_limit_per_minute);
                    }

                    if cfg.digest_mode {
                        digest_buffer.push(event);
                    } else {
                        // Real-time send.
                        if !rl.check() {
                            warn!("Notification rate limit exceeded; dropping event");
                            continue;
                        }
                        let subject = event.subject.clone();
                        let body = event.body.clone();
                        match send_email_with_ipv6(&cfg, &subject, &body, load_ipv6_enabled(&state)).await {
                            Ok(()) => info!(subject = %subject, "Notification sent"),
                            Err(e) => warn!(error = %e, "Failed to send notification email"),
                        }
                    }
                }

                // Digest timer fired.
                _ = digest_timer.tick() => {
                    if digest_buffer.is_empty() {
                        continue;
                    }
                    let Some(cfg) = load_config(&state) else {
                        digest_buffer.clear();
                        continue;
                    };
                    if !cfg.digest_mode {
                        // Digest mode was turned off; discard buffered events.
                        digest_buffer.clear();
                        continue;
                    }

                    let rl = rate_limiter_opt.get_or_insert_with(|| RateLimiter::new(cfg.rate_limit_per_minute));
                    if !rl.check() {
                        warn!("Digest rate limit exceeded; retaining events for next window");
                        continue;
                    }

                    let events = std::mem::take(&mut digest_buffer);
                    let (subject, body) = compose_digest(&events);
                    match send_email_with_ipv6(&cfg, &subject, &body, load_ipv6_enabled(&state)).await {
                        Ok(()) => info!(count = events.len(), "Digest notification sent"),
                        Err(e) => warn!(error = %e, "Failed to send digest email"),
                    }
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::NotifyCategory;

    fn make_event(category: NotifyCategory, subject: &str) -> NotifyEvent {
        NotifyEvent {
            category,
            subject: subject.to_string(),
            body: "body".to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    #[test]
    fn compose_digest_subject_contains_count() {
        let events = vec![
            make_event(NotifyCategory::System, "event1"),
            make_event(NotifyCategory::Suricata, "event2"),
        ];
        let (subject, body) = compose_digest(&events);
        assert!(subject.contains("2 events"), "subject: {subject}");
        assert!(body.contains("event1"));
        assert!(body.contains("event2"));
    }
}
