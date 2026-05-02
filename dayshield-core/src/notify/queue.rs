//! Notification queue — a thin wrapper around a Tokio MPSC channel.

use tokio::sync::mpsc;

use super::model::NotifyEvent;

/// Capacity of the bounded notification channel.
const QUEUE_CAPACITY: usize = 512;

/// The sending half of the notification channel.
///
/// Clone this to enqueue events from multiple producers (Suricata engine,
/// CrowdSec engine, ACME engine, system log tailer, etc.).
#[derive(Clone)]
pub struct NotifyQueue {
    pub tx: mpsc::Sender<NotifyEvent>,
}

impl NotifyQueue {
    /// Create a new channel and return the queue (sender) together with
    /// the raw receiver that the worker needs.
    pub fn new() -> (Self, mpsc::Receiver<NotifyEvent>) {
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        (Self { tx }, rx)
    }

    /// Enqueue an event, returning [`Err`] if the queue is full.
    pub async fn enqueue(&self, event: NotifyEvent) -> Result<(), crate::notify::smtp::NotifyError> {
        self.tx
            .try_send(event)
            .map_err(|_| crate::notify::smtp::NotifyError::QueueFull)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::NotifyCategory;

    fn make_event(subject: &str) -> NotifyEvent {
        NotifyEvent {
            category: NotifyCategory::System,
            subject: subject.to_string(),
            body: "test body".to_string(),
            timestamp: 0,
        }
    }

    #[tokio::test]
    async fn enqueue_and_receive() {
        let (queue, mut rx) = NotifyQueue::new();
        queue.enqueue(make_event("hello")).await.unwrap();
        let evt = rx.try_recv().unwrap();
        assert_eq!(evt.subject, "hello");
    }

    #[tokio::test]
    async fn queue_full_returns_error() {
        // Use a tiny capacity via raw channel to test error path.
        let (tx, _rx) = tokio::sync::mpsc::channel::<NotifyEvent>(1);
        let queue = NotifyQueue { tx };
        queue.enqueue(make_event("first")).await.unwrap();
        // Second send to a full channel should fail (receiver not consuming).
        let result = queue.enqueue(make_event("overflow")).await;
        assert!(result.is_err());
    }
}
