//! In-memory time-series ring buffer for [`MetricsSnapshot`] values.
//!
//! [`MetricsBuffer`] holds the last `max_entries` snapshots in a [`VecDeque`].
//! When the buffer is full the oldest entry is evicted before inserting the new
//! one, so memory usage is strictly bounded.
//!
//! The default capacity is 300 entries, which covers 5 minutes at a 1-second
//! collection interval.

use std::collections::VecDeque;

use serde_json::Value;

use crate::metrics::MetricsSnapshot;

/// Default number of snapshots to retain.
pub const DEFAULT_MAX_ENTRIES: usize = 300;

/// A bounded in-memory ring buffer for [`MetricsSnapshot`] values.
pub struct MetricsBuffer {
    /// Stored snapshots, oldest first.
    pub history: VecDeque<MetricsSnapshot>,
    /// Maximum number of entries to retain.
    pub max_entries: usize,
}

impl MetricsBuffer {
    /// Create a new buffer with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            history: VecDeque::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Push a new snapshot, evicting the oldest if the buffer is full.
    pub fn push(&mut self, snapshot: MetricsSnapshot) {
        if self.history.len() >= self.max_entries {
            self.history.pop_front();
        }
        self.history.push_back(snapshot);
    }

    /// Return a reference to the most-recently pushed snapshot, or `None` if
    /// the buffer is empty.
    pub fn latest(&self) -> Option<&MetricsSnapshot> {
        self.history.back()
    }

    /// Return snapshots whose `timestamp` falls within the last `seconds`
    /// seconds relative to the most-recent entry.
    ///
    /// Returns an empty slice if the buffer is empty.
    pub fn last_n(&self, seconds: u64) -> Vec<&MetricsSnapshot> {
        match self.history.back() {
            None => vec![],
            Some(last) => {
                let cutoff = last.timestamp.saturating_sub(seconds);
                self.history
                    .iter()
                    .filter(|s| s.timestamp >= cutoff)
                    .collect()
            }
        }
    }

    /// Serialise the entire history to a JSON [`Value`] (array of objects).
    pub fn to_json(&self) -> Value {
        let entries: Vec<&MetricsSnapshot> = self.history.iter().collect();
        serde_json::to_value(&entries).unwrap_or(Value::Array(vec![]))
    }
}

impl Default for MetricsBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::MetricsSnapshot;

    fn make_snapshot(ts: u64) -> MetricsSnapshot {
        MetricsSnapshot {
            timestamp: ts,
            ..Default::default()
        }
    }

    #[test]
    fn test_push_and_latest() {
        let mut buf = MetricsBuffer::new(5);
        assert!(buf.latest().is_none());

        buf.push(make_snapshot(1));
        buf.push(make_snapshot(2));
        buf.push(make_snapshot(3));

        assert_eq!(buf.latest().unwrap().timestamp, 3);
        assert_eq!(buf.history.len(), 3);
    }

    #[test]
    fn test_eviction_at_capacity() {
        let mut buf = MetricsBuffer::new(3);
        for i in 1u64..=5 {
            buf.push(make_snapshot(i));
        }
        // Buffer should retain the 3 most-recent entries.
        assert_eq!(buf.history.len(), 3);
        let timestamps: Vec<u64> = buf.history.iter().map(|s| s.timestamp).collect();
        assert_eq!(timestamps, vec![3, 4, 5]);
    }

    #[test]
    fn test_last_n_seconds() {
        let mut buf = MetricsBuffer::new(300);
        // Snapshots at t = 100, 110, 120, 130, 140
        for t in [100u64, 110, 120, 130, 140] {
            buf.push(make_snapshot(t));
        }
        // Ask for the last 30 seconds relative to t=140 → cutoff = 110
        let result = buf.last_n(30);
        let ts: Vec<u64> = result.iter().map(|s| s.timestamp).collect();
        assert_eq!(ts, vec![110, 120, 130, 140]);
    }

    #[test]
    fn test_last_n_empty_buffer() {
        let buf = MetricsBuffer::new(10);
        assert!(buf.last_n(60).is_empty());
    }

    #[test]
    fn test_to_json_returns_array() {
        let mut buf = MetricsBuffer::new(5);
        buf.push(make_snapshot(1));
        buf.push(make_snapshot(2));
        let json = buf.to_json();
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 2);
    }
}
