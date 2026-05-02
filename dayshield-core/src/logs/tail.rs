//! Generic async file tailer with rotation detection.
//!
//! [`FileTailer`] reads new lines appended to a file and forwards them through
//! a [`tokio::sync::mpsc::Sender`].  It detects file rotation (the file is
//! replaced or truncated) by comparing the inode and file-size on every poll
//! cycle, reopens the file when rotation is detected, and logs the event.
//!
//! # Design notes
//!
//! * Fully async — built on `tokio::fs` + `tokio::io::AsyncBufReadExt`.
//! * Never blocks the Tokio runtime; all I/O is awaited.
//! * Backpressure is handled naturally: `tx.send(line).await` will block the
//!   tailer task when the consumer is slow, preventing unbounded buffering.
//! * The tailer sleeps [`POLL_INTERVAL`] between polls to avoid busy-looping.

use std::path::{Path, PathBuf};

use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
    time::{sleep, Duration},
};
use tracing::{info, warn};

/// How long the tailer waits between polls when no new data is available.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Metadata used to detect file rotation: inode number and file size.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileMeta {
    ino: u64,
    size: u64,
}

impl FileMeta {
    async fn read(path: &Path) -> Option<Self> {
        use tokio::fs::metadata;
        use std::os::unix::fs::MetadataExt;

        metadata(path).await.ok().map(|m| FileMeta {
            ino: m.ino(),
            size: m.len(),
        })
    }
}

/// A persistent async tailer for a single file.
///
/// Call [`FileTailer::run`] to start tailing; it runs indefinitely and only
/// returns when the sender channel is closed (i.e. the receiver has been
/// dropped).
pub struct FileTailer {
    path: PathBuf,
}

impl FileTailer {
    /// Create a new tailer for the file at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Tail the file, sending each new line (without the trailing newline) to
    /// `tx`.
    ///
    /// The function returns when `tx.send()` returns an error (channel closed).
    ///
    /// # Rotation detection
    ///
    /// After draining available lines the tailer checks whether the inode or
    /// file size has changed compared to the last open.  If either changes it
    /// reopens the file from the beginning so no events are missed.
    pub async fn run(self, tx: tokio::sync::mpsc::Sender<String>) {
        let path = &self.path;

        loop {
            // Wait for the file to exist.
            let meta = loop {
                match FileMeta::read(path).await {
                    Some(m) => break m,
                    None => {
                        warn!(path = %path.display(), "tailer: file not found, retrying in 5s");
                        sleep(Duration::from_secs(5)).await;
                    }
                }
            };

            info!(path = %path.display(), "tailer: opening file");

            let file = match File::open(path).await {
                Ok(f) => f,
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "tailer: failed to open, retrying in 5s");
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            let mut reader = BufReader::new(file);
            let mut current_meta = meta;

            loop {
                // Read all available lines.
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line).await {
                        Ok(0) => break, // No more data right now.
                        Ok(_) => {
                            let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
                            if !trimmed.is_empty() {
                                if tx.send(trimmed.to_string()).await.is_err() {
                                    // Receiver dropped — stop tailing.
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(path = %path.display(), error = %e, "tailer: read error");
                            break;
                        }
                    }
                }

                sleep(POLL_INTERVAL).await;

                // Detect rotation: re-stat the path.
                match FileMeta::read(path).await {
                    None => {
                        info!(path = %path.display(), "tailer: file disappeared, waiting for rotation");
                        break; // Outer loop will re-open.
                    }
                    Some(new_meta) => {
                        if new_meta.ino != current_meta.ino || new_meta.size < current_meta.size {
                            info!(path = %path.display(), "tailer: rotation detected, reopening");
                            break; // Outer loop will re-open.
                        }
                        current_meta = new_meta;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tokio::sync::mpsc;

    /// Helper: write `content` to a temp file and return its path.
    fn temp_file_with(content: &str) -> (tempfile::NamedTempFile, PathBuf) {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        write!(f, "{}", content).unwrap();
        let path = f.path().to_path_buf();
        (f, path)
    }

    #[tokio::test]
    async fn test_tail_reads_existing_lines() {
        let (_guard, path) = temp_file_with("line1\nline2\nline3\n");
        let (tx, mut rx) = mpsc::channel(16);

        // Run the tailer in a separate task; cancel it after receiving lines.
        let handle = tokio::spawn({
            let path = path.clone();
            async move {
                FileTailer::new(path).run(tx).await;
            }
        });

        let mut received = vec![];
        for _ in 0..3 {
            if let Some(line) = rx.recv().await {
                received.push(line);
            }
        }
        handle.abort();

        assert_eq!(received, ["line1", "line2", "line3"]);
    }

    #[tokio::test]
    async fn test_tail_detects_rotation() {
        use std::io::Write;
        use tokio::time::{sleep, Duration};

        // Start with a file containing one line.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "before_rotation").unwrap();
        }

        let (tx, mut rx) = mpsc::channel(16);
        let handle = tokio::spawn({
            let path = path.clone();
            async move {
                FileTailer::new(path).run(tx).await;
            }
        });

        // Read the first line.
        let first = rx.recv().await.unwrap();
        assert_eq!(first, "before_rotation");

        // Simulate rotation: recreate the file with a different inode.
        sleep(Duration::from_millis(50)).await;
        std::fs::remove_file(&path).unwrap();
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "after_rotation").unwrap();
        }

        let second = rx.recv().await.unwrap();
        assert_eq!(second, "after_rotation");

        handle.abort();
    }
}
