//! Append-only JSONL audit log.
//!
//! Design (RFC-0003 H2):
//!
//! - One bounded `mpsc` channel feeds a single dedicated writer task.
//!   Multiple request handlers can `record(...)` concurrently; the
//!   writer serialises them and is the sole owner of the file
//!   handle, eliminating both lock contention and the previous
//!   per-event `tokio::spawn` (which leaked tasks under load and
//!   produced an unbounded interleaving with no flush guarantees).
//! - `record(...)` is non-blocking: it uses `try_send`. If the
//!   channel is full or the writer has crashed, the record is
//!   dropped and a counter is incremented. Audit records must
//!   never block the request path — losing one is preferable to
//!   stalling traffic.
//! - We deliberately do NOT log full request/response bodies, only
//!   the inspection event (which carries shell-side tool inputs by
//!   design — that's what rules match against — but never user
//!   prompt text) and the verdict.
//!
//! Privacy contract: every field that ends up in `event` or
//! `verdict` is reviewed against the no-prompt-content rule. New
//! fields are gated by H8 once it lands.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use relix_core::model::InspectionEvent;
use relix_core::Verdict;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::warn;

/// Channel depth for the writer queue. 1024 records absorbs short
/// bursts (e.g. one streaming response producing multiple `tool_use`
/// audits) without backing up the request path. Large enough that we
/// rarely drop, small enough that disk-stalled writers do not eat
/// process memory.
const CHANNEL_CAPACITY: usize = 1024;

#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<Inner>,
}

struct Inner {
    /// `None` when no audit path was configured at startup; in that
    /// case `record` is a no-op (still increments dropped if anyone
    /// tries — that's the signal an operator forgot to set --audit).
    sender: Option<mpsc::Sender<Message>>,
    dropped: AtomicU64,
}

#[derive(Debug, Serialize)]
struct AuditRecord<'a> {
    event: &'a InspectionEvent,
    verdict: &'a Verdict,
}

enum Message {
    Record { line: String },
    Flush(tokio::sync::oneshot::Sender<()>),
}

impl AuditLog {
    /// Open the audit log at `path` and start the writer task.
    /// If the file cannot be created, the log degrades to a no-op
    /// rather than failing startup — operators expect Relix to come
    /// up even on a read-only home directory.
    pub async fn open(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .ok();

        let sender = file.map(|f| {
            let (tx, rx) = mpsc::channel::<Message>(CHANNEL_CAPACITY);
            tokio::spawn(writer_loop(f, rx));
            tx
        });

        Ok(Self {
            inner: Arc::new(Inner {
                sender,
                dropped: AtomicU64::new(0),
            }),
        })
    }

    /// Audit log that drops every record. Used by tests and by
    /// startup paths that explicitly disable auditing.
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            inner: Arc::new(Inner {
                sender: None,
                dropped: AtomicU64::new(0),
            }),
        }
    }

    /// Number of records dropped since startup (channel full or no
    /// configured destination). Exposed for tests and metrics.
    #[allow(dead_code)]
    pub fn dropped_count(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    /// Enqueue an audit record. Non-blocking: returns immediately
    /// after a `try_send`. The hot path of a streaming response can
    /// call this from within an inspection lock — it must never
    /// await disk I/O.
    pub fn record(&self, event: &InspectionEvent, verdict: &Verdict) {
        let Some(sender) = &self.inner.sender else {
            return;
        };
        let line = match serde_json::to_string(&AuditRecord { event, verdict }) {
            Ok(s) => s,
            Err(err) => {
                warn!(error = %err, "audit serialize failed");
                return;
            }
        };
        match sender.try_send(Message::Record { line }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                let n = self.inner.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_power_of_two() {
                    warn!(dropped = n, "audit channel full, dropping record");
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Wait until every record submitted *before this call* has been
    /// written and flushed. Intended for tests and graceful shutdown.
    /// Resolves immediately if the log is disabled.
    #[allow(dead_code)]
    pub async fn flush(&self) {
        let Some(sender) = &self.inner.sender else {
            return;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        if sender.send(Message::Flush(tx)).await.is_err() {
            return;
        }
        let _ = rx.await;
    }
}

async fn writer_loop(mut file: tokio::fs::File, mut rx: mpsc::Receiver<Message>) {
    while let Some(msg) = rx.recv().await {
        match msg {
            Message::Record { line } => {
                if let Err(err) = file.write_all(line.as_bytes()).await {
                    warn!(error = %err, "audit write failed");
                    continue;
                }
                if let Err(err) = file.write_all(b"\n").await {
                    warn!(error = %err, "audit write failed");
                }
            }
            Message::Flush(ack) => {
                let _ = file.flush().await;
                let _ = ack.send(());
            }
        }
    }
    // Channel closed: drain any in-flight bytes to disk before the
    // task exits so a clean shutdown does not lose records.
    let _ = file.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use relix_core::inspect::Decision;
    use relix_core::model::HttpDirection;

    fn sample_event() -> InspectionEvent {
        InspectionEvent::new(uuid::Uuid::nil(), HttpDirection::Request, "host".into())
    }

    fn sample_verdict() -> Verdict {
        Verdict {
            decision: Decision::Allow,
            matches: vec![],
        }
    }

    fn unique_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("relix-audit-{tag}-{pid}-{nonce}.jsonl"));
        p
    }

    #[tokio::test]
    async fn writes_serially_in_order() {
        let path = unique_path("order");
        let log = AuditLog::open(path.clone()).await.expect("open");
        let mut event = sample_event();
        let verdict = sample_verdict();
        for i in 0..50 {
            event.upstream_host = format!("host-{i}");
            log.record(&event, &verdict);
        }
        log.flush().await;
        let contents = tokio::fs::read_to_string(&path).await.expect("read");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 50);
        for (i, line) in lines.iter().enumerate() {
            let expected = format!("host-{i}");
            assert!(
                line.contains(&expected),
                "line {i} missing {expected}: {line}"
            );
        }
        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn disabled_log_is_a_noop() {
        let log = AuditLog::disabled();
        let event = sample_event();
        let verdict = sample_verdict();
        for _ in 0..10 {
            log.record(&event, &verdict);
        }
        log.flush().await;
        // No file to read, no assertion to make beyond "did not
        // panic and dropped_count stayed at zero" — disabled() does
        // not count records as dropped.
        assert_eq!(log.dropped_count(), 0);
    }

    #[tokio::test]
    async fn channel_full_increments_dropped_counter() {
        // Bypass the public API to inject a tiny channel and a
        // writer that never consumes — a real-world equivalent of a
        // disk that has stalled. We assert the request-path side
        // (try_send + counter), which is the contract callers rely
        // on.
        let (tx, _rx) = mpsc::channel::<Message>(2);
        let log = AuditLog {
            inner: Arc::new(Inner {
                sender: Some(tx),
                dropped: AtomicU64::new(0),
            }),
        };
        let event = sample_event();
        let verdict = sample_verdict();
        for _ in 0..10 {
            log.record(&event, &verdict);
        }
        // Channel capacity is 2; first ~2 succeed, the rest count as dropped.
        assert!(
            log.dropped_count() >= 5,
            "expected drops after stalling sink, got {}",
            log.dropped_count()
        );
    }

    #[tokio::test]
    async fn record_does_not_block_on_slow_disk() {
        // We can't easily stall the real fs writer in a unit test, but
        // we *can* verify that record() returns synchronously without
        // awaiting — i.e. the function signature is `&self -> ()`,
        // not async. This compiles iff the contract holds.
        let log = AuditLog::disabled();
        let event = sample_event();
        let verdict = sample_verdict();
        let _: () = log.record(&event, &verdict);
    }
}
