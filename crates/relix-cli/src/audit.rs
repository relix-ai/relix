use std::sync::Arc;

use anyhow::Result;
use relix_core::model::InspectionEvent;
use relix_core::Verdict;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::warn;

/// Append-only jsonl audit logger.
///
/// Note: we intentionally do NOT log full request/response bodies, only
/// the inspection event (which already excludes user prompt content) and
/// the verdict.
#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    file: Option<tokio::fs::File>,
}

#[derive(Debug, Serialize)]
struct AuditRecord<'a> {
    event: &'a InspectionEvent,
    verdict: &'a Verdict,
}

impl AuditLog {
    pub async fn open(path: std::path::PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .ok();
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner { file })),
        })
    }

    pub async fn record(&self, event: &InspectionEvent, verdict: &Verdict) {
        let line = match serde_json::to_string(&AuditRecord { event, verdict }) {
            Ok(s) => s,
            Err(err) => {
                warn!(error = %err, "audit serialize failed");
                return;
            }
        };
        let mut guard = self.inner.lock().await;
        if let Some(f) = guard.file.as_mut() {
            if let Err(err) = f.write_all(line.as_bytes()).await {
                warn!(error = %err, "audit write failed");
            }
            let _ = f.write_all(b"\n").await;
            let _ = f.flush().await;
        }
    }
}
