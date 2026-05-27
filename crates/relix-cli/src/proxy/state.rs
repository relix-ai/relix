use std::sync::Arc;

use crate::audit::AuditLog;
use relix_core::{RedactConfig, RuleSet, Vault};

/// State shared across all in-flight proxy requests.
///
/// Cloning is cheap: the rule set is `Arc`'d, the reqwest client is
/// internally reference-counted, and the vault wraps an `Arc<RwLock>`.
#[derive(Clone)]
pub struct ProxyState {
    pub upstream: String,
    pub client: reqwest::Client,
    pub rules: Arc<RuleSet>,
    pub audit: AuditLog,
    /// Secret-redaction subsystem (RFC-0004). When
    /// `redact_config.enabled` is `false`, the proxy skips both the
    /// outbound redaction pass and the inbound restore pass.
    pub vault: Vault,
    pub redact_config: Arc<RedactConfig>,
}
