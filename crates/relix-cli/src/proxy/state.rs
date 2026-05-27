use std::sync::Arc;

use crate::audit::AuditLog;
use relix_core::RuleSet;

/// State shared across all in-flight proxy requests.
///
/// Cloning is cheap: the rule set is `Arc`'d and the reqwest client
/// is internally reference-counted.
#[derive(Clone)]
pub struct ProxyState {
    pub upstream: String,
    pub client: reqwest::Client,
    pub rules: Arc<RuleSet>,
    pub audit: AuditLog,
}
