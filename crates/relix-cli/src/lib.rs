//! Relix CLI library surface.
//!
//! The binary `src/main.rs` is a thin wrapper around the items exposed
//! here. End-to-end tests under `tests/` link against this library to
//! boot a real Relix instance in-process on a `127.0.0.1:0` port.
//!
//! Stability: this surface is intentionally minimal and **not** a public
//! API. Versioning policy applies to the `relix` binary, not to these
//! re-exports. Out-of-tree consumers should depend on `relix-core`
//! (Apache-2.0) instead of `relix-cli` (AGPL-3.0).

pub mod audit;
pub mod cli;
pub mod proxy;
pub mod rules_loader;

use std::sync::Arc;

use anyhow::Result;
use axum::routing::any;
use axum::Router;

pub use crate::audit::AuditLog;
pub use crate::proxy::{proxy_handler, ProxyState};

/// Build the axum [`Router`] used by the proxy. Used by the binary
/// entry point and by integration tests so they share exactly the
/// same handler wiring.
pub fn app_router(state: ProxyState) -> Router {
    Router::new()
        .route("/", any(proxy_handler))
        .route("/*path", any(proxy_handler))
        .with_state(state)
}

/// Convenience constructor: assemble a [`ProxyState`] from its parts.
/// `upstream` must be a valid http/https URL; the constructor does not
/// validate it (validation happens at first request, where the error
/// is surfaced as a 502).
pub async fn build_state(
    upstream: String,
    rules: relix_core::RuleSet,
    audit: AuditLog,
) -> Result<ProxyState> {
    let client = crate::proxy::client::build()?;
    Ok(ProxyState {
        upstream,
        client,
        rules: Arc::new(rules),
        audit,
    })
}
