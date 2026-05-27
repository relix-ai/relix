//! Lifecycle hooks for an LLM proxy.
//!
//! The trait is modeled on Cloudflare Pingora's `ProxyHttp`. Hook
//! names are intentionally identical so the abstraction is easy to
//! port to a Pingora-based backend in a later milestone.
//!
//! Each concrete protocol (Anthropic, OpenAI, Gemini, passthrough)
//! provides an implementation of [`LlmProxy`]. The
//! [`crate::proxy::driver`] module dispatches incoming requests to
//! the right implementation based on URL path.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Uri};
use axum::response::Response;
use bytes::Bytes;
use relix_core::Verdict;
use uuid::Uuid;

use crate::proxy::state::ProxyState;

/// Per-request inspection context. Lives for the duration of a single
/// HTTP request through the proxy. Hooks may store extra state in
/// the implementation's own struct fields if needed.
///
/// `method` and `uri` are kept on the context so future hooks
/// (notably `response_body_filter` for streaming responses, planned
/// for v0.2-step2) can introspect the original request without
/// holding a reference to the now-consumed `Request`. They appear
/// unused in v0.2-step1 because no hook reads them yet.
#[allow(dead_code)]
pub struct ProxyContext {
    pub session_id: Uuid,
    pub method: Method,
    pub uri: Uri,
    pub upstream_host: String,
}

impl ProxyContext {
    pub fn new(method: Method, uri: Uri, upstream_host: String) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            method,
            uri,
            upstream_host,
        }
    }
}

/// Outcome of an early lifecycle hook. Mirrors Pingora's pattern:
/// a hook may either let the pipeline continue, short-circuit with
/// a synthesized response, or fail the request entirely.
pub enum HookOutcome {
    /// Continue to the next stage of the pipeline.
    Continue,
    /// Short-circuit: return this response to the agent immediately.
    /// Used by `request_filter` when a rule blocks an outbound
    /// request before any upstream contact.
    ShortCircuit(Response),
}

/// The contract every protocol must satisfy.
///
/// Implementations are stateless across requests; per-request state
/// lives in [`ProxyContext`]. Hooks correspond to the lifecycle
/// stages described in RFC-0001 §"Lifecycle hooks".
#[async_trait]
pub trait LlmProxy: Send + Sync {
    /// Stable identifier for the protocol, used in audit logs.
    fn name(&self) -> &'static str;

    /// Inspect the inbound (agent → upstream) request, run outbound
    /// rules, and decide whether to forward.
    ///
    /// Returns `Continue` to proceed to upstream, `ShortCircuit` to
    /// reply directly without contacting the upstream.
    async fn request_filter(
        &self,
        ctx: &mut ProxyContext,
        state: &ProxyState,
        headers: &HeaderMap,
        body: &Bytes,
    ) -> anyhow::Result<HookOutcome>;

    /// Inspect a fully-buffered upstream response and decide whether
    /// to forward the bytes unchanged or replace them with a block
    /// notice.
    ///
    /// In v0.2 this hook will be replaced for streaming responses
    /// with a `response_body_filter` that operates per-chunk. v0.1
    /// shipped only this buffered path; v0.2-step1 preserves it.
    async fn response_filter(
        &self,
        ctx: &mut ProxyContext,
        state: &ProxyState,
        upstream_status: axum::http::StatusCode,
        upstream_headers: &HeaderMap,
        body: &Bytes,
    ) -> anyhow::Result<ResponseAction>;
}

/// Outcome of `response_filter`.
pub enum ResponseAction {
    /// Forward the upstream response to the agent unchanged.
    Forward,
    /// Replace the response with a block notice carrying the verdict.
    Block(Verdict),
}

/// Build the canonical 403 block response sent to the agent when a
/// rule fires. Used by both `request_filter` short-circuits and
/// `response_filter` blocks.
pub fn blocked_response(rule_id: &str, reason: &str) -> Response {
    let body = serde_json::json!({
        "type": "error",
        "error": {
            "type": "relix_blocked",
            "rule_id": rule_id,
            "message": format!("Relix blocked this request: {reason}"),
        }
    });
    let mut resp = Response::new(Body::from(body.to_string()));
    *resp.status_mut() = axum::http::StatusCode::FORBIDDEN;
    resp.headers_mut().insert(
        "content-type",
        axum::http::HeaderValue::from_static("application/json"),
    );
    resp.headers_mut().insert(
        "x-relix-blocked",
        axum::http::HeaderValue::from_static("1"),
    );
    resp
}
