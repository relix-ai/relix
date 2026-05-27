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

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::Response;
use bytes::Bytes;
use relix_core::Verdict;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::proxy::state::ProxyState;

/// Per-request inspection context. Lives for the duration of a single
/// HTTP request through the proxy.
///
/// `method` and `uri` are retained on the context so streaming hooks
/// (notably [`LlmProxy::response_body_filter`]) can introspect the
/// original request without holding a reference to the consumed
/// axum `Request`.
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
/// a hook may either let the pipeline continue, or short-circuit
/// with a synthesized response.
pub enum HookOutcome {
    /// Continue to the next stage of the pipeline.
    Continue,
    /// Short-circuit: return this response to the agent immediately.
    /// Used by `request_filter` when a rule blocks an outbound
    /// request before any upstream contact.
    ShortCircuit(Response),
}

/// Outcome of [`LlmProxy::response_filter`] (buffered path).
pub enum ResponseAction {
    /// Forward the upstream response to the agent unchanged.
    Forward,
    /// Replace the response with a block notice carrying the verdict.
    Block(Verdict),
}

/// Outcome of [`LlmProxy::response_body_filter`] (streaming path),
/// applied per chunk.
pub enum BodyFilterAction {
    /// Forward this chunk to the agent unchanged.
    Forward,
    /// A rule fired during streaming. The driver will close the
    /// upstream connection and emit a synthetic SSE error frame to
    /// the agent identifying the rule.
    BlockMidStream(Verdict),
}

/// State for streaming responses. Created by
/// [`LlmProxy::response_filter_stream_init`] when an upstream
/// response is detected to be `text/event-stream`. Subsequent
/// chunks are fed to [`LlmProxy::response_body_filter`].
///
/// The state is `Send + Sync` and held inside a `Mutex` so the
/// driver can poll it from a streaming task without holding a
/// borrow on the protocol implementation.
pub type StreamingState = Arc<Mutex<dyn StreamingProtocolState>>;

/// Per-protocol streaming state.
///
/// Anthropic uses [`crate::proxy::protocols::anthropic::AnthropicStreamingState`];
/// OpenAI and Gemini will provide their own. The driver only sees
/// this opaque trait.
pub trait StreamingProtocolState: Send + Sync {
    /// Feed a chunk of upstream bytes. Returns the action the driver
    /// should take for this chunk.
    fn feed_chunk(
        &mut self,
        state: &ProxyState,
        ctx: &ProxyContext,
        chunk: &[u8],
    ) -> anyhow::Result<BodyFilterAction>;

    /// Called once when the upstream stream ends cleanly. Used to
    /// flush any pending events to the audit log.
    fn finish(
        &mut self,
        state: &ProxyState,
        ctx: &ProxyContext,
    ) -> anyhow::Result<()>;
}

/// The contract every protocol must satisfy.
///
/// Implementations are stateless across requests; per-request state
/// lives in [`ProxyContext`] for non-streaming hooks and in
/// [`StreamingProtocolState`] for streaming.
#[async_trait]
pub trait LlmProxy: Send + Sync {
    /// Stable identifier for the protocol, used in audit logs.
    fn name(&self) -> &'static str;

    /// Inspect the inbound (agent → upstream) request, run outbound
    /// rules, and decide whether to forward.
    async fn request_filter(
        &self,
        ctx: &mut ProxyContext,
        state: &ProxyState,
        headers: &HeaderMap,
        body: &Bytes,
    ) -> anyhow::Result<HookOutcome>;

    /// Inspect a fully-buffered upstream response. Called when the
    /// upstream content type is **not** `text/event-stream`.
    async fn response_filter(
        &self,
        ctx: &mut ProxyContext,
        state: &ProxyState,
        upstream_status: StatusCode,
        upstream_headers: &HeaderMap,
        body: &Bytes,
    ) -> anyhow::Result<ResponseAction>;

    /// Build per-protocol streaming state for an SSE response.
    ///
    /// The driver calls this when the upstream response carries
    /// `Content-Type: text/event-stream`. Each subsequent chunk is
    /// fed to the returned state via
    /// [`StreamingProtocolState::feed_chunk`].
    ///
    /// The default implementation returns `None`, meaning the
    /// protocol does not yet support streaming inspection — the
    /// driver will pass bytes through unchanged.
    fn response_filter_stream_init(
        &self,
        _ctx: &ProxyContext,
        _state: &ProxyState,
        _upstream_headers: &HeaderMap,
    ) -> Option<StreamingState> {
        None
    }
}

/// Build the canonical 403 block response sent to the agent when a
/// rule fires. Used by `request_filter` short-circuits and the
/// non-streaming `response_filter` block path.
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
    *resp.status_mut() = StatusCode::FORBIDDEN;
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

/// Build a synthetic SSE error frame to splice into a streaming
/// response when a rule fires mid-stream. The agent sees a
/// well-formed `error` event so it can fail gracefully.
pub fn streaming_block_frame(rule_id: &str, reason: &str) -> Bytes {
    let payload = serde_json::json!({
        "type": "error",
        "error": {
            "type": "relix_blocked",
            "rule_id": rule_id,
            "message": format!("Relix blocked this stream: {reason}"),
        }
    });
    let frame = format!(
        "event: error\ndata: {}\n\n",
        serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
    );
    Bytes::from(frame)
}
