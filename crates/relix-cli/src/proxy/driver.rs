//! Transport-layer driver: bridges axum to the [`LlmProxy`] trait.
//!
//! Two response paths exist:
//!
//! - **Buffered**: full upstream body is awaited, then handed to
//!   [`LlmProxy::response_filter`].
//! - **Streaming**: when the upstream returns `Content-Type:
//!   text/event-stream` and the protocol opts in via
//!   [`LlmProxy::response_filter_stream_init`], chunks are streamed
//!   to the client and inspected through
//!   [`StreamingProtocolState::feed_chunk`].
//!
//! No protocol-specific logic lives in this module.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::proxy::lifecycle::{
    BodyFilterAction, HookOutcome, ProxyContext, ResponseAction, StreamingState, blocked_response,
    streaming_block_frame,
};
use crate::proxy::protocols;
use crate::proxy::state::ProxyState;

/// Top-level axum handler. Wraps [`drive`] and converts internal
/// errors into a structured 502.
pub async fn proxy_handler(
    State(state): State<ProxyState>,
    req: Request<Body>,
) -> Response {
    match drive(state, req).await {
        Ok(resp) => resp,
        Err(err) => {
            warn!(error = %err, "proxy error");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("x-relix-error", "proxy")
                .body(Body::from(format!(
                    r#"{{"error":"relix_proxy_error","message":"{err}"}}"#
                )))
                .unwrap()
        }
    }
}

async fn drive(state: ProxyState, req: Request<Body>) -> anyhow::Result<Response> {
    let (parts, body) = req.into_parts();

    let upstream_host = url::Url::parse(&state.upstream)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into());

    let upstream_url = format!(
        "{}{}",
        state.upstream.trim_end_matches('/'),
        parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("")
    );

    let mut ctx = ProxyContext::new(parts.method.clone(), parts.uri.clone(), upstream_host);
    let protocol = protocols::select(&parts.uri);
    debug!(protocol = protocol.name(), uri = %parts.uri, "selected protocol");

    let body_bytes = axum::body::to_bytes(body, usize::MAX).await?;

    // Stage 1: request_filter
    match protocol
        .request_filter(&mut ctx, &state, &parts.headers, &body_bytes)
        .await?
    {
        HookOutcome::ShortCircuit(resp) => return Ok(resp),
        HookOutcome::Continue => {}
    }

    // Stage 2: forward to upstream
    let mut upstream_req = state
        .client
        .request(parts.method.clone(), &upstream_url)
        .body(body_bytes);
    for (name, value) in parts.headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if matches!(lname.as_str(), "host" | "content-length" | "connection") {
            continue;
        }
        upstream_req = upstream_req.header(name.clone(), value.clone());
    }

    let upstream_resp = upstream_req.send().await?;
    let status = upstream_resp.status();
    let resp_headers_orig = upstream_resp.headers().clone();

    // Stage 3a: streaming branch if upstream is SSE
    if is_event_stream(&resp_headers_orig) {
        if let Some(stream_state) =
            protocol.response_filter_stream_init(&ctx, &state, &resp_headers_orig)
        {
            return forward_streaming(
                state,
                ctx,
                status,
                resp_headers_orig,
                upstream_resp.bytes_stream(),
                stream_state,
            )
            .await;
        }
        // Protocol does not support streaming inspection: pass
        // bytes through unchanged. We still set up a streaming
        // forward so we do not buffer the whole body in memory.
        return Ok(forward_streaming_passthrough(
            status,
            resp_headers_orig,
            upstream_resp.bytes_stream(),
        ));
    }

    // Stage 3b: buffered branch
    let resp_bytes = upstream_resp.bytes().await?;
    let action = protocol
        .response_filter(&mut ctx, &state, status, &resp_headers_orig, &resp_bytes)
        .await?;
    match action {
        ResponseAction::Block(verdict) => {
            if let relix_core::Decision::Block { rule_id, reason } = &verdict.decision {
                Ok(blocked_response(rule_id, reason))
            } else {
                Ok(blocked_response("relix.unknown", "blocked"))
            }
        }
        ResponseAction::Forward => forward_buffered(status, &resp_headers_orig, resp_bytes),
    }
}

fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().starts_with("text/event-stream"))
        .unwrap_or(false)
}

fn forward_buffered(
    status: StatusCode,
    upstream_headers: &HeaderMap,
    body: Bytes,
) -> anyhow::Result<Response> {
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }
    Ok(builder.body(Body::from(body))?)
}

/// Forward a streaming SSE response to the agent without inspection.
/// Used when a protocol returns `None` from
/// `response_filter_stream_init` (it does not yet support streaming).
fn forward_streaming_passthrough<S>(
    status: StatusCode,
    upstream_headers: HeaderMap,
    upstream_body: S,
) -> Response
where
    S: futures::Stream<Item = reqwest::Result<Bytes>> + Send + 'static,
{
    let body = Body::from_stream(upstream_body);
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }
    builder.body(body).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from(r#"{"error":"relix_response_build_failed"}"#))
            .unwrap()
    })
}

/// Forward an SSE stream to the agent while inspecting each chunk.
///
/// On a `BlockMidStream` verdict, splices a synthetic `error` SSE
/// frame into the downstream body and stops forwarding upstream
/// bytes. The upstream connection is dropped when the spawned task
/// returns, freeing reqwest to close the socket.
async fn forward_streaming<S>(
    state: ProxyState,
    ctx: ProxyContext,
    status: StatusCode,
    upstream_headers: HeaderMap,
    upstream_body: S,
    stream_state: StreamingState,
) -> anyhow::Result<Response>
where
    S: futures::Stream<Item = reqwest::Result<Bytes>> + Send + 'static + Unpin,
{
    // Channel size 32 is large enough that a fast upstream does not
    // throttle the inspection loop in practice; small enough to keep
    // memory bounded if the downstream agent stalls.
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);

    let state = Arc::new(state);
    let ctx = Arc::new(ctx);

    tokio::spawn(async move {
        let mut upstream_body = upstream_body;
        while let Some(chunk_result) = upstream_body.next().await {
            let chunk = match chunk_result {
                Ok(b) => b,
                Err(err) => {
                    warn!(error = %err, "upstream stream error");
                    let _ = tx
                        .send(Err(std::io::Error::other(err.to_string())))
                        .await;
                    return;
                }
            };

            // Inspect under lock. The lock is per-request, so this
            // does not contend with anything else.
            let action = {
                let mut guard = stream_state.lock().await;
                match guard.feed_chunk(&state, &ctx, &chunk) {
                    Ok(a) => a,
                    Err(err) => {
                        warn!(error = %err, "stream inspector error (forwarding anyway)");
                        BodyFilterAction::Forward
                    }
                }
            };

            match action {
                BodyFilterAction::Forward => {
                    if tx.send(Ok(chunk)).await.is_err() {
                        // Downstream went away. Stop forwarding.
                        return;
                    }
                }
                BodyFilterAction::BlockMidStream(verdict) => {
                    let (rule_id, reason) = match verdict.decision {
                        relix_core::Decision::Block { rule_id, reason } => (rule_id, reason),
                        _ => ("relix.unknown".to_string(), "blocked".to_string()),
                    };
                    let frame = streaming_block_frame(&rule_id, &reason);
                    let _ = tx.send(Ok(frame)).await;
                    // Drop the upstream stream; reqwest will close.
                    return;
                }
            }
        }

        // Upstream finished cleanly. Let the protocol flush.
        let mut guard = stream_state.lock().await;
        if let Err(err) = guard.finish(&state, &ctx) {
            warn!(error = %err, "stream finish error");
        }
    });

    let body = Body::from_stream(ReceiverStream::new(rx));
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }
    Ok(builder.body(body)?)
}

fn is_hop_by_hop(name: &str) -> bool {
    let lname = name.to_ascii_lowercase();
    matches!(
        lname.as_str(),
        "content-length" | "transfer-encoding" | "connection"
    )
}
