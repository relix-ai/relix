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
    blocked_response, streaming_block_frame, BodyFilterAction, HookOutcome, ProxyContext,
    ResponseAction, StreamingState,
};
use crate::proxy::protocols;
use crate::proxy::state::ProxyState;

/// Hard cap on the number of bytes accepted in an inbound request
/// body. 16 MiB is generously above any legitimate Anthropic /
/// OpenAI / Gemini request and well below default OS process memory
/// pressure thresholds. Defends against attackers that try to
/// exhaust memory by streaming a never-ending request body.
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Per-chunk slice cap fed to the streaming inspector and to the
/// downstream channel (RFC-0003 H9). `reqwest::Response::bytes_stream`
/// may yield arbitrary-sized chunks; a malicious upstream that pushes
/// a single multi-megabyte chunk would force the SSE decoder to
/// allocate the full chunk before the per-frame 1 MiB cap fires,
/// since the cap is checked once per `next_frame` call. Slicing on
/// the way in keeps the assembler buffer growth bounded by this cap
/// per iteration and also reduces inspection latency on legitimate
/// fragmented streams. 64 KiB matches typical TLS record / TCP
/// segment sizes so well-behaved upstreams pay no extra copy cost.
const MAX_CHUNK_SLICE: usize = 64 * 1024;

/// Hard cap on the total size of a buffered (non-streaming) upstream
/// response (RFC-0003 H9 red-team follow-up). The streaming branch
/// is bounded by [`MAX_CHUNK_SLICE`] per inspection step plus the
/// 1 MiB per-frame cap inside the SSE decoder; the buffered branch,
/// in contrast, calls `Response::bytes()` which collects the entire
/// body into memory before inspection. Without this cap a malicious
/// upstream could force Relix to allocate gigabytes by chunking a
/// huge JSON message. 32 MiB is well above any legitimate Anthropic
/// or OpenAI non-streaming response (token-count, models list,
/// completed message) and well below process memory pressure.
const MAX_BUFFERED_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;

/// Top-level axum handler. Wraps [`drive`] and converts internal
/// errors into a structured 502.
pub async fn proxy_handler(State(state): State<ProxyState>, req: Request<Body>) -> Response {
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

    // RFC-0003 H4: classify the inbound path before contacting the
    // upstream. Unsafe paths (path traversal, encoded slashes,
    // control bytes, etc.) are rejected with 400 *here*, never
    // forwarded. The classifier is also used downstream by the
    // protocol selector but is checked again at URL construction
    // time as defence in depth.
    match crate::proxy::url::classify_path(parts.uri.path()) {
        crate::proxy::url::PathDecision::Reject(reason) => {
            warn!(path = %parts.uri.path(), %reason, "rejecting unsafe inbound path");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("x-relix-error", "unsafe-path")
                .body(Body::from(format!(
                    r#"{{"error":"relix_unsafe_path","message":"{reason}"}}"#
                )))
                .unwrap());
        }
        crate::proxy::url::PathDecision::AllowedKnown
        | crate::proxy::url::PathDecision::AllowedUnknown => {}
    }

    // Parse the upstream base once. A misconfigured upstream URL
    // is a fatal config bug, not a per-request error; surface 502
    // and let the operator fix it.
    let upstream_base = ::url::Url::parse(&state.upstream)
        .map_err(|e| anyhow::anyhow!("invalid RELIX_UPSTREAM '{}': {e}", state.upstream))?;
    let upstream_host = upstream_base
        .host_str()
        .map(str::to_string)
        .unwrap_or_else(|| "unknown".into());

    let upstream_url = crate::proxy::url::build_upstream_url(&upstream_base, &parts.uri)
        .map_err(|e| anyhow::anyhow!("upstream URL construction rejected inbound URI: {e}"))?;

    let mut ctx = ProxyContext::new(parts.method.clone(), parts.uri.clone(), upstream_host);
    let protocol = protocols::select(&parts.uri);
    debug!(protocol = protocol.name(), uri = %parts.uri, "selected protocol");

    // Hard cap on inbound request body size. LLM API calls do not
    // legitimately exceed this; without it, an attacker can drive
    // memory usage to the system limit by sending a never-ending
    // request body.
    let body_bytes = axum::body::to_bytes(body, MAX_REQUEST_BODY_BYTES).await?;

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
        .request(parts.method.clone(), upstream_url)
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
    let resp_bytes = collect_capped(upstream_resp.bytes_stream()).await?;
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
                    let _ = tx.send(Err(std::io::Error::other(err.to_string()))).await;
                    return;
                }
            };

            // RFC-0003 H9: slice the upstream chunk into <= 64 KiB
            // pieces before inspection. Without this, a single
            // chunk of N MiB pushes N MiB into the assembler buffer
            // before the 1 MiB per-frame cap can fire, since the
            // cap is checked once per `next_frame` call rather than
            // on each push. Slicing also bounds the size of each
            // forwarded `Bytes` we hand to the downstream channel.
            for slice in slice_chunk(chunk, MAX_CHUNK_SLICE) {
                // Inspect under lock. The lock is per-request, so
                // this does not contend with anything else.
                let action = {
                    let mut guard = stream_state.lock().await;
                    match guard.feed_chunk(&state, &ctx, &slice) {
                        Ok(a) => a,
                        Err(err) => {
                            warn!(
                                error = %err,
                                "stream inspector error (forwarding anyway)"
                            );
                            BodyFilterAction::Forward
                        }
                    }
                };

                match action {
                    BodyFilterAction::Forward => {
                        if tx.send(Ok(slice)).await.is_err() {
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

/// Collect a buffered upstream response into a single `Bytes`, bailing
/// with a hard error once [`MAX_BUFFERED_RESPONSE_BYTES`] is exceeded
/// (RFC-0003 H9 red-team follow-up).
///
/// Using this in place of `Response::bytes()` means a malicious
/// upstream cannot drive Relix to OOM by chunked-encoding a giant
/// non-streaming response. The cap is checked on each chunk so the
/// allocation never grows past it.
async fn collect_capped<S>(stream: S) -> anyhow::Result<Bytes>
where
    S: futures::Stream<Item = reqwest::Result<Bytes>> + Send + 'static + Unpin,
{
    let mut stream = stream;
    let mut total: u64 = 0;
    let mut buf = bytes::BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        total = total.saturating_add(chunk.len() as u64);
        if total > MAX_BUFFERED_RESPONSE_BYTES {
            anyhow::bail!(
                "upstream response exceeds {} byte cap",
                MAX_BUFFERED_RESPONSE_BYTES
            );
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}

/// Slice a chunk into pieces of at most `max` bytes (RFC-0003 H9).
///
/// Returns an iterator of cheap `Bytes::slice` views (no copy) so the
/// caller can feed each piece independently to the inspector and the
/// downstream channel. Always yields at least one piece, even for an
/// empty input chunk, to preserve original framing for empty
/// keep-alive chunks (rare but legal in chunked-transfer).
fn slice_chunk(chunk: Bytes, max: usize) -> impl Iterator<Item = Bytes> {
    debug_assert!(max > 0, "slice cap must be positive");
    let total = chunk.len();
    let mut offset = 0usize;
    let mut yielded_empty = false;

    std::iter::from_fn(move || {
        if total == 0 {
            if yielded_empty {
                return None;
            }
            yielded_empty = true;
            return Some(chunk.clone());
        }
        if offset >= total {
            return None;
        }
        let end = offset.saturating_add(max).min(total);
        let piece = chunk.slice(offset..end);
        offset = end;
        Some(piece)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_chunk_yields_pieces_of_at_most_max() {
        let chunk = Bytes::from(vec![0u8; 200_000]);
        let pieces: Vec<Bytes> = slice_chunk(chunk, MAX_CHUNK_SLICE).collect();
        // 200_000 / 65_536 = 3 full + 1 partial (3408 bytes).
        assert_eq!(pieces.len(), 4);
        assert_eq!(pieces[0].len(), MAX_CHUNK_SLICE);
        assert_eq!(pieces[1].len(), MAX_CHUNK_SLICE);
        assert_eq!(pieces[2].len(), MAX_CHUNK_SLICE);
        assert_eq!(pieces[3].len(), 200_000 - 3 * MAX_CHUNK_SLICE);
        let total: usize = pieces.iter().map(|p| p.len()).sum();
        assert_eq!(total, 200_000);
    }

    #[test]
    fn slice_chunk_passes_small_chunk_through_unchanged() {
        let chunk = Bytes::from_static(b"hello");
        let pieces: Vec<Bytes> = slice_chunk(chunk.clone(), MAX_CHUNK_SLICE).collect();
        assert_eq!(pieces.len(), 1);
        assert_eq!(pieces[0], chunk);
    }

    #[test]
    fn slice_chunk_handles_exact_multiple() {
        let size = MAX_CHUNK_SLICE * 3;
        let chunk = Bytes::from(vec![1u8; size]);
        let pieces: Vec<Bytes> = slice_chunk(chunk, MAX_CHUNK_SLICE).collect();
        assert_eq!(pieces.len(), 3);
        for p in &pieces {
            assert_eq!(p.len(), MAX_CHUNK_SLICE);
        }
    }

    #[test]
    fn slice_chunk_handles_empty_chunk() {
        let chunk = Bytes::new();
        let pieces: Vec<Bytes> = slice_chunk(chunk, MAX_CHUNK_SLICE).collect();
        // Empty input still yields one (empty) piece so framing is
        // preserved on keep-alive style chunks.
        assert_eq!(pieces.len(), 1);
        assert_eq!(pieces[0].len(), 0);
    }

    #[test]
    fn slice_chunk_caps_a_one_megabyte_chunk() {
        // RFC-0003 H9 motivating case: a 1 MiB single chunk must be
        // split into many pieces, none exceeding the cap.
        let size = 1024 * 1024;
        let chunk = Bytes::from(vec![0xAB; size]);
        let pieces: Vec<Bytes> = slice_chunk(chunk, MAX_CHUNK_SLICE).collect();
        assert_eq!(pieces.len(), size / MAX_CHUNK_SLICE);
        for p in &pieces {
            assert!(p.len() <= MAX_CHUNK_SLICE);
        }
    }

    #[tokio::test]
    async fn rt_collect_capped_rejects_oversize_buffered_response() {
        // Red-team regression for the H9 follow-up: a malicious
        // non-streaming upstream that exceeds the buffered cap must
        // be rejected before the body is fully buffered.
        let one_mb_chunk = Bytes::from(vec![0u8; 1024 * 1024]);
        let chunks = (0..40)
            .map(|_| Ok::<_, reqwest::Error>(one_mb_chunk.clone()))
            .collect::<Vec<_>>();
        let stream = futures::stream::iter(chunks);
        let err = collect_capped(stream).await.expect_err("must reject");
        assert!(
            err.to_string().contains("exceeds"),
            "expected size cap error, got: {err}"
        );
    }

    #[tokio::test]
    async fn collect_capped_passes_legitimate_response() {
        let body = Bytes::from_static(b"{\"ok\":true}");
        let stream = futures::stream::iter(vec![Ok::<_, reqwest::Error>(body.clone())]);
        let collected = collect_capped(stream).await.expect("collect");
        assert_eq!(collected, body);
    }
}
