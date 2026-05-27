//! Transport-layer driver: bridges axum to the [`LlmProxy`] trait.
//!
//! Responsible for:
//!
//! - reading the request from axum,
//! - selecting a protocol based on URL path,
//! - calling the lifecycle hooks in order,
//! - forwarding to the upstream over rustls (via reqwest),
//! - assembling the final axum [`Response`].
//!
//! This module deliberately holds no protocol-specific logic. All
//! protocol awareness lives in [`crate::proxy::protocols`].

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use bytes::Bytes;
use tracing::{debug, warn};

use crate::proxy::lifecycle::{
    HookOutcome, ProxyContext, ResponseAction, blocked_response,
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
    let resp_bytes = upstream_resp.bytes().await?;

    // Stage 3: response_filter
    let action = protocol
        .response_filter(&mut ctx, &state, status, &resp_headers_orig, &resp_bytes)
        .await?;

    match action {
        ResponseAction::Block(verdict) => {
            if let relix_core::Decision::Block { rule_id, reason } = &verdict.decision {
                Ok(blocked_response(rule_id, reason))
            } else {
                // Defensive: response_filter only returns Block with a
                // Block decision, but be safe if a future change drifts.
                Ok(blocked_response("relix.unknown", "blocked"))
            }
        }
        ResponseAction::Forward => Ok(forward_response(status, &resp_headers_orig, resp_bytes)?),
    }
}

fn forward_response(
    status: StatusCode,
    upstream_headers: &axum::http::HeaderMap,
    body: Bytes,
) -> anyhow::Result<Response> {
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if matches!(
            lname.as_str(),
            "content-length" | "transfer-encoding" | "connection"
        ) {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }
    Ok(builder.body(Body::from(body))?)
}
