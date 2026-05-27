use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use relix_core::model::{HttpDirection, InspectionEvent};
use relix_core::protocol::AnthropicMessageResponse;
use relix_core::{Decision, InspectionContext, RuleSet};
use serde_json::Value;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::audit::AuditLog;

#[derive(Clone)]
pub struct ProxyState {
    pub upstream: String,
    pub client: reqwest::Client,
    pub rules: Arc<RuleSet>,
    pub audit: AuditLog,
}

pub async fn proxy_handler(
    State(state): State<ProxyState>,
    req: Request<Body>,
) -> Response {
    match handle(state, req).await {
        Ok(resp) => resp,
        Err(err) => {
            warn!(error = %err, "proxy error");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!(
                    r#"{{"error":"relix_proxy_error","message":"{err}"}}"#
                )))
                .unwrap()
        }
    }
}

async fn handle(state: ProxyState, req: Request<Body>) -> anyhow::Result<Response> {
    let session_id = Uuid::new_v4();
    let (parts, body) = req.into_parts();

    let upstream_url = format!(
        "{}{}",
        state.upstream.trim_end_matches('/'),
        parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("")
    );
    let upstream_host = url::Url::parse(&state.upstream)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into());

    let body_bytes = axum::body::to_bytes(body, usize::MAX).await?;

    // Inspect outbound: parse system prompt if present, run rules.
    let outbound_system_prompt = extract_system_prompt(&body_bytes);
    let outbound_event = InspectionEvent::new(
        session_id,
        HttpDirection::Request,
        upstream_host.clone(),
    );
    let outbound_ctx = InspectionContext {
        event: &outbound_event,
        system_prompt: outbound_system_prompt.as_deref(),
    };
    let outbound_verdict = relix_core::inspect::evaluate(&state.rules, &outbound_ctx);
    state.audit.record(&outbound_event, &outbound_verdict).await;

    if let Decision::Block { reason, rule_id } = &outbound_verdict.decision {
        info!(rule = %rule_id, "blocking outbound request");
        return Ok(blocked_response(rule_id, reason));
    }

    // Forward to upstream.
    let mut upstream_req = state
        .client
        .request(parts.method.clone(), &upstream_url)
        .body(body_bytes.clone());
    for (name, value) in parts.headers.iter() {
        // strip hop-by-hop and host
        let lname = name.as_str().to_ascii_lowercase();
        if matches!(lname.as_str(), "host" | "content-length" | "connection") {
            continue;
        }
        upstream_req = upstream_req.header(name.clone(), value.clone());
    }

    let upstream_resp = upstream_req.send().await?;
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_bytes = upstream_resp.bytes().await?;

    // Inspect inbound (non-streaming for now).
    let mut inbound_event = InspectionEvent::new(
        session_id,
        HttpDirection::Response,
        upstream_host,
    );
    if let Ok(parsed) = serde_json::from_slice::<AnthropicMessageResponse>(&resp_bytes) {
        inbound_event.model = Some(parsed.model.clone());
        inbound_event.tool_calls = parsed.tool_calls();
    }
    let inbound_ctx = InspectionContext {
        event: &inbound_event,
        system_prompt: None,
    };
    let inbound_verdict = relix_core::inspect::evaluate(&state.rules, &inbound_ctx);
    state.audit.record(&inbound_event, &inbound_verdict).await;

    if let Decision::Block { reason, rule_id } = &inbound_verdict.decision {
        info!(rule = %rule_id, "blocking inbound response");
        return Ok(blocked_response(rule_id, reason));
    }

    debug!(?status, bytes = resp_bytes.len(), "forwarded response");
    let mut builder = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if matches!(
            lname.as_str(),
            "content-length" | "transfer-encoding" | "connection"
        ) {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }
    Ok(builder.body(Body::from(resp_bytes))?)
}

fn extract_system_prompt(body: &Bytes) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    match v.get("system")? {
        Value::String(s) => Some(s.clone()),
        Value::Array(parts) => Some(
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        _ => None,
    }
}

fn blocked_response(rule_id: &str, reason: &str) -> Response {
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
    resp.headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    resp.headers_mut()
        .insert("x-relix-blocked", HeaderValue::from_static("1"));
    resp
}
