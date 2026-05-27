//! Anthropic Messages API adapter.
//!
//! v0.2-step1 preserves the v0.1 buffered behavior: the entire
//! upstream response is loaded into memory, parsed as a JSON
//! `Message`, and inspected. Streaming inspection ships in
//! v0.2-step2 (see RFC-0001 §"Streaming inspection").
//!
//! The protocol is responsible for:
//!
//! - extracting the system prompt from outbound requests so rules
//!   matching `system_prompt_regex` see it,
//! - parsing the response body as an Anthropic Message and pulling
//!   `tool_use` blocks into the rule engine.

use async_trait::async_trait;
use axum::http::{HeaderMap, StatusCode};
use bytes::Bytes;
use relix_core::Decision;
use relix_core::InspectionContext;
use relix_core::model::{HttpDirection, InspectionEvent};
use relix_core::protocol::AnthropicMessageResponse;
use serde_json::Value;
use tracing::info;

use crate::proxy::lifecycle::{
    HookOutcome, LlmProxy, ProxyContext, ResponseAction, blocked_response,
};
use crate::proxy::state::ProxyState;

pub struct AnthropicProtocol;

#[async_trait]
impl LlmProxy for AnthropicProtocol {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    async fn request_filter(
        &self,
        ctx: &mut ProxyContext,
        state: &ProxyState,
        _headers: &HeaderMap,
        body: &Bytes,
    ) -> anyhow::Result<HookOutcome> {
        let system_prompt = extract_system_prompt(body);

        let event = InspectionEvent::new(
            ctx.session_id,
            HttpDirection::Request,
            ctx.upstream_host.clone(),
        );
        let inspection_ctx = InspectionContext {
            event: &event,
            system_prompt: system_prompt.as_deref(),
        };
        let verdict = relix_core::inspect::evaluate(&state.rules, &inspection_ctx);
        state.audit.record(&event, &verdict).await;

        if let Decision::Block { reason, rule_id } = &verdict.decision {
            info!(rule = %rule_id, "blocking outbound request");
            return Ok(HookOutcome::ShortCircuit(blocked_response(rule_id, reason)));
        }

        Ok(HookOutcome::Continue)
    }

    async fn response_filter(
        &self,
        ctx: &mut ProxyContext,
        state: &ProxyState,
        _upstream_status: StatusCode,
        _upstream_headers: &HeaderMap,
        body: &Bytes,
    ) -> anyhow::Result<ResponseAction> {
        let mut event = InspectionEvent::new(
            ctx.session_id,
            HttpDirection::Response,
            ctx.upstream_host.clone(),
        );

        if let Ok(parsed) = serde_json::from_slice::<AnthropicMessageResponse>(body) {
            event.model = Some(parsed.model.clone());
            event.tool_calls = parsed.tool_calls();
        }

        let inspection_ctx = InspectionContext {
            event: &event,
            system_prompt: None,
        };
        let verdict = relix_core::inspect::evaluate(&state.rules, &inspection_ctx);
        state.audit.record(&event, &verdict).await;

        if matches!(verdict.decision, Decision::Block { .. }) {
            if let Decision::Block { rule_id, .. } = &verdict.decision {
                info!(rule = %rule_id, "blocking inbound response");
            }
            return Ok(ResponseAction::Block(verdict));
        }

        Ok(ResponseAction::Forward)
    }
}

/// Extract the system prompt from an Anthropic Messages request body.
///
/// The `system` field accepts two shapes per the Anthropic spec
/// (RFC-0001 references): a raw string, or an array of content
/// blocks where each block has a `text` field. We concatenate
/// text blocks with newlines.
pub(crate) fn extract_system_prompt(body: &Bytes) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_string_system_prompt() {
        let body = Bytes::from(r#"{"system":"You are helpful."}"#);
        assert_eq!(
            extract_system_prompt(&body),
            Some("You are helpful.".to_string())
        );
    }

    #[test]
    fn extracts_array_system_prompt() {
        let body = Bytes::from(
            r#"{"system":[{"type":"text","text":"line one"},{"type":"text","text":"line two"}]}"#,
        );
        assert_eq!(
            extract_system_prompt(&body),
            Some("line one\nline two".to_string())
        );
    }

    #[test]
    fn returns_none_when_absent() {
        let body = Bytes::from(r#"{"messages":[]}"#);
        assert_eq!(extract_system_prompt(&body), None);
    }
}
