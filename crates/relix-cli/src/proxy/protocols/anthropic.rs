//! Anthropic Messages API adapter.
//!
//! Two paths are supported:
//!
//! - **Buffered**: non-streaming responses (`Content-Type: application/json`).
//!   The full body is parsed as an Anthropic `Message` and inspected.
//!   This is the v0.1 behavior, preserved for clients that opt out
//!   of streaming.
//!
//! - **Streaming**: SSE responses (`Content-Type: text/event-stream`).
//!   Bytes are fed incrementally to a [`relix_core::AnthropicStreamAssembler`].
//!   `tool_use` blocks are inspected at `content_block_stop`, never
//!   on partial deltas — see RFC-0001 §"Per-block accumulator".
//!
//! The protocol is also responsible for extracting the system prompt
//! from outbound requests so rules matching `system_prompt_regex` see
//! it.

use async_trait::async_trait;
use axum::http::{HeaderMap, StatusCode};
use bytes::Bytes;
use relix_core::model::{HttpDirection, InspectionEvent};
use relix_core::protocol::AnthropicMessageResponse;
use relix_core::Decision;
use relix_core::InspectionContext;
use relix_core::{AnthropicStreamAssembler, StreamEvent};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::proxy::lifecycle::{
    blocked_response, BodyFilterAction, HookOutcome, LlmProxy, ProxyContext, ResponseAction,
    StreamingProtocolState, StreamingState,
};
use crate::proxy::redact::{redact_outbound, RedactPaths};
use crate::proxy::state::ProxyState;

/// JSON paths the redactor should walk in an Anthropic Messages
/// request body. `system` may be a raw string or an array of
/// `{"type":"text","text":"..."}` content blocks; both shapes are
/// handled.
const REDACT_PATHS: RedactPaths = RedactPaths {
    top_level_strings: &["system"],
    top_level_text_arrays: &["system"],
    walk_messages: true,
};

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
        // RFC-0004: redact secrets in the outbound body before
        // anything else looks at it. The redacted body is what
        // gets forwarded upstream and what the rule engine
        // inspects, so a system_prompt rule sees the
        // already-redacted text — secrets never reach either
        // upstream or the audit log.
        let outcome = redact_outbound(state, &REDACT_PATHS, body).await;
        let body_for_inspection = if outcome.count > 0 {
            ctx.redacted_count = outcome.count;
            ctx.replaced_body = Some(outcome.body.clone());
            outcome.body
        } else {
            body.clone()
        };

        let system_prompt = extract_system_prompt(&body_for_inspection);

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
        state.audit.record(&event, &verdict);

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
        // RFC-0004 S4: scan the upstream response for literal real
        // secret values. A response carrying a real key is either
        // a leak from a misbehaving upstream or active reverse
        // poisoning. Block-on-leak is on by default.
        if let Some(leak) = crate::proxy::redact::detect_upstream_leak(state, body) {
            let verdict = relix_core::Verdict {
                decision: relix_core::Decision::Block {
                    rule_id: leak.rule_id().to_string(),
                    reason: leak.reason(),
                },
                matches: vec![],
            };
            let event = InspectionEvent::new(
                ctx.session_id,
                HttpDirection::Response,
                ctx.upstream_host.clone(),
            );
            state.audit.record(&event, &verdict);
            return Ok(ResponseAction::Block(verdict));
        }

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
        state.audit.record(&event, &verdict);

        if matches!(verdict.decision, Decision::Block { .. }) {
            if let Decision::Block { rule_id, .. } = &verdict.decision {
                info!(rule = %rule_id, "blocking inbound response");
            }
            return Ok(ResponseAction::Block(verdict));
        }

        Ok(ResponseAction::Forward)
    }

    fn response_filter_stream_init(
        &self,
        _ctx: &ProxyContext,
        _state: &ProxyState,
        _upstream_headers: &HeaderMap,
    ) -> Option<StreamingState> {
        Some(Arc::new(Mutex::new(AnthropicStreamingState::default())))
    }
}

/// Per-stream state for Anthropic SSE responses.
///
/// Owns an [`AnthropicStreamAssembler`] and accumulates `tool_use`
/// events for inspection. On every chunk:
///
/// 1. bytes go to the assembler,
/// 2. drained `StreamEvent`s are converted into rule-engine input,
/// 3. if any rule blocks, the driver is told to splice in an error
///    SSE frame and close the connection.
#[derive(Default)]
pub struct AnthropicStreamingState {
    assembler: AnthropicStreamAssembler,
    /// Model identifier observed in `message_start`. Cached so audit
    /// records can include it.
    model: Option<String>,
    /// True after a block has fired. Subsequent chunks are dropped.
    poisoned: bool,
}

impl StreamingProtocolState for AnthropicStreamingState {
    fn feed_chunk(
        &mut self,
        state: &ProxyState,
        ctx: &ProxyContext,
        chunk: &[u8],
    ) -> anyhow::Result<BodyFilterAction> {
        if self.poisoned {
            // Once we have already blocked, do not inspect further;
            // the connection is being torn down by the driver.
            return Ok(BodyFilterAction::Forward);
        }

        self.assembler.push_bytes(chunk);
        let events = self.assembler.drain_events();

        for ev in events {
            match ev {
                StreamEvent::StreamStart { model } => {
                    self.model = Some(model);
                }
                StreamEvent::ToolUseFinalised {
                    name, input, id, ..
                } => {
                    let mut event = InspectionEvent::new(
                        ctx.session_id,
                        HttpDirection::Response,
                        ctx.upstream_host.clone(),
                    );
                    event.model = self.model.clone();
                    event.tool_calls.push(relix_core::ToolCall {
                        name,
                        input,
                        id: Some(id),
                    });

                    let inspection_ctx = InspectionContext {
                        event: &event,
                        system_prompt: None,
                    };
                    let verdict = relix_core::inspect::evaluate(&state.rules, &inspection_ctx);

                    // Non-blocking enqueue. The single writer task
                    // serialises records and owns the file handle;
                    // see audit::AuditLog (RFC-0003 H2).
                    state.audit.record(&event, &verdict);

                    if matches!(verdict.decision, Decision::Block { .. }) {
                        if let Decision::Block { rule_id, .. } = &verdict.decision {
                            info!(rule = %rule_id, "blocking streaming tool_use");
                        }
                        self.poisoned = true;
                        return Ok(BodyFilterAction::BlockMidStream(verdict));
                    }
                }
                StreamEvent::StreamEnd { .. } => {}
                StreamEvent::ParseError { reason } => {
                    info!(reason = %reason, "stream parse error (forwarding chunk anyway)");
                }
            }
        }

        Ok(BodyFilterAction::Forward)
    }

    fn finish(&mut self, _state: &ProxyState, _ctx: &ProxyContext) -> anyhow::Result<()> {
        // Nothing to flush in v0.2-step2. Future steps may emit a
        // session-end audit record here.
        Ok(())
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
