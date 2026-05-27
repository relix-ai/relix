//! OpenAI Chat Completions / Completions API adapter.
//!
//! Mirrors the structure of [`super::anthropic::AnthropicProtocol`]
//! but speaks OpenAI's wire format. See RFC-0002 for the full
//! specification.
//!
//! Buffered (non-streaming) responses parse as a `ChatCompletion`
//! shape and surface `tool_calls` to the rule engine. Streaming
//! responses go through [`OpenAiStreamingState`], which drives an
//! [`OpenAiStreamAssembler`] and inspects each `tool_use` block as
//! it finalises (the same lifecycle as the Anthropic streaming
//! state — see RFC-0001).

use async_trait::async_trait;
use axum::http::{HeaderMap, StatusCode};
use bytes::Bytes;
use relix_core::model::{HttpDirection, InspectionEvent};
use relix_core::Decision;
use relix_core::InspectionContext;
use relix_core::{OpenAiStreamAssembler, StreamEvent};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::proxy::lifecycle::{
    blocked_response, BodyFilterAction, HookOutcome, LlmProxy, ProxyContext, ResponseAction,
    StreamingProtocolState, StreamingState,
};
use crate::proxy::state::ProxyState;

pub struct OpenAiProtocol;

#[async_trait]
impl LlmProxy for OpenAiProtocol {
    fn name(&self) -> &'static str {
        "openai"
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
        state.audit.record(&event, &verdict);

        if let Decision::Block { reason, rule_id } = &verdict.decision {
            info!(rule = %rule_id, "blocking outbound openai request");
            return Ok(HookOutcome::ShortCircuit(openai_blocked_response(
                rule_id, reason,
            )));
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

        if let Ok(parsed) = serde_json::from_slice::<Value>(body) {
            if let Some(model) = parsed.get("model").and_then(Value::as_str) {
                event.model = Some(model.to_string());
            }
            event.tool_calls = extract_buffered_tool_calls(&parsed);
        }

        let inspection_ctx = InspectionContext {
            event: &event,
            system_prompt: None,
        };
        let verdict = relix_core::inspect::evaluate(&state.rules, &inspection_ctx);
        state.audit.record(&event, &verdict);

        if matches!(verdict.decision, Decision::Block { .. }) {
            if let Decision::Block { rule_id, .. } = &verdict.decision {
                info!(rule = %rule_id, "blocking inbound openai response");
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
        Some(Arc::new(Mutex::new(OpenAiStreamingState::default())))
    }
}

/// Per-stream state for OpenAI SSE responses.
#[derive(Default)]
pub struct OpenAiStreamingState {
    assembler: OpenAiStreamAssembler,
    /// Cached model identifier from the first `chat.completion.chunk`.
    model: Option<String>,
    /// `true` after a block decision has been issued; subsequent
    /// chunks are dropped without inspection.
    poisoned: bool,
}

impl StreamingProtocolState for OpenAiStreamingState {
    fn feed_chunk(
        &mut self,
        state: &ProxyState,
        ctx: &ProxyContext,
        chunk: &[u8],
    ) -> anyhow::Result<BodyFilterAction> {
        if self.poisoned {
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

                    state.audit.record(&event, &verdict);

                    if matches!(verdict.decision, Decision::Block { .. }) {
                        if let Decision::Block { rule_id, .. } = &verdict.decision {
                            info!(rule = %rule_id, "blocking streaming openai tool_call");
                        }
                        self.poisoned = true;
                        return Ok(BodyFilterAction::BlockMidStream(verdict));
                    }
                }
                StreamEvent::StreamEnd { .. } => {}
                StreamEvent::ParseError { reason } => {
                    info!(reason = %reason, "openai stream parse error");
                }
            }
        }

        Ok(BodyFilterAction::Forward)
    }

    fn finish(&mut self, _state: &ProxyState, _ctx: &ProxyContext) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Extract the system prompt from an OpenAI Chat Completions request.
///
/// Walks `messages[]` and concatenates `text` from every entry whose
/// role is `system` or `developer` (the o-series rename) per the
/// official spec. Both `string` and `array` content shapes are
/// accepted.
pub(crate) fn extract_system_prompt(body: &Bytes) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let messages = v.get("messages")?.as_array()?;
    let mut parts: Vec<String> = Vec::new();
    for msg in messages {
        let role = msg.get("role").and_then(Value::as_str).unwrap_or("");
        if role != "system" && role != "developer" {
            continue;
        }
        if let Some(s) = msg.get("content").and_then(Value::as_str) {
            parts.push(s.to_string());
            continue;
        }
        if let Some(arr) = msg.get("content").and_then(Value::as_array) {
            for p in arr {
                if let Some(t) = p.get("text").and_then(Value::as_str) {
                    parts.push(t.to_string());
                }
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

/// Extract `tool_calls` from a buffered (non-streaming) OpenAI
/// Chat Completion response. Returns an empty `Vec` if the shape
/// does not match — matching is best-effort and never fatal.
fn extract_buffered_tool_calls(parsed: &Value) -> Vec<relix_core::ToolCall> {
    let mut out = Vec::new();
    let Some(choices) = parsed.get("choices").and_then(Value::as_array) else {
        return out;
    };
    for choice in choices {
        let Some(msg) = choice.get("message") else {
            continue;
        };
        // Modern tool_calls
        if let Some(tcs) = msg.get("tool_calls").and_then(Value::as_array) {
            for tc in tcs {
                let id = tc.get("id").and_then(Value::as_str).map(str::to_string);
                let func = match tc.get("function") {
                    Some(f) => f,
                    None => continue,
                };
                let name = func
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let args_str = func.get("arguments").and_then(Value::as_str).unwrap_or("");
                let input: Value = serde_json::from_str(args_str).unwrap_or(Value::Null);
                out.push(relix_core::ToolCall { name, input, id });
            }
        }
        // Legacy function_call
        if let Some(fc) = msg.get("function_call") {
            let name = fc
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let args_str = fc.get("arguments").and_then(Value::as_str).unwrap_or("");
            let input: Value = serde_json::from_str(args_str).unwrap_or(Value::Null);
            out.push(relix_core::ToolCall {
                name,
                input,
                id: None,
            });
        }
    }
    out
}

/// OpenAI-shaped block notice. Distinct from the Anthropic shape
/// because clients written against either API expect errors in the
/// shape they know.
fn openai_blocked_response(rule_id: &str, reason: &str) -> axum::response::Response {
    let body = format!(
        r#"{{"error":{{"type":"relix_blocked","code":"relix_blocked","message":"Relix blocked: {}","rule_id":"{}"}}}}"#,
        json_escape(reason),
        json_escape(rule_id)
    );
    let mut resp = blocked_response(rule_id, reason);
    *resp.body_mut() = axum::body::Body::from(body);
    resp.headers_mut().insert(
        "content-type",
        axum::http::HeaderValue::from_static("application/json"),
    );
    *resp.status_mut() = StatusCode::FORBIDDEN;
    resp
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_string_system_prompt() {
        let body = Bytes::from(
            r#"{"messages":[{"role":"system","content":"You are helpful."},{"role":"user","content":"hi"}]}"#,
        );
        assert_eq!(
            extract_system_prompt(&body),
            Some("You are helpful.".to_string())
        );
    }

    #[test]
    fn extracts_developer_role_same_as_system() {
        let body = Bytes::from(
            r#"{"messages":[{"role":"developer","content":"obey"},{"role":"user","content":"hi"}]}"#,
        );
        assert_eq!(extract_system_prompt(&body), Some("obey".to_string()));
    }

    #[test]
    fn concatenates_multiple_system_messages() {
        let body = Bytes::from(
            r#"{"messages":[{"role":"system","content":"a"},{"role":"system","content":"b"}]}"#,
        );
        assert_eq!(extract_system_prompt(&body), Some("a\nb".to_string()));
    }

    #[test]
    fn extracts_array_content_blocks() {
        let body = Bytes::from(
            r#"{"messages":[{"role":"system","content":[{"type":"text","text":"l1"},{"type":"text","text":"l2"}]}]}"#,
        );
        assert_eq!(extract_system_prompt(&body), Some("l1\nl2".to_string()));
    }

    #[test]
    fn returns_none_when_no_system_message() {
        let body = Bytes::from(r#"{"messages":[{"role":"user","content":"hi"}]}"#);
        assert_eq!(extract_system_prompt(&body), None);
    }

    #[test]
    fn extracts_tool_calls_from_buffered_response() {
        let parsed: Value = serde_json::from_str(
            r#"{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]}}]}"#,
        )
        .unwrap();
        let tcs = extract_buffered_tool_calls(&parsed);
        assert_eq!(tcs.len(), 1);
        assert_eq!(tcs[0].name, "Bash");
        assert_eq!(
            tcs[0].input.get("command").and_then(Value::as_str),
            Some("ls")
        );
    }

    #[test]
    fn extracts_legacy_function_call_from_buffered_response() {
        let parsed: Value = serde_json::from_str(
            r#"{"choices":[{"message":{"role":"assistant","function_call":{"name":"Bash","arguments":"{\"command\":\"id\"}"}}}]}"#,
        )
        .unwrap();
        let tcs = extract_buffered_tool_calls(&parsed);
        assert_eq!(tcs.len(), 1);
        assert_eq!(tcs[0].name, "Bash");
    }
}
