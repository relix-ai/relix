//! OpenAI Chat Completions streaming assembler.
//!
//! Pairs with [`crate::streaming::AnthropicStreamAssembler`]. Both
//! consume bytes via the shared [`crate::streaming::SseFrameDecoder`]
//! and emit the same [`crate::streaming::StreamEvent`] vocabulary, so
//! the rule engine sees a unified stream regardless of upstream
//! protocol.
//!
//! Wire format reference: RFC-0002 §"Wire format reference".
//!
//! Key differences from Anthropic the assembler must handle:
//!
//! - SSE frames are `data:`-only (no `event:` line). Comment lines
//!   (starting with `:`) are discarded by the decoder.
//! - Tool calls are keyed by `(choice.index, tool_call.index)`,
//!   not by a single block index.
//! - Argument fragments live in
//!   `delta.tool_calls[].function.arguments` and concatenate as raw
//!   bytes; parsing as JSON is only valid after `finish_reason`.
//! - The terminating sentinel is `data: [DONE]`. Some implementations
//!   send `[DONE]` with trailing whitespace or fragments; we accept
//!   `data` whose trimmed body starts with `[DONE]` (matching the
//!   official Python SDK's tolerance).
//! - Legacy `function_call` is synthesised into a single
//!   `tool_calls[]` entry at `(choice.index, 0)` so the rule engine
//!   has one shape to match against.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::streaming::{
    sanitize_label, SseFrameDecoder, StreamEvent, MAX_LABEL_BYTES, MAX_TOOL_INPUT_BYTES,
};

/// Per-tool-call accumulator state. `id`, `name`, and `type` are
/// late-binding: most providers send them only on the first chunk of
/// a given tool call, but compatibility relays may delay or repeat
/// them. We accept whichever non-empty value arrives first and treat
/// later non-empty values as overwrites — never erase a populated
/// field with an empty one, since some providers blank fields on
/// follow-up chunks.
#[derive(Debug, Default)]
struct ToolCallBuffer {
    id: Option<String>,
    name: Option<String>,
    args_buf: String,
    /// `true` after the matching choice's `finish_reason` triggered
    /// finalisation. Subsequent fragments are flagged as a parse
    /// error rather than silently appended.
    finalised: bool,
    /// `true` after the args buffer hit [`MAX_TOOL_INPUT_BYTES`] and
    /// was force-finalised early.
    overflowed: bool,
}

/// Per-choice state. We track `finished` so chunks arriving after a
/// `finish_reason` for the same choice are surfaced as a protocol
/// violation per RFC-0002.
#[derive(Debug, Default)]
struct ChoiceState {
    finished: bool,
    /// Tool call accumulators keyed by `tool_call.index`. `BTreeMap`
    /// (not `HashMap`) so finalisation order is deterministic for
    /// audit logs.
    tool_calls: BTreeMap<u32, ToolCallBuffer>,
}

/// Streaming-aware OpenAI Chat Completions response assembler.
///
/// Push raw upstream bytes via [`Self::push_bytes`]; drain semantic
/// events via [`Self::drain_events`].
#[derive(Debug, Default)]
pub struct OpenAiStreamAssembler {
    decoder: SseFrameDecoder,
    /// Choices keyed by `choice.index`. `BTreeMap` for the same
    /// determinism reason as inside `ChoiceState`.
    choices: BTreeMap<u32, ChoiceState>,
    /// Model identifier observed in the first chunk that carries one.
    /// Cached so audit records can include it.
    model: Option<String>,
    /// Set after `data: [DONE]` is seen.
    done: bool,
    /// Set after `done` triggers force-finalisation, so it runs once.
    drained_unfinished: bool,
    pending_events: Vec<StreamEvent>,
}

impl OpenAiStreamAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_bytes(&mut self, chunk: &[u8]) {
        self.decoder.push(chunk);
        while let Some(frame) = self.decoder.next_frame() {
            self.handle_frame(frame);
        }
    }

    /// Take any events the assembler has produced so far.
    pub fn drain_events(&mut self) -> Vec<StreamEvent> {
        std::mem::take(&mut self.pending_events)
    }

    pub fn is_finished(&self) -> bool {
        self.done
    }

    fn handle_frame(&mut self, frame: crate::streaming::SseFrame) {
        // Synthetic frame inserted by the decoder when its buffer
        // exceeded the size cap. Surface as a parse error so the
        // rule engine can react aggressively.
        if frame.event_name == "__relix_oversize__" {
            self.pending_events.push(StreamEvent::ParseError {
                reason: "sse frame exceeded size limit".into(),
            });
            return;
        }
        if frame.data.is_empty() {
            return;
        }

        // [DONE] sentinel handling. We accept `[DONE]`, `[DONE]\n`,
        // `[DONE] ` etc. by checking the trimmed prefix.
        if is_done_sentinel(&frame.data) {
            self.finalise_unfinished_at_done();
            self.done = true;
            self.pending_events.push(StreamEvent::StreamEnd {
                stop_reason: Some("done".into()),
            });
            return;
        }

        let raw: Value = match serde_json::from_str(&frame.data) {
            Ok(v) => v,
            Err(err) => {
                self.pending_events.push(StreamEvent::ParseError {
                    reason: format!("invalid sse json: {err}"),
                });
                return;
            }
        };

        // Cache the model identifier on the first chunk that carries
        // one. Some providers omit it from later chunks.
        if self.model.is_none() {
            if let Some(m) = raw.get("model").and_then(Value::as_str) {
                let m = sanitize_label(m);
                if !m.is_empty() {
                    self.pending_events
                        .push(StreamEvent::StreamStart { model: m.clone() });
                    self.model = Some(m);
                }
            }
        }

        let Some(choices) = raw.get("choices").and_then(Value::as_array) else {
            return;
        };

        for choice in choices {
            self.handle_choice(choice);
        }
    }

    fn handle_choice(&mut self, choice: &Value) {
        let Some(ci) = choice.get("index").and_then(Value::as_u64) else {
            self.pending_events.push(StreamEvent::ParseError {
                reason: "choice without index".into(),
            });
            return;
        };
        let ci = ci as u32;

        // RFC-0002: a chunk arriving after a `finish_reason` for the
        // same choice is a protocol violation. Surface it but keep
        // forwarding bytes downstream — the driver layer decides
        // whether to block.
        let cs = self.choices.entry(ci).or_default();
        if cs.finished {
            self.pending_events.push(StreamEvent::ParseError {
                reason: format!("choice {ci} delta after finish_reason"),
            });
        }

        if let Some(delta) = choice.get("delta") {
            // Modern tool_calls
            if let Some(tcs) = delta.get("tool_calls").and_then(Value::as_array) {
                for tc in tcs {
                    Self::merge_tool_call(cs, tc, &mut self.pending_events);
                }
            }
            // Legacy function_call → synthesise tool_call at index 0.
            if let Some(fc) = delta.get("function_call") {
                let synthetic = serde_json::json!({
                    "index": 0,
                    "function": fc,
                });
                Self::merge_tool_call(cs, &synthetic, &mut self.pending_events);
            }
        }

        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            if matches!(reason, "tool_calls" | "function_call") {
                Self::finalise_choice_tool_calls(ci, cs, &mut self.pending_events);
            }
            cs.finished = true;
        }
    }

    fn merge_tool_call(cs: &mut ChoiceState, tc: &Value, events: &mut Vec<StreamEvent>) {
        let Some(idx) = tc.get("index").and_then(Value::as_u64) else {
            events.push(StreamEvent::ParseError {
                reason: "tool_call without index".into(),
            });
            return;
        };
        let idx = idx as u32;
        let buf = cs.tool_calls.entry(idx).or_default();

        if buf.finalised {
            events.push(StreamEvent::ParseError {
                reason: format!("tool_call {idx} fragment after finalisation"),
            });
            return;
        }

        if buf.id.as_deref().unwrap_or("").is_empty() {
            if let Some(id) = tc.get("id").and_then(Value::as_str) {
                let id = sanitize_label(id);
                if !id.is_empty() {
                    buf.id = Some(id);
                }
            }
        }

        let func = tc.get("function");
        if let Some(func) = func {
            if buf.name.as_deref().unwrap_or("").is_empty() {
                if let Some(name) = func.get("name").and_then(Value::as_str) {
                    let name = sanitize_label(name);
                    if !name.is_empty() {
                        buf.name = Some(name);
                    }
                }
            }
            if let Some(args_chunk) = func.get("arguments").and_then(Value::as_str) {
                if buf.args_buf.len().saturating_add(args_chunk.len()) > MAX_TOOL_INPUT_BYTES {
                    if !buf.overflowed {
                        buf.overflowed = true;
                        buf.finalised = true;
                        events.push(StreamEvent::ParseError {
                            reason: format!(
                                "tool_call arguments exceeded {MAX_TOOL_INPUT_BYTES}-byte cap"
                            ),
                        });
                        events.push(StreamEvent::ToolUseFinalised {
                            index: idx,
                            id: buf.id.clone().unwrap_or_default(),
                            name: buf.name.clone().unwrap_or_default(),
                            input: Value::Null,
                        });
                    }
                    return;
                }
                buf.args_buf.push_str(args_chunk);
            }
        }
    }

    fn finalise_choice_tool_calls(_ci: u32, cs: &mut ChoiceState, events: &mut Vec<StreamEvent>) {
        for (idx, buf) in cs.tool_calls.iter_mut() {
            if buf.finalised {
                continue;
            }
            buf.finalised = true;
            let id = buf.id.clone().unwrap_or_default();
            let name = buf.name.clone().unwrap_or_default();
            let input = parse_or_null(&buf.args_buf);
            events.push(StreamEvent::ToolUseFinalised {
                index: *idx,
                id,
                name,
                input,
            });
        }
    }

    fn finalise_unfinished_at_done(&mut self) {
        if self.drained_unfinished {
            return;
        }
        self.drained_unfinished = true;
        for (_ci, cs) in self.choices.iter_mut() {
            if cs.finished {
                continue;
            }
            // No `finish_reason` was seen for this choice before
            // `[DONE]`. Surface a parse error and force-finalise any
            // tool calls so an attacker cannot park malicious
            // payloads in an open buffer.
            for (idx, buf) in cs.tool_calls.iter_mut() {
                if buf.finalised {
                    continue;
                }
                buf.finalised = true;
                self.pending_events.push(StreamEvent::ParseError {
                    reason: format!(
                        "tool_call {idx} closed without finish_reason; force-finalising at [DONE]"
                    ),
                });
                let id = buf.id.clone().unwrap_or_default();
                let name = buf.name.clone().unwrap_or_default();
                let input = parse_or_null(&buf.args_buf);
                self.pending_events.push(StreamEvent::ToolUseFinalised {
                    index: *idx,
                    id,
                    name,
                    input,
                });
            }
            cs.finished = true;
        }
    }
}

/// Best-effort JSON parse of an accumulated `arguments` buffer.
/// Returns `Value::Null` on parse failure so the rule engine can
/// still inspect the (now-empty) tool call rather than silently
/// passing it.
fn parse_or_null(buf: &str) -> Value {
    if buf.trim().is_empty() {
        return Value::Null;
    }
    serde_json::from_str(buf).unwrap_or(Value::Null)
}

fn is_done_sentinel(data: &str) -> bool {
    let trimmed = data.trim();
    trimmed.starts_with("[DONE]")
}

/// Dead-code-allow stub so callers can reference the label cap
/// constant from this module without re-importing.
#[allow(dead_code)]
const _: usize = MAX_LABEL_BYTES;

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(data: &str) -> Vec<u8> {
        format!("data: {data}\n\n").into_bytes()
    }

    fn done() -> Vec<u8> {
        b"data: [DONE]\n\n".to_vec()
    }

    fn assemble(chunks: &[&[u8]]) -> Vec<StreamEvent> {
        let mut a = OpenAiStreamAssembler::new();
        for c in chunks {
            a.push_bytes(c);
        }
        a.drain_events()
    }

    #[test]
    fn assembles_tool_call_split_across_chunks() {
        let f1 = frame(
            r#"{"id":"x","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"Bash","arguments":"{\"co"}}]},"finish_reason":null}]}"#,
        );
        let f2 = frame(
            r#"{"id":"x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"mmand\":\"ls\"}"}}]},"finish_reason":null}]}"#,
        );
        let f3 = frame(
            r#"{"id":"x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        );
        let events = assemble(&[&f1, &f2, &f3, &done()]);

        let finalised = events.iter().find_map(|e| match e {
            StreamEvent::ToolUseFinalised {
                index,
                id,
                name,
                input,
            } => Some((*index, id.clone(), name.clone(), input.clone())),
            _ => None,
        });
        let (idx, id, name, input) = finalised.expect("must finalise tool_call");
        assert_eq!(idx, 0);
        assert_eq!(id, "call_1");
        assert_eq!(name, "Bash");
        assert_eq!(input.get("command").and_then(Value::as_str), Some("ls"));
    }

    #[test]
    fn emits_stream_start_with_model_once() {
        let f1 = frame(
            r#"{"object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}"#,
        );
        let f2 = frame(
            r#"{"object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":"stop"}]}"#,
        );
        let events = assemble(&[&f1, &f2, &done()]);
        let starts = events
            .iter()
            .filter(|e| matches!(e, StreamEvent::StreamStart { .. }))
            .count();
        assert_eq!(starts, 1, "model should only emit once");
    }

    #[test]
    fn done_sentinel_emits_stream_end_and_tolerates_trailing_whitespace() {
        // Real providers add space or extra newlines after [DONE].
        let f1 = frame(
            r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        );
        let mut a = OpenAiStreamAssembler::new();
        a.push_bytes(&f1);
        a.push_bytes(b"data: [DONE]   \n\n");
        let events = a.drain_events();
        assert!(events
            .iter()
            .any(|e| matches!(e, StreamEvent::StreamEnd { .. })));
        assert!(a.is_finished());
    }

    #[test]
    fn parallel_tool_calls_are_distinguished_by_index() {
        let f1 = frame(
            r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]},"finish_reason":null}]}"#,
        );
        let f2 = frame(
            r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"b","function":{"name":"Read","arguments":"{\"path\":\"/tmp\"}"}}]},"finish_reason":null}]}"#,
        );
        let f3 = frame(
            r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        );
        let events = assemble(&[&f1, &f2, &f3, &done()]);
        let finalised: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                StreamEvent::ToolUseFinalised { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(finalised.len(), 2);
        assert!(finalised.contains(&"Bash".to_string()));
        assert!(finalised.contains(&"Read".to_string()));
    }

    #[test]
    fn legacy_function_call_synthesises_tool_call_at_index_zero() {
        let f1 = frame(
            r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"function_call":{"name":"Bash","arguments":"{\"command\":\"id\"}"}},"finish_reason":null}]}"#,
        );
        let f2 = frame(
            r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"function_call"}]}"#,
        );
        let events = assemble(&[&f1, &f2, &done()]);
        let f = events.iter().find_map(|e| match e {
            StreamEvent::ToolUseFinalised { index, name, .. } => Some((*index, name.clone())),
            _ => None,
        });
        assert_eq!(f, Some((0, "Bash".to_string())));
    }

    #[test]
    fn rt_finalisation_only_at_finish_reason() {
        // Red-team: even if `tool_calls` deltas form valid JSON
        // mid-stream, we must NOT finalise until finish_reason fires.
        let full = frame(
            r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"x","function":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]},"finish_reason":null}]}"#,
        );
        let events = assemble(&[&full]);
        let finalised = events
            .iter()
            .find(|e| matches!(e, StreamEvent::ToolUseFinalised { .. }));
        assert!(
            finalised.is_none(),
            "must not finalise before finish_reason: {events:?}"
        );
    }

    #[test]
    fn rt_chunk_after_finish_reason_emits_parse_error() {
        // Red-team: a poisoned upstream sneaks bytes after the
        // finish_reason chunk. We must surface a ParseError.
        let f1 = frame(
            r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        );
        let f2 = frame(
            r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"sneaky"},"finish_reason":null}]}"#,
        );
        let events = assemble(&[&f1, &f2, &done()]);
        assert!(events.iter().any(|e| matches!(
            e,
            StreamEvent::ParseError { reason } if reason.contains("delta after finish_reason")
        )));
    }

    #[test]
    fn rt_arguments_size_cap_truncates() {
        // Red-team: an upstream sends a huge `arguments` fragment.
        // We must finalise the tool call early with Null and emit a
        // ParseError, preventing memory exhaustion.
        let big = "x".repeat(MAX_TOOL_INPUT_BYTES + 1024);
        let payload = format!(
            r#"{{"object":"chat.completion.chunk","choices":[{{"index":0,"delta":{{"tool_calls":[{{"index":0,"id":"x","function":{{"name":"Bash","arguments":"{big}"}}}}]}},"finish_reason":null}}]}}"#
        );
        let f1 = frame(&payload);
        let events = assemble(&[&f1]);
        assert!(events.iter().any(|e| matches!(
            e,
            StreamEvent::ParseError { reason } if reason.contains("arguments exceeded")
        )));
        assert!(events.iter().any(|e| matches!(
            e,
            StreamEvent::ToolUseFinalised { input, .. } if input == &Value::Null
        )));
    }

    #[test]
    fn rt_done_without_finish_reason_force_finalises() {
        // Red-team: upstream sends tool_call deltas, then [DONE]
        // without a finish_reason chunk. The assembler must still
        // surface a ToolUseFinalised so the rule engine sees the
        // payload, plus a ParseError for the protocol violation.
        let f1 = frame(
            r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"x","function":{"name":"Bash","arguments":"{\"command\":\"id\"}"}}]},"finish_reason":null}]}"#,
        );
        let events = assemble(&[&f1, &done()]);
        assert!(events.iter().any(|e| matches!(
            e,
            StreamEvent::ParseError { reason } if reason.contains("closed without finish_reason")
        )));
        assert!(events.iter().any(|e| matches!(
            e,
            StreamEvent::ToolUseFinalised { name, .. } if name == "Bash"
        )));
    }

    #[test]
    fn comment_lines_are_ignored() {
        // OpenRouter and similar relays inject `: keepalive` lines.
        // Decoder discards comment lines; assembler should never see
        // them.
        let mut bytes = b": keepalive\n\n".to_vec();
        bytes.extend(frame(r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":"stop"}]}"#));
        bytes.extend(done());
        let mut a = OpenAiStreamAssembler::new();
        a.push_bytes(&bytes);
        let events = a.drain_events();
        // No ParseError from the keepalive line.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, StreamEvent::ParseError { .. })),
            "comment lines must not surface as parse errors: {events:?}"
        );
    }
}
