//! SSE frame splitting and Anthropic streaming response assembly.
//!
//! This module is intentionally IO-free. It transforms incoming
//! byte chunks (as they arrive from the upstream HTTP client) into
//! semantic events the rule engine can evaluate.
//!
//! Two layers live here:
//!
//! 1. [`SseFrameDecoder`] — splits a byte stream into `(event_name,
//!    data_bytes)` pairs. Tolerant of chunk boundaries that fall
//!    mid-frame; buffers internally.
//!
//! 2. [`AnthropicStreamAssembler`] — consumes those pairs, runs the
//!    per-block accumulator described in RFC-0001 §"Per-block
//!    accumulator", and emits high-level [`StreamEvent`]s.
//!
//! Critical invariant from the Anthropic specification: a tool_use
//! block's `input` is only valid at `content_block_stop`. Inspection
//! must therefore run on the [`StreamEvent::ToolUseFinalised`] event,
//! never on partial deltas.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::ToolCall;

/// High-level event produced by [`AnthropicStreamAssembler`].
///
/// Lower-level SSE frames (`message_start`, `content_block_delta`,
/// etc.) are absorbed by the assembler; only events that are useful
/// to the rule engine surface here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StreamEvent {
    /// First event of a stream. Carries the model identifier so audit
    /// logs can record which model produced the response.
    StreamStart { model: String },

    /// A `tool_use` content block finished assembling. `input` is
    /// guaranteed parseable JSON (or `Value::Null` if the upstream
    /// emitted a malformed `partial_json` sequence — see
    /// [`StreamEvent::ParseError`]).
    ToolUseFinalised {
        index: u32,
        id: String,
        name: String,
        input: Value,
    },

    /// Stream finished cleanly (`message_stop`).
    StreamEnd { stop_reason: Option<String> },

    /// Best-effort recovery: the upstream sent something the
    /// assembler could not parse. Forwarded as an event so the rule
    /// engine can react (e.g. block aggressively when an inspection
    /// gap is detected) and the audit log can record the breach.
    ///
    /// The proxy must continue to forward bytes; this is informational.
    ParseError { reason: String },
}

impl StreamEvent {
    /// Convenience: convert a `ToolUseFinalised` into a `ToolCall`
    /// suitable for `InspectionEvent::tool_calls`.
    pub fn as_tool_call(&self) -> Option<ToolCall> {
        match self {
            StreamEvent::ToolUseFinalised {
                id, name, input, ..
            } => Some(ToolCall {
                name: name.clone(),
                input: input.clone(),
                id: Some(id.clone()),
            }),
            _ => None,
        }
    }
}

/// Incremental SSE frame decoder.
///
/// Feed bytes via [`Self::push`]. Drain ready frames via
/// [`Self::next_frame`].
///
/// SSE format we accept (per the WHATWG spec, restricted to the
/// shape Anthropic emits):
///
/// ```text
/// event: <name>\n
/// data: <json>\n
/// \n
/// ```
///
/// `data:` lines may repeat across multiple lines for one event;
/// multiple lines are concatenated with `\n` per the spec. We do
/// not support `id:` or `retry:` fields (they are not used by
/// Anthropic streams).
///
/// Non-Anthropic providers may send frames without an `event:` line
/// (OpenAI does this, using only `data:`). Such frames yield
/// `event_name = ""` so callers can distinguish.
#[derive(Debug, Default)]
pub struct SseFrameDecoder {
    buf: Vec<u8>,
}

impl SseFrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Pull one fully-received frame from the buffer if one is
    /// available. Returns `None` when the buffer does not yet contain
    /// a complete frame (a blank line separator has not arrived).
    pub fn next_frame(&mut self) -> Option<SseFrame> {
        // Frames are separated by a blank line: \n\n or \r\n\r\n.
        // Search for either pattern; pick the earliest match.
        let mut sep_at: Option<(usize, usize)> = None; // (position, length)
        for i in 0..self.buf.len().saturating_sub(1) {
            if self.buf[i] == b'\n' && self.buf.get(i + 1) == Some(&b'\n') {
                sep_at = Some((i, 2));
                break;
            }
            if i + 3 < self.buf.len() && &self.buf[i..i + 4] == b"\r\n\r\n" {
                sep_at = Some((i, 4));
                break;
            }
        }
        let (end, sep_len) = sep_at?;

        let raw = self.buf.drain(..end + sep_len).collect::<Vec<u8>>();
        let frame_bytes = &raw[..end];
        let frame_str = std::str::from_utf8(frame_bytes).ok()?;

        let mut event_name = String::new();
        let mut data_lines: Vec<&str> = Vec::new();
        for line in frame_str.split('\n') {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with(':') {
                continue;
            }
            if let Some(name) = line.strip_prefix("event:") {
                event_name = name.trim().to_string();
            } else if let Some(value) = line.strip_prefix("data:") {
                let v = value.strip_prefix(' ').unwrap_or(value);
                data_lines.push(v);
            }
            // Other field names (id, retry) ignored.
        }

        let data = data_lines.join("\n");
        Some(SseFrame { event_name, data })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SseFrame {
    pub event_name: String,
    pub data: String,
}

/// Per-block state inside the assembler.
#[derive(Debug)]
enum BlockState {
    Text,
    ToolUse {
        id: String,
        name: String,
        json_buf: String,
    },
    Other,
}

/// Streaming-aware Anthropic Messages API response assembler.
///
/// Drives the state machine described in RFC-0001 §"Per-block
/// accumulator". Push raw upstream bytes via [`Self::push_bytes`];
/// drain semantic events via [`Self::drain_events`].
#[derive(Debug, Default)]
pub struct AnthropicStreamAssembler {
    decoder: SseFrameDecoder,
    blocks: HashMap<u32, BlockState>,
    pending_events: Vec<StreamEvent>,
    finished: bool,
}

impl AnthropicStreamAssembler {
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
        self.finished
    }

    fn handle_frame(&mut self, frame: SseFrame) {
        if frame.data.is_empty() {
            return;
        }
        // Parse the JSON payload. We type-erase via `Value` first so
        // unknown event types do not abort the stream.
        let raw: Value = match serde_json::from_str(&frame.data) {
            Ok(v) => v,
            Err(err) => {
                self.pending_events.push(StreamEvent::ParseError {
                    reason: format!("invalid sse json: {err}"),
                });
                return;
            }
        };

        let typ = raw.get("type").and_then(Value::as_str).unwrap_or("");
        match typ {
            "message_start" => {
                if let Some(model) = raw.pointer("/message/model").and_then(Value::as_str) {
                    self.pending_events.push(StreamEvent::StreamStart {
                        model: model.to_string(),
                    });
                }
            }
            "content_block_start" => {
                let index = raw.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                let cb = match raw.get("content_block") {
                    Some(v) => v,
                    None => return,
                };
                let block_type = cb.get("type").and_then(Value::as_str).unwrap_or("");
                match block_type {
                    "text" => {
                        self.blocks.insert(index, BlockState::Text);
                    }
                    "tool_use" | "server_tool_use" => {
                        let id = cb
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        let name = cb
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        self.blocks.insert(
                            index,
                            BlockState::ToolUse {
                                id,
                                name,
                                json_buf: String::new(),
                            },
                        );
                    }
                    _ => {
                        self.blocks.insert(index, BlockState::Other);
                    }
                }
            }
            "content_block_delta" => {
                let index = raw.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                let delta = match raw.get("delta") {
                    Some(v) => v,
                    None => return,
                };
                let delta_type = delta.get("type").and_then(Value::as_str).unwrap_or("");
                if delta_type != "input_json_delta" {
                    return;
                }
                let partial = match delta.get("partial_json").and_then(Value::as_str) {
                    Some(s) => s,
                    None => return,
                };
                if let Some(BlockState::ToolUse { json_buf, .. }) = self.blocks.get_mut(&index) {
                    json_buf.push_str(partial);
                }
            }
            "content_block_stop" => {
                let index = raw.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                if let Some(state) = self.blocks.remove(&index) {
                    if let BlockState::ToolUse { id, name, json_buf } = state {
                        let input = if json_buf.trim().is_empty() {
                            // Anthropic always sends content_block_start with
                            // input: {} so an empty buf is legal — treat as
                            // empty object, not error.
                            Value::Object(Default::default())
                        } else {
                            match serde_json::from_str::<Value>(&json_buf) {
                                Ok(v) => v,
                                Err(err) => {
                                    self.pending_events.push(StreamEvent::ParseError {
                                        reason: format!(
                                            "tool_use input json invalid for index {index}: {err}"
                                        ),
                                    });
                                    Value::Null
                                }
                            }
                        };
                        self.pending_events.push(StreamEvent::ToolUseFinalised {
                            index,
                            id,
                            name,
                            input,
                        });
                    }
                }
            }
            "message_delta" => {
                // Track stop_reason so StreamEnd carries it.
                if let Some(stop_reason) = raw.pointer("/delta/stop_reason").and_then(Value::as_str)
                {
                    self.pending_events.push(StreamEvent::StreamEnd {
                        stop_reason: Some(stop_reason.to_string()),
                    });
                }
            }
            "message_stop" => {
                self.finished = true;
                // If we never saw a message_delta with stop_reason,
                // emit an end event with None.
                if !self
                    .pending_events
                    .iter()
                    .any(|e| matches!(e, StreamEvent::StreamEnd { .. }))
                {
                    self.pending_events
                        .push(StreamEvent::StreamEnd { stop_reason: None });
                }
            }
            "ping" | "" => {
                // Keep-alive or unknown event with no type discriminator.
            }
            "error" => {
                // Anthropic emits errors mid-stream as SSE events with
                // a 200 status. Surface the error as a ParseError-style
                // event so audit logs capture it; do not crash.
                let msg = raw
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("upstream stream error");
                self.pending_events.push(StreamEvent::ParseError {
                    reason: format!("upstream error event: {msg}"),
                });
            }
            _ => {
                // Forwards-compatibility: unknown event types are
                // ignored, not failed. The Anthropic versioning
                // policy reserves the right to add new events.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(event: &str, data: &str) -> Vec<u8> {
        format!("event: {event}\ndata: {data}\n\n").into_bytes()
    }

    #[test]
    fn decodes_single_frame() {
        let mut d = SseFrameDecoder::new();
        d.push(b"event: ping\ndata: {\"type\":\"ping\"}\n\n");
        let f = d.next_frame().unwrap();
        assert_eq!(f.event_name, "ping");
        assert_eq!(f.data, r#"{"type":"ping"}"#);
        assert!(d.next_frame().is_none());
    }

    #[test]
    fn decodes_split_chunks() {
        let mut d = SseFrameDecoder::new();
        d.push(b"event: pi");
        d.push(b"ng\ndata: {}\n");
        assert!(d.next_frame().is_none()); // separator not yet here
        d.push(b"\n");
        let f = d.next_frame().unwrap();
        assert_eq!(f.event_name, "ping");
        assert_eq!(f.data, "{}");
    }

    #[test]
    fn decodes_multiple_frames_in_one_chunk() {
        let mut d = SseFrameDecoder::new();
        let mut buf = Vec::new();
        buf.extend_from_slice(&frame("a", "{\"v\":1}"));
        buf.extend_from_slice(&frame("b", "{\"v\":2}"));
        d.push(&buf);
        let f1 = d.next_frame().unwrap();
        let f2 = d.next_frame().unwrap();
        assert_eq!(f1.event_name, "a");
        assert_eq!(f2.event_name, "b");
    }

    #[test]
    fn ignores_comment_lines() {
        let mut d = SseFrameDecoder::new();
        d.push(b": this is a comment\nevent: x\ndata: {}\n\n");
        let f = d.next_frame().unwrap();
        assert_eq!(f.event_name, "x");
    }

    #[test]
    fn handles_crlf_line_endings() {
        let mut d = SseFrameDecoder::new();
        d.push(b"event: x\r\ndata: {}\r\n\r\n");
        let f = d.next_frame().unwrap();
        assert_eq!(f.event_name, "x");
        assert_eq!(f.data, "{}");
    }

    #[test]
    fn assembler_emits_stream_start() {
        let mut a = AnthropicStreamAssembler::new();
        a.push_bytes(&frame(
            "message_start",
            r#"{"type":"message_start","message":{"id":"m1","model":"claude-opus-4-7","role":"assistant"}}"#,
        ));
        let events = a.drain_events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            StreamEvent::StreamStart { model } => assert_eq!(model, "claude-opus-4-7"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn assembler_assembles_tool_use_from_deltas() {
        let mut a = AnthropicStreamAssembler::new();
        a.push_bytes(&frame(
            "content_block_start",
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_1","name":"Bash","input":{}}}"#,
        ));
        a.push_bytes(&frame(
            "content_block_delta",
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"comm"}}"#,
        ));
        a.push_bytes(&frame(
            "content_block_delta",
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"and\":\"ls -la\"}"}}"#,
        ));
        // Before stop, no event should be emitted for this block.
        assert!(a.drain_events().is_empty());

        a.push_bytes(&frame(
            "content_block_stop",
            r#"{"type":"content_block_stop","index":0}"#,
        ));
        let events = a.drain_events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            StreamEvent::ToolUseFinalised {
                name,
                input,
                id,
                index,
            } => {
                assert_eq!(name, "Bash");
                assert_eq!(id, "tu_1");
                assert_eq!(*index, 0);
                assert_eq!(input.get("command").and_then(Value::as_str), Some("ls -la"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn assembler_recovers_from_invalid_partial_json() {
        let mut a = AnthropicStreamAssembler::new();
        a.push_bytes(&frame(
            "content_block_start",
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_1","name":"X","input":{}}}"#,
        ));
        a.push_bytes(&frame(
            "content_block_delta",
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"not json"}}"#,
        ));
        a.push_bytes(&frame(
            "content_block_stop",
            r#"{"type":"content_block_stop","index":0}"#,
        ));
        let events = a.drain_events();
        // Expect a ParseError followed by a ToolUseFinalised with null input.
        assert!(events
            .iter()
            .any(|e| matches!(e, StreamEvent::ParseError { .. })));
        let tuf = events.iter().find_map(|e| match e {
            StreamEvent::ToolUseFinalised { input, .. } => Some(input.clone()),
            _ => None,
        });
        assert_eq!(tuf, Some(Value::Null));
    }

    #[test]
    fn assembler_handles_message_stop() {
        let mut a = AnthropicStreamAssembler::new();
        a.push_bytes(&frame("message_stop", r#"{"type":"message_stop"}"#));
        assert!(a.is_finished());
        let events = a.drain_events();
        assert!(events
            .iter()
            .any(|e| matches!(e, StreamEvent::StreamEnd { .. })));
    }

    #[test]
    fn assembler_ignores_unknown_event_types() {
        let mut a = AnthropicStreamAssembler::new();
        a.push_bytes(&frame(
            "future_event",
            r#"{"type":"future_event","payload":42}"#,
        ));
        // No event emitted, no panic.
        assert!(a.drain_events().is_empty());
    }

    #[test]
    fn assembler_surfaces_upstream_errors() {
        let mut a = AnthropicStreamAssembler::new();
        a.push_bytes(&frame(
            "error",
            r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
        ));
        let events = a.drain_events();
        let has_err = events.iter().any(
            |e| matches!(e, StreamEvent::ParseError { reason } if reason.contains("Overloaded")),
        );
        assert!(has_err);
    }

    #[test]
    fn assembler_handles_non_tool_use_blocks() {
        // text block deltas should be silently absorbed
        let mut a = AnthropicStreamAssembler::new();
        a.push_bytes(&frame(
            "content_block_start",
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
        ));
        a.push_bytes(&frame(
            "content_block_delta",
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}"#,
        ));
        a.push_bytes(&frame(
            "content_block_stop",
            r#"{"type":"content_block_stop","index":0}"#,
        ));
        // No ToolUseFinalised should appear.
        assert!(a
            .drain_events()
            .iter()
            .all(|e| !matches!(e, StreamEvent::ToolUseFinalised { .. })));
    }
}
