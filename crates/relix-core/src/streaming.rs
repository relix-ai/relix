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
#[derive(Debug)]
pub struct SseFrameDecoder {
    buf: Vec<u8>,
    /// Hard cap on internal buffer growth. A malicious upstream that
    /// sends bytes without a frame separator could otherwise drive
    /// us to OOM. When exceeded, the buffer is reset and a
    /// [`SseDecoderError::FrameTooLarge`] is reported through
    /// [`Self::next_frame`] returning a synthetic error frame.
    max_frame_bytes: usize,
}

impl Default for SseFrameDecoder {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }
}

/// Default ceiling on a single SSE frame's size. Large enough for
/// any legitimate Anthropic / OpenAI / Gemini frame; small enough
/// to prevent OOM from a malicious upstream.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024; // 1 MiB

impl SseFrameDecoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    /// Override the per-frame size cap. Mostly useful in tests.
    pub fn with_max_frame_bytes(max_frame_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_frame_bytes,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// True if the internal buffer has grown past [`Self::max_frame_bytes`].
    /// When true, [`Self::next_frame`] will yield a single oversize-error
    /// frame and reset the buffer.
    pub fn over_limit(&self) -> bool {
        self.buf.len() > self.max_frame_bytes
    }

    /// Pull one fully-received frame from the buffer if one is
    /// available. Returns `None` when the buffer does not yet contain
    /// a complete frame (a blank line separator has not arrived).
    ///
    /// If the buffer has grown past [`Self::max_frame_bytes`] without
    /// a separator, the buffer is reset and a synthetic `oversize`
    /// frame is returned. The assembler maps this to a
    /// [`StreamEvent::ParseError`].
    pub fn next_frame(&mut self) -> Option<SseFrame> {
        if self.over_limit() {
            self.buf.clear();
            return Some(SseFrame {
                event_name: "__relix_oversize__".to_string(),
                data: String::new(),
            });
        }

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

/// Per-block JSON-buffer cap. A malicious upstream emitting an
/// unbounded `input_json_delta` stream is detected and the block
/// is finalised early with `Value::Null` plus a `ParseError`.
pub const MAX_TOOL_INPUT_BYTES: usize = 256 * 1024; // 256 KiB

/// Hard cap on the length of strings copied from upstream-controlled
/// fields (model name, tool name, error message). Anything longer is
/// truncated when stored to keep audit logs and downstream
/// consumers from being flooded.
pub const MAX_LABEL_BYTES: usize = 256;

fn sanitize_label(s: &str) -> String {
    // Drop control characters that would corrupt jsonl audit logs.
    // Keep printable ASCII and non-ASCII letter / number characters
    // (which lets legitimate model names pass) but normalise control
    // characters to underscore.
    let cleaned: String = s.chars().filter(|c| !c.is_control()).collect();
    if cleaned.len() <= MAX_LABEL_BYTES {
        cleaned
    } else {
        // Truncate at a char boundary.
        let mut end = MAX_LABEL_BYTES;
        while end > 0 && !cleaned.is_char_boundary(end) {
            end -= 1;
        }
        cleaned[..end].to_string()
    }
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
        // Synthetic frame inserted by the decoder when the buffer
        // exceeded its size cap.
        if frame.event_name == "__relix_oversize__" {
            self.pending_events.push(StreamEvent::ParseError {
                reason: "sse frame exceeded size limit".into(),
            });
            return;
        }
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

        // A1 fix: SSE `event:` name (when present) must agree with
        // the JSON `type` field. A poisoned upstream that sends
        // `event: ping` but `data: {"type":"content_block_delta",...}`
        // (or vice versa) is treated as a protocol violation.
        // Frames without an `event:` line (the OpenAI convention)
        // are accepted unchanged.
        if !frame.event_name.is_empty() && frame.event_name != typ {
            self.pending_events.push(StreamEvent::ParseError {
                reason: format!(
                    "sse event/type mismatch: event={} type={}",
                    frame.event_name, typ
                ),
            });
            return;
        }

        match typ {
            "message_start" => {
                if let Some(model) = raw.pointer("/message/model").and_then(Value::as_str) {
                    // C1 fix: sanitize upstream-controlled string before
                    // emitting it into events that may reach audit logs.
                    self.pending_events.push(StreamEvent::StreamStart {
                        model: sanitize_label(model),
                    });
                }
            }
            "content_block_start" => {
                let index = raw.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                let cb = match raw.get("content_block") {
                    Some(v) => v,
                    None => return,
                };

                // A3 fix: a duplicate content_block_start for the same
                // index is a protocol violation. We surface it as a
                // ParseError and overwrite (the second one wins,
                // because that matches the most-paranoid-inspector
                // posture: if we are going to evaluate something,
                // evaluate the latest claimed content). Without this
                // detection an attacker could finalise a benign
                // tool_use first, pass rules, then sneak a second
                // payload through.
                if self.blocks.contains_key(&index) {
                    self.pending_events.push(StreamEvent::ParseError {
                        reason: format!("duplicate content_block_start at index {index}"),
                    });
                }

                let block_type = cb.get("type").and_then(Value::as_str).unwrap_or("");
                match block_type {
                    "text" => {
                        self.blocks.insert(index, BlockState::Text);
                    }
                    "tool_use" | "server_tool_use" => {
                        let id = sanitize_label(cb.get("id").and_then(Value::as_str).unwrap_or(""));
                        let name =
                            sanitize_label(cb.get("name").and_then(Value::as_str).unwrap_or(""));
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
                // A4 fix: cap json_buf growth. If the cap is exceeded
                // we record a ParseError and finalise the block early
                // with `Value::Null` so a downstream rule that wants to
                // refuse on unknown input can do so. The block is
                // removed so subsequent deltas have no effect.
                let mut overflow_index: Option<(u32, String, String)> = None;
                if let Some(BlockState::ToolUse {
                    json_buf, id, name, ..
                }) = self.blocks.get_mut(&index)
                {
                    if json_buf.len().saturating_add(partial.len()) > MAX_TOOL_INPUT_BYTES {
                        overflow_index = Some((index, id.clone(), name.clone()));
                    } else {
                        json_buf.push_str(partial);
                    }
                }
                if let Some((idx, id, name)) = overflow_index {
                    self.blocks.remove(&idx);
                    self.pending_events.push(StreamEvent::ParseError {
                        reason: format!(
                            "tool_use input exceeded {MAX_TOOL_INPUT_BYTES}-byte cap at index {idx}"
                        ),
                    });
                    self.pending_events.push(StreamEvent::ToolUseFinalised {
                        index: idx,
                        id,
                        name,
                        input: Value::Null,
                    });
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
                        stop_reason: Some(sanitize_label(stop_reason)),
                    });
                }
            }
            "message_stop" => {
                self.finished = true;
                // A3 follow-on: if blocks remain unclosed at message_stop,
                // force-finalise tool_use blocks with the current buffer.
                // This prevents "open block forever" stalling inspection.
                let leftovers: Vec<u32> = self.blocks.keys().copied().collect();
                for idx in leftovers {
                    if let Some(BlockState::ToolUse { id, name, json_buf }) =
                        self.blocks.remove(&idx)
                    {
                        let input = if json_buf.trim().is_empty() {
                            Value::Null
                        } else {
                            serde_json::from_str(&json_buf).unwrap_or(Value::Null)
                        };
                        self.pending_events.push(StreamEvent::ParseError {
                            reason: format!(
                                "tool_use at index {idx} closed without content_block_stop"
                            ),
                        });
                        self.pending_events.push(StreamEvent::ToolUseFinalised {
                            index: idx,
                            id,
                            name,
                            input,
                        });
                    }
                }
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

    /// SSE frame helper that produces a `data:`-only frame (no
    /// `event:` line). Used to bypass the strict event-vs-type
    /// agreement check in tests where the event name was a free
    /// label in v0.2-step2 (e.g. "a", "b") rather than an actual
    /// Anthropic event type.
    fn data_only(data: &str) -> Vec<u8> {
        format!("data: {data}\n\n").into_bytes()
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

    // -- red-team regressions ----------------------------------------------

    #[test]
    fn rt_a1_event_name_must_match_data_type() {
        // Frame whose `event:` line contradicts its `data.type` field.
        // A poisoned upstream might use this to slip events past
        // type-aware inspection.
        let mut a = AnthropicStreamAssembler::new();
        let bytes = b"event: ping\n\
                      data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"x\"}}\n\
                      \n";
        a.push_bytes(bytes);
        let events = a.drain_events();
        assert!(
            events.iter().any(|e| matches!(
                e,
                StreamEvent::ParseError { reason } if reason.contains("event/type mismatch")
            )),
            "expected event/type mismatch parse error, got {events:?}"
        );
    }

    #[test]
    fn rt_a3_duplicate_content_block_start_is_flagged() {
        let mut a = AnthropicStreamAssembler::new();
        a.push_bytes(&frame(
            "content_block_start",
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"Bash","input":{}}}"#,
        ));
        a.push_bytes(&frame(
            "content_block_start",
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t2","name":"Bash","input":{}}}"#,
        ));
        let events = a.drain_events();
        assert!(events.iter().any(|e| matches!(
            e,
            StreamEvent::ParseError { reason } if reason.contains("duplicate content_block_start")
        )));
    }

    #[test]
    fn rt_a3_unclosed_block_finalised_at_message_stop() {
        // tool_use opened but never explicitly stopped should still be
        // evaluated when the stream ends. Otherwise an attacker can
        // park malicious payloads inside an open block.
        let mut a = AnthropicStreamAssembler::new();
        a.push_bytes(&frame(
            "content_block_start",
            r#"{"type":"content_block_start","index":7,"content_block":{"type":"tool_use","id":"t1","name":"Bash","input":{}}}"#,
        ));
        a.push_bytes(&frame(
            "content_block_delta",
            r#"{"type":"content_block_delta","index":7,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}"#,
        ));
        a.push_bytes(&frame("message_stop", r#"{"type":"message_stop"}"#));
        let events = a.drain_events();
        // Expect both a ParseError (unclosed) and a ToolUseFinalised.
        assert!(events.iter().any(|e| matches!(
            e,
            StreamEvent::ParseError { reason } if reason.contains("closed without")
        )));
        let finalised = events.iter().find_map(|e| match e {
            StreamEvent::ToolUseFinalised { name, input, .. } => {
                Some((name.clone(), input.clone()))
            }
            _ => None,
        });
        let (name, input) = finalised.expect("force-finalised tool_use");
        assert_eq!(name, "Bash");
        assert_eq!(input.get("command").and_then(Value::as_str), Some("ls"));
    }

    #[test]
    fn rt_a4_tool_input_size_cap() {
        // A delta sequence whose cumulative size exceeds the cap is
        // truncated and the block is finalised early with Null input.
        let mut a = AnthropicStreamAssembler::new();
        a.push_bytes(&frame(
            "content_block_start",
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"X","input":{}}}"#,
        ));
        // One delta carrying just over the cap.
        let oversize = "x".repeat(MAX_TOOL_INPUT_BYTES + 16);
        let payload = format!(
            r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"input_json_delta","partial_json":"{oversize}"}}}}"#
        );
        a.push_bytes(&frame("content_block_delta", &payload));
        let events = a.drain_events();
        assert!(events.iter().any(|e| matches!(
            e,
            StreamEvent::ParseError { reason } if reason.contains("exceeded")
        )));
        let null_input = events.iter().any(|e| {
            matches!(
                e,
                StreamEvent::ToolUseFinalised { input, .. } if matches!(input, Value::Null)
            )
        });
        assert!(null_input);
    }

    #[test]
    fn rt_c1_model_field_control_chars_stripped() {
        // Upstream tries to inject newlines / control characters via
        // the model field, hoping to corrupt jsonl audit logs.
        let mut a = AnthropicStreamAssembler::new();
        a.push_bytes(&frame(
            "message_start",
            "{\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"model\":\"evil\\u0000\\u0007\\nclaude\",\"role\":\"assistant\"}}",
        ));
        let events = a.drain_events();
        let model = events.iter().find_map(|e| match e {
            StreamEvent::StreamStart { model } => Some(model.clone()),
            _ => None,
        });
        let m = model.expect("StreamStart emitted");
        assert!(!m.contains('\n'), "newline survived sanitization: {m:?}");
        assert!(!m.contains('\u{0000}'), "null survived sanitization");
        assert!(!m.contains('\u{0007}'), "bell survived sanitization");
    }

    #[test]
    fn rt_decoder_oversize_buffer_yields_synthetic_error_frame() {
        // Bytes that never include a frame separator should be
        // dropped once they exceed the cap, with the assembler
        // surfacing a ParseError.
        let mut a = AnthropicStreamAssembler::default();
        // Use the public assembler so the synthetic frame routes
        // through handle_frame.
        a.assembler_mut_max_for_test(64);
        a.push_bytes(&vec![b'x'; 256]);
        let events = a.drain_events();
        assert!(events.iter().any(|e| matches!(
            e,
            StreamEvent::ParseError { reason } if reason.contains("size limit")
        )));
    }
}

// Test-only helper: shrink the decoder cap so the oversize path is
// exercised without allocating megabytes in tests.
#[cfg(test)]
impl AnthropicStreamAssembler {
    fn assembler_mut_max_for_test(&mut self, cap: usize) {
        self.decoder = SseFrameDecoder::with_max_frame_bytes(cap);
    }
}
