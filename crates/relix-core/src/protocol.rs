use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::ToolCall;

/// Subset of the Anthropic Messages API streaming events that we care about.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AnthropicSseEvent {
    MessageStart {
        message: AnthropicMessageStart,
    },
    ContentBlockStart {
        index: u32,
        content_block: ContentBlock,
    },
    ContentBlockDelta {
        index: u32,
        delta: ContentDelta,
    },
    ContentBlockStop {
        index: u32,
    },
    MessageDelta {
        delta: MessageDeltaInner,
    },
    MessageStop,
    Ping,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicMessageStart {
    pub id: String,
    pub model: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        #[serde(default)]
        input: Value,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentDelta {
    TextDelta {
        text: String,
    },
    InputJsonDelta {
        partial_json: String,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDeltaInner {
    #[serde(default)]
    pub stop_reason: Option<String>,
}

/// Best-effort extraction of a `ToolCall` from a complete content block.
///
/// Streaming tool calls arrive as a `ContentBlockStart` (with empty input)
/// followed by `InputJsonDelta` chunks. The CLI assembles those before
/// calling this. Here we just convert a fully-formed block.
pub fn tool_call_from_block(block: &ContentBlock) -> Option<ToolCall> {
    match block {
        ContentBlock::ToolUse { id, name, input } => Some(ToolCall {
            name: name.clone(),
            input: input.clone(),
            id: Some(id.clone()),
        }),
        _ => None,
    }
}

/// Parse a full non-streaming Anthropic Messages response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicMessageResponse {
    pub id: String,
    pub model: String,
    #[serde(default)]
    pub content: Vec<ContentBlock>,
    #[serde(default)]
    pub stop_reason: Option<String>,
}

impl AnthropicMessageResponse {
    pub fn tool_calls(&self) -> Vec<ToolCall> {
        self.content
            .iter()
            .filter_map(tool_call_from_block)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tool_use_block() {
        let json = r#"{
            "id": "msg_01",
            "model": "claude-opus-4-7",
            "content": [
                {"type": "text", "text": "ok"},
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "ls"}}
            ]
        }"#;
        let resp: AnthropicMessageResponse = serde_json::from_str(json).unwrap();
        let calls = resp.tool_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "Bash");
    }
}
