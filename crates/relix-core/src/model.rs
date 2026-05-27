use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpDirection {
    Request,
    Response,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    pub input: serde_json::Value,
    pub id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionEvent {
    pub event_id: Uuid,
    pub session_id: Uuid,
    pub at: DateTime<Utc>,
    pub direction: HttpDirection,
    pub upstream_host: String,
    pub model: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub system_prompt_excerpt: Option<String>,
}

impl InspectionEvent {
    pub fn new(session_id: Uuid, direction: HttpDirection, upstream_host: String) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            session_id,
            at: Utc::now(),
            direction,
            upstream_host,
            model: None,
            tool_calls: Vec::new(),
            system_prompt_excerpt: None,
        }
    }
}
