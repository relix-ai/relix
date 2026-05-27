//! relix-core: the engine that powers Relix.
//!
//! This crate is intentionally IO-free. It exposes pure data structures
//! and functions for:
//!
//! - parsing LLM API protocols (Anthropic Messages, OpenAI Chat)
//! - loading and matching detection rules
//! - producing inspection verdicts
//!
//! All network and CLI concerns live in `relix-cli`.

pub mod error;
pub mod inspect;
pub mod model;
pub mod protocol;
pub mod redact;
pub mod rules;
pub mod streaming;
pub mod streaming_openai;

pub use error::{Error, Result};
pub use inspect::{Decision, InspectionContext, Verdict};
pub use model::{HttpDirection, InspectionEvent, ToolCall};
pub use redact::{detect, Detection, Placeholder, PlaceholderId, RedactConfig, SecretKind, Vault};
pub use rules::{Rule, RuleAction, RuleSet, Severity};
pub use streaming::{AnthropicStreamAssembler, SseFrame, SseFrameDecoder, StreamEvent};
pub use streaming_openai::OpenAiStreamAssembler;
