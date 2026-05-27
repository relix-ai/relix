//! Concrete protocol implementations.
//!
//! Each protocol implements [`crate::proxy::lifecycle::LlmProxy`].
//! The driver picks one per request based on URL path; see
//! [`select`].

pub mod anthropic;
pub mod openai;
pub mod passthrough;

use std::sync::Arc;

use axum::http::Uri;

use crate::proxy::lifecycle::LlmProxy;

/// Pick a protocol implementation based on the request URI.
///
/// The mapping follows RFC-0001 §"Protocol selection" and
/// RFC-0002 §"Routing". Unknown paths fall through to the
/// passthrough protocol so auxiliary endpoints (token-count,
/// model-list, health) keep working.
pub fn select(uri: &Uri) -> Arc<dyn LlmProxy> {
    let path = uri.path();
    if path.starts_with("/v1/messages") {
        return Arc::new(anthropic::AnthropicProtocol);
    }
    if path == "/v1/chat/completions" || path == "/v1/completions" {
        return Arc::new(openai::OpenAiProtocol);
    }
    Arc::new(passthrough::PassthroughProtocol)
}
