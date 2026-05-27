//! Passthrough protocol: forward bytes unchanged, run no inspection.
//!
//! Used when the request URI does not match any known protocol path
//! (token-count, model-list, health endpoints, or anything Relix
//! does not yet understand). RFC-0001 §"Protocol selection"
//! requires this fallback so auxiliary calls do not crash the
//! parser.

use async_trait::async_trait;
use axum::http::{HeaderMap, StatusCode};
use bytes::Bytes;

use crate::proxy::lifecycle::{HookOutcome, LlmProxy, ProxyContext, ResponseAction};
use crate::proxy::state::ProxyState;

pub struct PassthroughProtocol;

#[async_trait]
impl LlmProxy for PassthroughProtocol {
    fn name(&self) -> &'static str {
        "passthrough"
    }

    async fn request_filter(
        &self,
        _ctx: &mut ProxyContext,
        _state: &ProxyState,
        _headers: &HeaderMap,
        _body: &Bytes,
    ) -> anyhow::Result<HookOutcome> {
        Ok(HookOutcome::Continue)
    }

    async fn response_filter(
        &self,
        _ctx: &mut ProxyContext,
        _state: &ProxyState,
        _upstream_status: StatusCode,
        _upstream_headers: &HeaderMap,
        _body: &Bytes,
    ) -> anyhow::Result<ResponseAction> {
        Ok(ResponseAction::Forward)
    }
}
