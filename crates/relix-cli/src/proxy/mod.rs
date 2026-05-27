//! Proxy module: transports, lifecycle, and protocol implementations.
//!
//! Layered as described in `docs/rfcs/0001-multi-protocol-gateway.md`:
//!
//! - [`state`] — shared `ProxyState`
//! - [`lifecycle`] — `LlmProxy` trait modeled on Pingora's `ProxyHttp`
//! - [`driver`] — axum handler that drives the lifecycle
//! - [`protocols`] — concrete per-provider implementations

pub mod driver;
pub mod lifecycle;
pub mod protocols;
pub mod state;

pub use driver::proxy_handler;
pub use state::ProxyState;
