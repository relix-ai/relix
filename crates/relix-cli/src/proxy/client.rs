//! Upstream HTTP client construction.
//!
//! Centralised so timeout and connection-pool tuning is reviewable in
//! one place. The configuration is documented in
//! [`docs/rfcs/0003-hardening-plan.md`] §H1.
//!
//! Key invariants:
//!
//! - **No total request timeout.** LLM streaming responses can run
//!   for many minutes. A `timeout()` would kill legitimate streams.
//!   Stalled connections are detected by a per-read timeout instead.
//! - **`https_only(true)`.** Relix is an LLM API gateway; plaintext
//!   upstream is never legitimate. The flag prevents accidental
//!   downgrade if a misconfigured `RELIX_UPSTREAM` lacks the `https://`
//!   scheme.
//! - **Bounded pool.** `pool_max_idle_per_host = 32` prevents file-
//!   descriptor leaks on long-running gateways without harming
//!   per-request latency for typical workloads.

use std::time::Duration;

use anyhow::Result;

/// TCP+TLS handshake to the upstream must complete within this window.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum allowed gap between successive bytes read from the
/// upstream response. Set above any plausible legitimate
/// inter-chunk delay (LLM tokens normally arrive faster than once
/// per second; 60 s leaves headroom for slow first-token
/// scenarios like cold-start models).
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Idle keep-alive sockets are dropped after this period.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Cap on idle keep-alive sockets retained per upstream host.
const POOL_MAX_IDLE_PER_HOST: usize = 32;

/// TCP keep-alive ping cadence on idle sockets.
const TCP_KEEPALIVE: Duration = Duration::from_secs(30);

/// HTTP/2 keep-alive ping cadence on the upstream connection.
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// HTTP/2 keep-alive timeout: peer has this long to respond to a
/// keep-alive ping before the connection is considered dead.
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the Relix upstream HTTP client.
///
/// The client is cheap to clone (it is internally reference-counted)
/// and is intended to be created once at process start.
pub fn build() -> Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        // No `.timeout()` — see module docs.
        .read_timeout(READ_TIMEOUT)
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
        .tcp_keepalive(TCP_KEEPALIVE)
        .http2_keep_alive_interval(H2_KEEPALIVE_INTERVAL)
        .http2_keep_alive_timeout(H2_KEEPALIVE_TIMEOUT)
        .https_only(true)
        .build()?;
    Ok(client)
}

/// Per-request timeout to use for **non-streaming** upstream calls
/// (token-count, model-list, health-check endpoints).
///
/// Apply via `RequestBuilder::timeout(NON_STREAMING_REQUEST_TIMEOUT)`
/// at the call site. The global client deliberately has no total
/// timeout because streaming requests share the same client and
/// must not be capped.
#[allow(dead_code)] // Intended for future non-streaming code paths.
pub const NON_STREAMING_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_succeeds() {
        let _client = build().expect("client builds with default config");
    }

    #[test]
    fn https_only_rejects_plain_http() {
        let client = build().expect("client builds");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let outcome = runtime.block_on(async {
            // Use a TEST-NET-1 address (RFC 5737) so this never reaches the
            // network even if the https_only check were missing. With
            // `https_only(true)` reqwest fails the request synchronously
            // at builder time before any DNS or TCP activity.
            client.get("http://192.0.2.1/").send().await
        });
        let err = outcome.expect_err("plaintext http must be rejected");
        // reqwest's https_only rejection surfaces as a builder error
        // tagged with the URL and `is_builder() == true`. We assert
        // that, rather than depending on the precise human-readable
        // message string (which has changed across reqwest versions).
        assert!(
            err.is_builder(),
            "expected reqwest builder error from https_only, got: {err:?}"
        );
    }
}
