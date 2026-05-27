//! Common helpers for Relix end-to-end tests (RFC-0003 H6).
//!
//! Each helper boots a real component on a `127.0.0.1:0` random port
//! and returns the bound address. Servers are owned by spawned tasks
//! that cancel when the returned [`TestServer`] drops, so individual
//! tests get isolated, leak-free fixtures with no shared state.

#![allow(dead_code)]

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use relix_cli::{app_router, AuditLog, ProxyState};
use relix_core::RuleSet;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Owned handle to an in-process test server. The server stops when
/// the handle is dropped (the spawned task is aborted).
pub struct TestServer {
    pub addr: SocketAddr,
    handle: JoinHandle<()>,
}

impl TestServer {
    /// Returns the base URL (`http://host:port`) for this server.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Spawn a Relix proxy bound to a random localhost port that forwards
/// to the given `upstream_url`. Audit log writes go to a per-test
/// temp file so concurrent tests do not contend.
pub async fn spawn_proxy(rules: RuleSet, upstream_url: String) -> TestServer {
    let audit_path = unique_tempfile("relix-e2e-audit");
    let audit = AuditLog::open(audit_path)
        .await
        .expect("open audit log for test");
    // E2E tests target an in-process `http://127.0.0.1` upstream;
    // disable `https_only` for the test client only. Production code
    // paths in `main.rs` use `client::build()` which keeps it on.
    let client = relix_cli::proxy::client::build_with(relix_cli::proxy::client::BuildOptions {
        https_only: false,
    })
    .expect("build test client");
    let state = ProxyState {
        upstream: upstream_url,
        client,
        rules: Arc::new(rules),
        audit,
    };
    spawn_router(app_router(state)).await
}

/// Spawn an in-process upstream that runs the given handler. Useful
/// when a test wants tight control over the response body, headers,
/// or framing (which `wiremock` cannot guarantee for SSE).
pub async fn spawn_upstream<F, Fut>(handler: F) -> TestServer
where
    F: Fn(Request<Body>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response<Body>> + Send + 'static,
{
    let app = Router::new().route(
        "/*path",
        any(move |req: Request<Body>| {
            let h = handler.clone();
            async move { Ok::<_, Infallible>(h(req).await) }
        }),
    );
    spawn_router(app).await
}

/// Spawn an upstream that returns the same canned bytes for every
/// request, with the supplied content-type. Convenience wrapper over
/// [`spawn_upstream`] for the common SSE-replay case.
pub async fn spawn_canned_upstream(content_type: &'static str, body: Bytes) -> TestServer {
    let body = body.clone();
    spawn_upstream(move |_req: Request<Body>| {
        let body = body.clone();
        async move {
            Response::builder()
                .status(200)
                .header("content-type", content_type)
                .body(Body::from(body))
                .expect("build canned response")
        }
    })
    .await
}

async fn spawn_router(app: Router) -> TestServer {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("listener has local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    TestServer { addr, handle }
}

/// Load a recorded SSE byte trace from `tests/golden/<name>`.
/// Bytes are returned verbatim so tests can replay exact framing
/// (including CRLFs and chunk boundaries) when fed to the proxy.
pub fn golden_sse(name: &str) -> Bytes {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("golden");
    path.push(name);
    let bytes =
        std::fs::read(&path).unwrap_or_else(|err| panic!("read golden {}: {err}", path.display()));
    Bytes::from(bytes)
}

fn unique_tempfile(prefix: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("{prefix}-{pid}-{nonce}.jsonl"));
    path
}
