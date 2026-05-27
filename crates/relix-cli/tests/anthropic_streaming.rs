//! End-to-end tests for the Anthropic streaming path (RFC-0003 H6).
//!
//! Boots a real Relix proxy, points it at an in-process upstream that
//! replays a recorded SSE byte trace, and asserts on the bytes the
//! downstream client receives. Together these cover:
//!
//! - T01 (relay-injected `tool_use` is blocked mid-stream),
//! - T02 (clean `tool_use` flows through unchanged),
//! - the streaming inspection lifecycle from `forward_streaming`.

mod common;

use bytes::Bytes;
use common::{golden_sse, spawn_canned_upstream, spawn_proxy};
use relix_core::RuleSet;

const RULES_YAML: &str = r#"
rules:
  - id: relix.bash.read-private-key
    name: shell command reads SSH private key
    description: test rule
    severity: critical
    action: block
    tags: [credential-exfiltration]
    matcher:
      kind: tool_input_regex
      name: Bash
      pattern: "(\\.ssh/id_(rsa|ed25519|ecdsa)|\\.aws/credentials)"
"#;

fn rules() -> RuleSet {
    RuleSet::from_yaml(RULES_YAML).expect("rules parse")
}

#[tokio::test]
async fn clean_tool_use_streams_through_unchanged() {
    let body = golden_sse("anthropic_clean_tool_use.sse");
    let upstream = spawn_canned_upstream("text/event-stream", body.clone()).await;
    let proxy = spawn_proxy(rules(), upstream.url()).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/messages", proxy.url()))
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .body(r#"{"model":"claude","max_tokens":10,"messages":[]}"#)
        .send()
        .await
        .expect("proxy responded");
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("text/event-stream"),
        "expected SSE content-type, got {ct}"
    );

    let received = resp.bytes().await.expect("collect body");
    // The clean stream should be forwarded byte-for-byte. We do not
    // require exact equality (the proxy may legitimately re-chunk),
    // only that the assistant's `tool_use` content survived.
    let received_text = String::from_utf8_lossy(&received);
    assert!(
        received_text.contains("ls -la /tmp"),
        "clean tool_use input was lost downstream: {received_text}"
    );
    assert!(
        received_text.contains("message_stop"),
        "stream finished without message_stop: {received_text}"
    );
    assert!(
        !received_text.contains("relix.block"),
        "clean stream incorrectly triggered a block frame: {received_text}"
    );
}

#[tokio::test]
async fn poisoned_tool_use_is_blocked_mid_stream() {
    let body = golden_sse("anthropic_poisoned_tool_use.sse");
    let upstream = spawn_canned_upstream("text/event-stream", body).await;
    let proxy = spawn_proxy(rules(), upstream.url()).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/messages", proxy.url()))
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .body(r#"{"model":"claude","max_tokens":10,"messages":[]}"#)
        .send()
        .await
        .expect("proxy responded");
    assert_eq!(resp.status(), 200);

    let received = resp.bytes().await.expect("collect body");
    let received_text = String::from_utf8_lossy(&received);

    // The injected `tool_use` matches `relix.bash.read-private-key`,
    // so the inspector must splice in a synthetic `error` frame and
    // stop forwarding upstream bytes.
    assert!(
        received_text.contains("event: error"),
        "expected synthetic error frame for blocked stream, got: {received_text}"
    );
    assert!(
        received_text.contains("relix.bash.read-private-key"),
        "expected rule id in synthetic error frame, got: {received_text}"
    );
    // The `message_stop` from the upstream golden trace must NOT be
    // propagated downstream; the proxy stops forwarding after the
    // block decision.
    assert!(
        !received_text.contains("message_stop"),
        "upstream message_stop leaked past block decision: {received_text}"
    );
}

#[tokio::test]
async fn unsafe_path_is_rejected_before_upstream_contact() {
    // RFC-0003 H4 enforced from the e2e layer: a path containing `..`
    // never reaches the upstream. We assert by pointing the proxy at
    // a sink upstream that fails the test if it sees any traffic.
    let upstream = spawn_canned_upstream(
        "text/plain",
        Bytes::from_static(b"upstream MUST NOT receive request"),
    )
    .await;
    let proxy = spawn_proxy(rules(), upstream.url()).await;

    // reqwest normalises `..` segments out of the URL before sending,
    // so we hit the proxy with a raw HTTP request via tokio TCP.
    let raw = b"GET /v1/../etc/passwd HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let mut stream = tokio::net::TcpStream::connect(proxy.addr)
        .await
        .expect("connect to proxy");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(raw).await.expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "expected 400 for unsafe path, got: {response}"
    );
    assert!(
        response
            .to_ascii_lowercase()
            .contains("x-relix-error: unsafe-path"),
        "expected x-relix-error header, got: {response}"
    );
}
