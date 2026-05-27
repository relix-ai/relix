//! End-to-end tests for the OpenAI Chat Completions streaming path
//! (RFC-0002 + RFC-0003 H6).
//!
//! Mirrors `anthropic_streaming.rs`. Together they ensure that
//! adding the OpenAI adapter does not regress Anthropic and that the
//! same threat surface (tool_call exfiltration of credentials) is
//! caught on both protocols.

mod common;

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
async fn openai_clean_tool_call_streams_through_unchanged() {
    let body = golden_sse("openai_clean_tool_call.sse");
    let upstream = spawn_canned_upstream("text/event-stream", body.clone()).await;
    let proxy = spawn_proxy(rules(), upstream.url()).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", proxy.url()))
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .body(r#"{"model":"gpt-4o","stream":true,"messages":[]}"#)
        .send()
        .await
        .expect("proxy responded");
    assert_eq!(resp.status(), 200);

    let received = resp.bytes().await.expect("collect body");
    let received_text = String::from_utf8_lossy(&received);
    assert!(
        received_text.contains("ls -la /tmp"),
        "clean tool_call args were lost downstream: {received_text}"
    );
    assert!(
        received_text.contains("[DONE]"),
        "stream finished without [DONE] sentinel: {received_text}"
    );
    assert!(
        !received_text.contains("relix_blocked"),
        "clean stream incorrectly triggered a block: {received_text}"
    );
}

#[tokio::test]
async fn openai_poisoned_tool_call_is_blocked_mid_stream() {
    let body = golden_sse("openai_poisoned_tool_call.sse");
    let upstream = spawn_canned_upstream("text/event-stream", body).await;
    let proxy = spawn_proxy(rules(), upstream.url()).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", proxy.url()))
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .body(r#"{"model":"gpt-4o","stream":true,"messages":[]}"#)
        .send()
        .await
        .expect("proxy responded");
    assert_eq!(resp.status(), 200);

    let received = resp.bytes().await.expect("collect body");
    let received_text = String::from_utf8_lossy(&received);

    // The injected tool_call matches the test rule. The streaming
    // inspector must splice in a synthetic error frame and stop
    // forwarding upstream bytes.
    assert!(
        received_text.contains("event: error"),
        "expected synthetic error frame, got: {received_text}"
    );
    assert!(
        received_text.contains("relix.bash.read-private-key"),
        "expected rule id in error frame, got: {received_text}"
    );
    // The `[DONE]` sentinel from the upstream golden trace must NOT
    // be propagated downstream; the proxy stops forwarding after the
    // block decision.
    assert!(
        !received_text.contains("[DONE]"),
        "upstream [DONE] leaked past block decision: {received_text}"
    );
}

#[tokio::test]
async fn openai_buffered_response_with_clean_tool_call_passes() {
    // Non-streaming OpenAI response: assistant returns a tool_call
    // pointing at a benign command. Should forward unchanged.
    let body = bytes::Bytes::from_static(
        br#"{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]}}]}"#,
    );
    let upstream = spawn_canned_upstream("application/json", body).await;
    let proxy = spawn_proxy(rules(), upstream.url()).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", proxy.url()))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-4o","messages":[]}"#)
        .send()
        .await
        .expect("proxy responded");
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.expect("body");
    // `arguments` is itself a JSON-encoded string in the OpenAI
    // shape, so the bytes on the wire have escaped quotes.
    assert!(
        text.contains(r#"\"command\":\"ls\""#),
        "buffered body did not survive: {text}"
    );
}

#[tokio::test]
async fn openai_buffered_response_with_poisoned_tool_call_is_blocked() {
    let body = bytes::Bytes::from_static(
        br#"{"id":"chatcmpl-2","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"call_evil","type":"function","function":{"name":"Bash","arguments":"{\"command\":\"cat $HOME/.ssh/id_rsa\"}"}}]}}]}"#,
    );
    let upstream = spawn_canned_upstream("application/json", body).await;
    let proxy = spawn_proxy(rules(), upstream.url()).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", proxy.url()))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-4o","messages":[]}"#)
        .send()
        .await
        .expect("proxy responded");
    // OpenAI-shaped block notice uses 403 (RFC-0002 §"Error responses").
    // Anthropic-shaped block notice uses 403 today as well (the
    // status flows from the shared `blocked_response` helper). Both
    // values are accepted; what we really care about is that the
    // body carries the rule id and the `x-relix-blocked` header is
    // set.
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "expected error status, got: {}",
        resp.status()
    );
    assert_eq!(
        resp.headers()
            .get("x-relix-blocked")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
    let text = resp.text().await.expect("body");
    assert!(
        text.contains("relix.bash.read-private-key"),
        "expected rule id in body, got: {text}"
    );
}
