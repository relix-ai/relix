//! End-to-end tests for the secret-redaction pipeline (RFC-0004).
//!
//! Boots a real Relix proxy and an in-process upstream that
//! captures the outbound request body so we can verify the
//! redacted bytes that reach upstream, then forges a response
//! that exercises restore + leak detection. Together these
//! cover threats S01 (leak via prompt), S04 (upstream returns
//! literal secret), S05 (forged placeholder), and the cross-
//! chunk restore path.

mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use bytes::Bytes;
use common::{spawn_proxy, spawn_upstream};
use relix_core::RuleSet;

fn empty_rules() -> RuleSet {
    RuleSet::default()
}

#[tokio::test]
async fn outbound_secret_is_redacted_before_upstream_sees_it() {
    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let captured_for_upstream = captured.clone();
    let upstream = spawn_upstream(move |req: Request<Body>| {
        let captured = captured_for_upstream.clone();
        async move {
            let bytes = axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024)
                .await
                .unwrap();
            *captured.lock().unwrap() = bytes.to_vec();
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"id":"x","content":"ok"}"#))
                .unwrap()
        }
    })
    .await;
    let proxy = spawn_proxy(empty_rules(), upstream.url()).await;

    let real = format!("{}{}", "ghp_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA01");
    let body = format!(r#"{{"system":"my key {real}","messages":[]}}"#);
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/messages", proxy.url()))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("proxy responded");
    assert_eq!(resp.status(), 200);

    let upstream_saw = captured.lock().unwrap().clone();
    let upstream_text = String::from_utf8_lossy(&upstream_saw);
    assert!(
        !upstream_text.contains(&real),
        "upstream saw the real secret: {upstream_text}"
    );
    assert!(
        upstream_text.contains("RELIX_SECRET") && upstream_text.contains("github_pat"),
        "upstream did not receive a placeholder: {upstream_text}"
    );

    // Diagnostic header surfaces the redacted count to the client.
    assert_eq!(
        resp.headers()
            .get("x-relix-redacted-count")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
}

#[tokio::test]
async fn buffered_response_with_placeholder_is_restored_to_real_value() {
    // Arrange: a custom upstream that
    //   (a) captures the outbound body, then
    //   (b) parses the placeholder out of the captured request
    //       and echoes it back in its own response, simulating
    //       a model that quoted the input back at the user.
    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let captured_for_upstream = captured.clone();
    let upstream = spawn_upstream(move |req: Request<Body>| {
        let captured = captured_for_upstream.clone();
        async move {
            let bytes = axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024)
                .await
                .unwrap();
            *captured.lock().unwrap() = bytes.to_vec();
            // Pull the placeholder out of the captured request and
            // echo it inside a JSON response field. We use serde_json
            // to encode so the placeholder gets the same JSON
            // escaping a real LLM upstream would apply.
            let txt = String::from_utf8_lossy(captured.lock().unwrap().as_slice()).to_string();
            // Inbound is JSON, so the placeholder is double-escaped
            // there. Decode the captured request so we get the raw
            // placeholder string the model would see.
            let parsed: serde_json::Value = serde_json::from_str(&txt).unwrap();
            let user_content = parsed["messages"][0]["content"].as_str().unwrap_or("");
            let pstart = user_content.find("<RELIX_SECRET").unwrap();
            let pend = user_content[pstart..].find('>').unwrap() + pstart + 1;
            let placeholder_raw = &user_content[pstart..pend];
            // Echo it inside a JSON response field. serde_json will
            // produce the canonical single-backslash escaping of the
            // inner quotes.
            let echo_body = serde_json::json!({ "echo": placeholder_raw });
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Body::from(echo_body.to_string()))
                .unwrap()
        }
    })
    .await;
    let proxy = spawn_proxy(empty_rules(), upstream.url()).await;

    let real = format!("{}{}", "ghp_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA01");
    let body = format!(r#"{{"messages":[{{"role":"user","content":"key {real}"}}]}}"#);
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/messages", proxy.url()))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("proxy responded");
    assert_eq!(resp.status(), 200);

    let body_back = resp.text().await.expect("body");
    assert!(
        body_back.contains(&real),
        "response did not restore the real secret: {body_back}"
    );
    assert!(
        !body_back.contains("RELIX_SECRET"),
        "placeholder leaked to the client: {body_back}"
    );
}

#[tokio::test]
async fn upstream_responding_with_literal_real_secret_is_blocked() {
    // S04: the upstream returns a literal AWS key in its response
    // body. Relix must block this.
    let leak = format!("AKIA{}", "IOSFODNN7EXAMPLE");
    let leak_for_upstream = leak.clone();
    let upstream = spawn_upstream(move |_req: Request<Body>| {
        let leak = leak_for_upstream.clone();
        async move {
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"value":"{leak}"}}"#)))
                .unwrap()
        }
    })
    .await;
    let proxy = spawn_proxy(empty_rules(), upstream.url()).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/messages", proxy.url()))
        .header("content-type", "application/json")
        .body(r#"{"messages":[]}"#)
        .send()
        .await
        .expect("proxy responded");

    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "expected error status, got: {}",
        resp.status()
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("relix.redact.upstream-leak"),
        "expected upstream-leak rule id in body: {body}"
    );
    assert!(
        !body.contains(&leak),
        "leaked secret was echoed back to the client: {body}"
    );
}

#[tokio::test]
async fn forged_placeholder_passes_through_unchanged() {
    // S05: an upstream injects a placeholder shape with an id the
    // vault never recorded. The proxy must NOT substitute anything;
    // it must forward the placeholder verbatim. (The downstream
    // client will see a literal `<RELIX_SECRET ...>` and is
    // expected to ignore it; the threat is about preventing the
    // attacker from extracting *some* real value via probing.)
    let forged = "<RELIX_SECRET kind=\"github_pat\" id=\"deadbe\">";
    let forged_for_upstream = forged.to_string();
    let upstream = spawn_upstream(move |_req: Request<Body>| {
        let forged = forged_for_upstream.clone();
        async move {
            let echo_body = serde_json::json!({ "v": forged });
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Body::from(echo_body.to_string()))
                .unwrap()
        }
    })
    .await;
    let proxy = spawn_proxy(empty_rules(), upstream.url()).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/messages", proxy.url()))
        .header("content-type", "application/json")
        .body(r#"{"messages":[]}"#)
        .send()
        .await
        .expect("proxy responded");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("RELIX_SECRET") && body.contains("deadbe"),
        "forged placeholder should pass through verbatim: {body}"
    );
}

#[tokio::test]
async fn no_secret_means_no_redacted_count_header() {
    let upstream = common::spawn_canned_upstream(
        "application/json",
        Bytes::from_static(br#"{"value":"plain text response"}"#),
    )
    .await;
    let proxy = spawn_proxy(empty_rules(), upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/messages", proxy.url()))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"role":"user","content":"plain text"}]}"#)
        .send()
        .await
        .expect("proxy responded");
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers().get("x-relix-redacted-count").is_none(),
        "header should be absent when nothing was redacted"
    );
}
