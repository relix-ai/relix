//! Secret-redaction integration (RFC-0004 §Integration).
//!
//! Bridges the IO-free [`relix_core::redact`] primitives to the
//! request lifecycle:
//!
//! - **Outbound**: walk a request body's text-bearing fields and
//!   substitute every detected secret with a deterministic
//!   `<RELIX_SECRET ...>` placeholder. The vault remembers the
//!   real value so the restore pass can put it back.
//!
//! - **Inbound**: see `restore.rs` (S4). This module is the
//!   write side; restore is the read side. They share the
//!   [`relix_core::Vault`] but are otherwise independent.
//!
//! The Anthropic and OpenAI protocol adapters call into this
//! module from their `request_filter` hook, after their
//! protocol-specific JSON walk.

use bytes::Bytes;
use relix_core::redact::detector::{detect, DetectorConfig};
use relix_core::{SecretKind, Vault};
use serde_json::Value;

use crate::proxy::state::ProxyState;

/// Outcome of a single redact pass.
pub struct RedactOutcome {
    /// Body to forward upstream. Equal to the input body when
    /// nothing was redacted (zero-copy).
    pub body: Bytes,
    /// Number of distinct secrets redacted.
    pub count: u32,
}

/// JSON paths in a request body that the redactor should walk.
/// The two protocol adapters configure this depending on which
/// API shape they handle.
pub struct RedactPaths {
    /// Top-level fields whose value is a string (e.g. Anthropic's
    /// `system` when sent as a plain string).
    pub top_level_strings: &'static [&'static str],
    /// Top-level fields whose value is an array of `{ "text": "..." }`
    /// objects (e.g. Anthropic's `system` when sent as an array).
    pub top_level_text_arrays: &'static [&'static str],
    /// Whether to walk `messages[]`. Both protocols set this to
    /// true; the implementation handles the role / content
    /// shape variants internally.
    pub walk_messages: bool,
}

/// Run the outbound redaction pass over a JSON request body.
///
/// On any error (non-JSON body, etc.) the original body is
/// returned unchanged with `count = 0`. Failure of the redactor
/// is **never** fatal to the request — the worst case is the
/// secret reaches the upstream the same way it would without
/// Relix in the path.
pub async fn redact_outbound(
    state: &ProxyState,
    paths: &RedactPaths,
    body: &Bytes,
) -> RedactOutcome {
    if !state.redact_config.enabled {
        return RedactOutcome {
            body: body.clone(),
            count: 0,
        };
    }

    let Ok(mut json) = serde_json::from_slice::<Value>(body) else {
        return RedactOutcome {
            body: body.clone(),
            count: 0,
        };
    };

    let mut count: u32 = 0;
    let cfg = state.redact_config.detector();

    for key in paths.top_level_strings {
        if let Some(field) = json.get_mut(*key) {
            if let Value::String(s) = field {
                if let Some(new) = redact_string(s, &cfg, &state.vault, &mut count).await {
                    *s = new;
                }
            }
        }
    }

    for key in paths.top_level_text_arrays {
        if let Some(Value::Array(items)) = json.get_mut(*key) {
            for item in items.iter_mut() {
                redact_text_field(item, "text", &cfg, &state.vault, &mut count).await;
            }
        }
    }

    if paths.walk_messages {
        if let Some(Value::Array(msgs)) = json.get_mut("messages") {
            for msg in msgs.iter_mut() {
                redact_message_content(msg, &cfg, &state.vault, &mut count).await;
            }
        }
    }

    if count == 0 {
        return RedactOutcome {
            body: body.clone(),
            count: 0,
        };
    }

    let new_body = match serde_json::to_vec(&json) {
        Ok(b) => Bytes::from(b),
        // Re-serialisation should never fail on a Value we just
        // parsed; fall back to original to be safe.
        Err(_) => body.clone(),
    };

    RedactOutcome {
        body: new_body,
        count,
    }
}

async fn redact_message_content(
    msg: &mut Value,
    cfg: &DetectorConfig,
    vault: &Vault,
    count: &mut u32,
) {
    let Some(content) = msg.get_mut("content") else {
        return;
    };
    match content {
        Value::String(s) => {
            if let Some(new) = redact_string(s, cfg, vault, count).await {
                *s = new;
            }
        }
        Value::Array(parts) => {
            for part in parts.iter_mut() {
                redact_text_field(part, "text", cfg, vault, count).await;
            }
        }
        _ => {}
    }
}

async fn redact_text_field(
    obj: &mut Value,
    field: &str,
    cfg: &DetectorConfig,
    vault: &Vault,
    count: &mut u32,
) {
    let Some(field_val) = obj.get_mut(field) else {
        return;
    };
    if let Value::String(s) = field_val {
        if let Some(new) = redact_string(s, cfg, vault, count).await {
            *s = new;
        }
    }
}

/// Redact every detection in `s`. Returns `None` when nothing
/// was changed (so callers can avoid an allocation).
///
/// Multiple matches are processed back-to-front so earlier byte
/// offsets remain valid throughout the rewrite.
async fn redact_string(
    s: &str,
    cfg: &DetectorConfig,
    vault: &Vault,
    count: &mut u32,
) -> Option<String> {
    let hits = detect(s, cfg);
    if hits.is_empty() {
        return None;
    }

    let mut placeholders: Vec<(usize, usize, String)> = Vec::with_capacity(hits.len());
    for h in &hits {
        let real = &s[h.start..h.end];
        let kind = pick_kind(h.kind, real);
        let p = vault.insert(real, kind);
        placeholders.push((h.start, h.end, p.render()));
        *count += 1;
    }

    placeholders.sort_by_key(|(start, _, _)| *start);

    let mut out = String::with_capacity(s.len());
    let mut cursor = 0usize;
    for (start, end, rendered) in placeholders {
        out.push_str(&s[cursor..start]);
        out.push_str(&rendered);
        cursor = end;
    }
    out.push_str(&s[cursor..]);
    Some(out)
}

/// `Generic` is the entropy-fallback kind. v0.3 keeps this as
/// identity; future heuristics that promote a Generic hit to a
/// more specific kind have a natural place to live here.
fn pick_kind(kind: SecretKind, _real: &str) -> SecretKind {
    kind
}

/// Iterate over every placeholder in `s`, yielding `(byte_range,
/// placeholder)`. Non-overlapping, left-to-right.
pub fn detect_upstream_leak(state: &ProxyState, body: &[u8]) -> Option<LeakReport> {
    if !state.redact_config.enabled || !state.redact_config.block_on_upstream_leak {
        return None;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return None;
    };
    let cfg = state.redact_config.detector();
    let hits = relix_core::redact::detector::detect(text, &cfg);
    if hits.is_empty() {
        return None;
    }
    // Filter out anything that is itself a placeholder span — those
    // are ours and not a leak.
    let placeholder_ranges = relix_core::redact::Placeholder::find_all(text);
    let mut leak_kinds: Vec<SecretKind> = Vec::new();
    'outer: for h in &hits {
        for (range, _) in &placeholder_ranges {
            if h.start >= range.start && h.end <= range.end {
                continue 'outer;
            }
        }
        leak_kinds.push(h.kind);
    }
    if leak_kinds.is_empty() {
        return None;
    }
    Some(LeakReport { kinds: leak_kinds })
}

/// Outcome of an upstream-leak scan.
pub struct LeakReport {
    pub kinds: Vec<SecretKind>,
}

impl LeakReport {
    pub fn rule_id(&self) -> &'static str {
        "relix.redact.upstream-leak"
    }
    pub fn reason(&self) -> String {
        format!(
            "upstream returned a literal secret (kind={})",
            self.kinds
                .iter()
                .map(|k| k.label())
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relix_core::RedactConfig;
    use std::sync::Arc;

    fn fixture_state() -> ProxyState {
        // Reuse the test client builder that opts out of
        // https_only; the redact path does not actually issue
        // network calls so this is just a no-op constructor.
        let client = crate::proxy::client::build_with(crate::proxy::client::BuildOptions {
            https_only: false,
        })
        .unwrap();
        ProxyState {
            upstream: "http://127.0.0.1".into(),
            client,
            rules: Arc::new(relix_core::RuleSet::default()),
            audit: crate::audit::AuditLog::disabled(),
            vault: Vault::with_fresh_salt(64),
            redact_config: Arc::new(RedactConfig::default()),
        }
    }

    const ANTHROPIC_PATHS: RedactPaths = RedactPaths {
        top_level_strings: &["system"],
        top_level_text_arrays: &[],
        walk_messages: true,
    };

    #[tokio::test]
    async fn anthropic_string_system_is_redacted() {
        let state = fixture_state();
        let body = Bytes::from(format!(
            r#"{{"system":"my key {}{}","messages":[]}}"#,
            "ghp_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA01"
        ));
        let out = redact_outbound(&state, &ANTHROPIC_PATHS, &body).await;
        assert_eq!(out.count, 1);
        let text = std::str::from_utf8(&out.body).unwrap();
        // The body is JSON; placeholder quotes are escaped.
        assert!(
            text.contains(r#"<RELIX_SECRET kind=\"github_pat\""#),
            "expected placeholder, got: {text}"
        );
        assert!(!text.contains("ghp_AAAAAA"));
    }

    #[tokio::test]
    async fn anthropic_message_content_string_is_redacted() {
        let state = fixture_state();
        let body = Bytes::from(format!(
            r#"{{"messages":[{{"role":"user","content":"please use {}{}"}}]}}"#,
            "sk-ant-", "api03-AAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBB"
        ));
        let out = redact_outbound(&state, &ANTHROPIC_PATHS, &body).await;
        assert_eq!(out.count, 1);
        let text = std::str::from_utf8(&out.body).unwrap();
        assert!(text.contains(r#"<RELIX_SECRET kind=\"anthropic_key\""#));
    }

    #[tokio::test]
    async fn anthropic_message_array_content_is_redacted() {
        let state = fixture_state();
        let body = Bytes::from(format!(
            r#"{{"messages":[{{"role":"user","content":[{{"type":"text","text":"key {}{}"}}]}}]}}"#,
            "AKIA", "IOSFODNN7EXAMPLE"
        ));
        let out = redact_outbound(&state, &ANTHROPIC_PATHS, &body).await;
        assert_eq!(out.count, 1);
        let text = std::str::from_utf8(&out.body).unwrap();
        assert!(text.contains(r#"<RELIX_SECRET kind=\"aws_access_key\""#));
    }

    #[tokio::test]
    async fn no_secrets_means_zero_copy_passthrough() {
        let state = fixture_state();
        let body = Bytes::from(r#"{"system":"plain text","messages":[]}"#);
        let out = redact_outbound(&state, &ANTHROPIC_PATHS, &body).await;
        assert_eq!(out.count, 0);
        assert_eq!(out.body, body);
    }

    #[tokio::test]
    async fn invalid_json_is_passthrough_not_error() {
        let state = fixture_state();
        let body = Bytes::from(b"not valid json".to_vec());
        let out = redact_outbound(&state, &ANTHROPIC_PATHS, &body).await;
        assert_eq!(out.count, 0);
        assert_eq!(out.body, body);
    }

    #[tokio::test]
    async fn disabled_config_is_passthrough() {
        let mut state = fixture_state();
        let mut cfg = RedactConfig::default();
        cfg.enabled = false;
        state.redact_config = Arc::new(cfg);
        let body = Bytes::from(format!(
            r#"{{"system":"key {}{}"}}"#,
            "ghp_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA01"
        ));
        let out = redact_outbound(&state, &ANTHROPIC_PATHS, &body).await;
        assert_eq!(out.count, 0);
        assert_eq!(out.body, body);
    }

    #[tokio::test]
    async fn multiple_secrets_in_one_string_all_replaced() {
        let state = fixture_state();
        let body = Bytes::from(format!(
            r#"{{"system":"a {}{} b {}{}"}}"#,
            "ghp_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA01", "AKIA", "IOSFODNN7EXAMPLE",
        ));
        let out = redact_outbound(&state, &ANTHROPIC_PATHS, &body).await;
        assert_eq!(out.count, 2);
        let text = std::str::from_utf8(&out.body).unwrap();
        assert!(text.contains(r#"<RELIX_SECRET kind=\"github_pat\""#));
        assert!(text.contains(r#"<RELIX_SECRET kind=\"aws_access_key\""#));
    }

    #[tokio::test]
    async fn vault_round_trip_yields_real_value_back() {
        // The whole point: insert via the proxy redact path,
        // then look up via the same vault and recover the real
        // value. This is the primitive the restore pass relies
        // on.
        let state = fixture_state();
        let real = format!("{}{}", "ghp_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA01");
        let body = Bytes::from(format!(r#"{{"system":"key {}"}}"#, real));
        let _ = redact_outbound(&state, &ANTHROPIC_PATHS, &body).await;

        // Derive the placeholder id directly from the real
        // value + the vault's salt — this is the same derivation
        // the redact path used. Look it up via the vault and
        // verify the round-trip.
        let id = relix_core::redact::placeholder::PlaceholderId::derive(&real, &state.vault.salt());
        let restored = state.vault.lookup(id).expect("vault hit");
        assert_eq!(restored.value, real);
    }
}
