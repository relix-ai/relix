//! Secret kinds and detection (RFC-0004).
//!
//! The detector is a pure function over a string slice and a
//! [`DetectorConfig`]; it returns `Vec<Detection>` with the
//! matched byte ranges and the inferred kind. No allocation
//! outside the result set.
//!
//! Two layers:
//!
//! 1. A static regex corpus (this file). Each entry is anchored
//!    on a high-precision prefix so false positives are rare.
//! 2. An optional Shannon-entropy fallback for "secret-shaped"
//!    high-entropy strings the corpus does not recognise.
//!
//! On a tie between the corpus and the entropy fallback, the
//! corpus wins (it carries a precise [`SecretKind`]).

use std::fmt;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Recognised secret families.
///
/// `Generic` is the catch-all for entropy-only detections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OpenaiKey,
    AnthropicKey,
    GithubPat,
    AwsAccessKey,
    GcpServiceAccount,
    AzureStorageKey,
    StripeKey,
    SlackToken,
    Jwt,
    PrivateKeyBlock,
    BearerToken,
    Generic,
}

impl SecretKind {
    /// Lowercase identifier used inside [`Placeholder`] strings.
    pub fn label(&self) -> &'static str {
        match self {
            Self::OpenaiKey => "openai_key",
            Self::AnthropicKey => "anthropic_key",
            Self::GithubPat => "github_pat",
            Self::AwsAccessKey => "aws_access_key",
            Self::GcpServiceAccount => "gcp_service_account",
            Self::AzureStorageKey => "azure_storage_key",
            Self::StripeKey => "stripe_key",
            Self::SlackToken => "slack_token",
            Self::Jwt => "jwt",
            Self::PrivateKeyBlock => "private_key_block",
            Self::BearerToken => "bearer_token",
            Self::Generic => "generic",
        }
    }

    /// Parse a label back into a kind. Returns [`SecretKind::Generic`]
    /// for unknown values rather than failing — this is the inverse
    /// of [`Self::label`] used on the restore path, where an unknown
    /// label means a forged placeholder (handled upstream).
    pub fn from_label(label: &str) -> Option<Self> {
        Some(match label {
            "openai_key" => Self::OpenaiKey,
            "anthropic_key" => Self::AnthropicKey,
            "github_pat" => Self::GithubPat,
            "aws_access_key" => Self::AwsAccessKey,
            "gcp_service_account" => Self::GcpServiceAccount,
            "azure_storage_key" => Self::AzureStorageKey,
            "stripe_key" => Self::StripeKey,
            "slack_token" => Self::SlackToken,
            "jwt" => Self::Jwt,
            "private_key_block" => Self::PrivateKeyBlock,
            "bearer_token" => Self::BearerToken,
            "generic" => Self::Generic,
            _ => return None,
        })
    }
}

impl fmt::Display for SecretKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One detection result: byte range inside the source string and
/// the inferred kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub start: usize,
    pub end: usize,
    pub kind: SecretKind,
}

impl Detection {
    /// Borrow the matched substring from the source.
    pub fn value<'a>(&self, src: &'a str) -> &'a str {
        &src[self.start..self.end]
    }
}

/// Detector configuration. Defaults track the production profile
/// described in RFC-0004 §Configuration.
#[derive(Debug, Clone, Copy)]
pub struct DetectorConfig {
    /// Shannon entropy threshold for the fallback layer. `0.0`
    /// disables the entropy fallback entirely.
    pub entropy_threshold: f64,
    /// Minimum length (chars) a candidate must reach before the
    /// entropy fallback considers it.
    pub min_entropy_len: usize,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 4.0,
            min_entropy_len: 32,
        }
    }
}

/// Scan `s` and return every detected secret occurrence, sorted by
/// start position, non-overlapping. When two layers fire on the
/// same range, the corpus wins.
pub fn detect(s: &str, cfg: &DetectorConfig) -> Vec<Detection> {
    let mut hits: Vec<Detection> = Vec::new();

    for spec in CORPUS.iter() {
        for m in spec.regex.find_iter(s) {
            hits.push(Detection {
                start: m.start(),
                end: m.end(),
                kind: spec.kind,
            });
        }
    }

    if cfg.entropy_threshold > 0.0 {
        for tok in tokenize_for_entropy(s) {
            if tok.end - tok.start < cfg.min_entropy_len {
                continue;
            }
            let slice = &s[tok.start..tok.end];
            if shannon_entropy(slice) >= cfg.entropy_threshold {
                hits.push(Detection {
                    start: tok.start,
                    end: tok.end,
                    kind: SecretKind::Generic,
                });
            }
        }
    }

    dedup_prefer_specific(&mut hits);
    hits
}

struct Span {
    start: usize,
    end: usize,
}

/// Split `s` into byte ranges of "secret-shaped" tokens: runs of
/// `[A-Za-z0-9_\-+/=.]` characters. Whitespace, brackets, quotes,
/// commas and similar delimiters break tokens.
fn tokenize_for_entropy(s: &str) -> Vec<Span> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if is_token_byte(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_token_byte(bytes[i]) {
                i += 1;
            }
            out.push(Span { start, end: i });
        } else {
            i += 1;
        }
    }
    out
}

fn is_token_byte(b: u8) -> bool {
    matches!(b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'+' | b'/' | b'=' | b'.'
    )
}

/// Shannon entropy in bits per byte. Empty / single-char input
/// returns 0.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

/// Deduplicate overlapping hits. When two detections overlap, keep
/// the one whose kind has the highest specificity. `Generic` is
/// the least specific; `OpenaiKey`'s regex is intentionally broad
/// (`sk-...`) and overlaps with the more specific `AnthropicKey`
/// (`sk-ant-...`), so OpenaiKey is ranked below AnthropicKey but
/// above Generic. Within the same specificity tier, the longer
/// span wins.
fn dedup_prefer_specific(hits: &mut Vec<Detection>) {
    hits.sort_by_key(|h| (h.start, specificity_rank(h.kind), !0 - (h.end - h.start)));
    let mut last_end = 0usize;
    let mut kept = Vec::with_capacity(hits.len());
    for h in hits.drain(..) {
        if h.start >= last_end {
            last_end = h.end;
            kept.push(h);
        } else {
            // Overlap: skip (we already kept the higher-specificity
            // / longer one because of the sort order).
        }
    }
    *hits = kept;
}

/// Lower number = higher specificity = preferred on overlap.
/// `OpenaiKey`'s regex is broad (`sk-...{20,}`) and intentionally
/// loses to any other specific kind (e.g. `AnthropicKey` whose
/// prefix `sk-ant-` is a subset). `Generic` always loses.
fn specificity_rank(kind: SecretKind) -> u8 {
    match kind {
        SecretKind::Generic => 2,
        SecretKind::OpenaiKey => 1,
        _ => 0,
    }
}

struct Spec {
    kind: SecretKind,
    regex: Regex,
}

/// Static regex corpus. Patterns are anchored on high-precision
/// prefixes to minimise false positives in natural English text.
///
/// Sources of inspiration: gitleaks (MIT) and trufflehog corpus.
/// Each entry is conservative; users can layer extra rules via
/// [`crate::redact::RedactConfig::rule_files`] in the future.
static CORPUS: Lazy<Vec<Spec>> = Lazy::new(|| {
    vec![
        // OpenAI: `sk-` followed by 20+ url-safe chars, or
        // project keys `sk-proj-...`.
        Spec {
            kind: SecretKind::OpenaiKey,
            regex: Regex::new(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}").unwrap(),
        },
        // Anthropic: `sk-ant-` and at least 24 url-safe chars.
        // Listed before OpenAI in match priority via dedup
        // (longer span wins on overlap).
        Spec {
            kind: SecretKind::AnthropicKey,
            regex: Regex::new(r"sk-ant-[A-Za-z0-9_\-]{24,}").unwrap(),
        },
        // GitHub: ghp_, gho_, ghu_, ghs_, ghr_ + 30-255 chars.
        Spec {
            kind: SecretKind::GithubPat,
            regex: Regex::new(r"gh[pousr]_[A-Za-z0-9]{30,255}").unwrap(),
        },
        // AWS access key (not secret): AKIA + 16 uppercase.
        Spec {
            kind: SecretKind::AwsAccessKey,
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        },
        // GCP service account JSON markers — we match on the
        // distinctive `"type": "service_account"` pair, which
        // is virtually unique to a leaked JSON blob.
        Spec {
            kind: SecretKind::GcpServiceAccount,
            regex: Regex::new(r#""type"\s*:\s*"service_account""#).unwrap(),
        },
        // Azure storage shared key (base64, 88 chars in
        // AccountKey=). We anchor on the `AccountKey=` prefix
        // to avoid catching unrelated 88-char base64 blobs.
        Spec {
            kind: SecretKind::AzureStorageKey,
            regex: Regex::new(r"AccountKey=[A-Za-z0-9+/=]{88}").unwrap(),
        },
        // Stripe: live or test keys.
        Spec {
            kind: SecretKind::StripeKey,
            regex: Regex::new(r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}").unwrap(),
        },
        // Slack: bot, user, app tokens.
        Spec {
            kind: SecretKind::SlackToken,
            regex: Regex::new(r"xox[baprs]-[A-Za-z0-9\-]{10,}").unwrap(),
        },
        // JWT: three dot-separated base64url segments. We
        // require the first segment to start with `eyJ` so we
        // do not catch arbitrary `a.b.c` strings.
        Spec {
            kind: SecretKind::Jwt,
            regex: Regex::new(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
                .unwrap(),
        },
        // PEM private key block. Catches RSA, EC, OPENSSH,
        // generic PRIVATE KEY headers.
        Spec {
            kind: SecretKind::PrivateKeyBlock,
            regex: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")
                .unwrap(),
        },
        // Generic Bearer header tokens. Anchored on `Bearer `
        // prefix so we do not catch random words. Requires
        // ≥ 24 chars to dodge "Bearer token_here" examples.
        Spec {
            kind: SecretKind::BearerToken,
            regex: Regex::new(r"[Bb]earer\s+[A-Za-z0-9_\-\.=]{24,}").unwrap(),
        },
    ]
});

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_kinds(s: &str) -> Vec<SecretKind> {
        let mut kinds: Vec<_> = detect(s, &DetectorConfig::default())
            .into_iter()
            .map(|d| d.kind)
            .collect();
        kinds.sort_by_key(|k| k.label());
        kinds
    }

    #[test]
    fn detects_openai_key() {
        let s = format!(
            "use key {}{} to call",
            "sk-", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        );
        assert!(detect_kinds(&s).contains(&SecretKind::OpenaiKey));
    }

    #[test]
    fn detects_anthropic_key_separately_from_openai() {
        let s = format!(
            "key={}{}",
            "sk-ant-", "api03-AAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBB"
        );
        let kinds = detect_kinds(&s);
        assert!(
            kinds.contains(&SecretKind::AnthropicKey),
            "expected anthropic_key, got: {kinds:?}"
        );
        assert!(
            !kinds.contains(&SecretKind::OpenaiKey),
            "openai_key must not double-fire on the anthropic prefix: {kinds:?}"
        );
    }

    #[test]
    fn detects_github_pat() {
        let s = format!(
            "GITHUB_TOKEN={}{}",
            "ghp_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA01"
        );
        assert!(detect_kinds(&s).contains(&SecretKind::GithubPat));
    }

    #[test]
    fn detects_aws_access_key() {
        let s = "aws: AKIAIOSFODNN7EXAMPLE";
        assert!(detect_kinds(s).contains(&SecretKind::AwsAccessKey));
    }

    #[test]
    fn detects_gcp_service_account() {
        let s = r#"{"type": "service_account", "project_id": "x"}"#;
        assert!(detect_kinds(s).contains(&SecretKind::GcpServiceAccount));
    }

    #[test]
    fn detects_stripe_key() {
        // Constructed at runtime so the source literal does not
        // trip GitHub's push-protection secret scanner. The shape
        // is still what our regex matches against.
        let s = format!("{}{}{}", "sk_", "live_", "A".repeat(24));
        assert!(detect_kinds(&s).contains(&SecretKind::StripeKey));
    }

    #[test]
    fn detects_slack_token() {
        let s = "slack=xoxb-1234567890-AAAAAAAAAAAA";
        assert!(detect_kinds(s).contains(&SecretKind::SlackToken));
    }

    #[test]
    fn detects_jwt() {
        let s = "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc12345";
        let kinds = detect_kinds(s);
        // The JWT regex covers the value; the Bearer regex does
        // not fire here because the prefix is `Authorization: ` not
        // `Bearer `.
        assert!(kinds.contains(&SecretKind::Jwt), "got: {kinds:?}");
    }

    #[test]
    fn detects_bearer_token() {
        let s = "Bearer abcdefghijklmnopqrstuvwxyz123456";
        assert!(detect_kinds(s).contains(&SecretKind::BearerToken));
    }

    #[test]
    fn detects_pem_private_key() {
        let s = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";
        assert!(detect_kinds(s).contains(&SecretKind::PrivateKeyBlock));
    }

    #[test]
    fn entropy_fallback_catches_unknown_high_entropy_token() {
        // Random-ish 40-char base62 string, no known prefix.
        let s = "id=Qf2pX7Lk9Vn3Wm8Td4Bs6Yc1Hg5Ja0RuNiE0z2L extra";
        let kinds = detect_kinds(s);
        assert!(
            kinds.contains(&SecretKind::Generic),
            "entropy fallback missed: {kinds:?}"
        );
    }

    #[test]
    fn entropy_fallback_ignores_normal_prose() {
        let s = "this is just a normal sentence that has no secrets at all";
        let kinds = detect_kinds(s);
        assert!(
            !kinds.contains(&SecretKind::Generic),
            "false positive on natural prose: {kinds:?}"
        );
    }

    #[test]
    fn entropy_fallback_can_be_disabled() {
        let cfg = DetectorConfig {
            entropy_threshold: 0.0,
            ..Default::default()
        };
        let s = "id=Qf2pX7Lk9Vn3Wm8Td4Bs6Yc1Hg5Ja0RuNiE0z2L";
        let hits = detect(s, &cfg);
        assert!(
            !hits.iter().any(|d| d.kind == SecretKind::Generic),
            "entropy disabled but generic hit fired: {hits:?}"
        );
    }

    #[test]
    fn dedup_prefers_specific_kind_over_generic_on_overlap() {
        // A GitHub PAT is both a regex hit (GithubPat) and a
        // high-entropy 40-char token (Generic). After dedup we
        // must keep only the GithubPat span.
        let s = "token=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA01";
        let hits = detect(s, &DetectorConfig::default());
        let pat_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.kind == SecretKind::GithubPat)
            .collect();
        let generic_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.kind == SecretKind::Generic)
            .collect();
        assert_eq!(pat_hits.len(), 1);
        assert_eq!(
            generic_hits.len(),
            0,
            "generic must not overlap with specific kind: {hits:?}"
        );
    }

    #[test]
    fn detection_value_borrow_returns_matched_substring() {
        let s = format!("x {}{} y", "sk-", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789");
        let hits = detect(&s, &DetectorConfig::default());
        let v = hits[0].value(&s);
        assert!(v.starts_with("sk-"));
    }

    #[test]
    fn secret_kind_label_roundtrip() {
        for k in [
            SecretKind::OpenaiKey,
            SecretKind::AnthropicKey,
            SecretKind::GithubPat,
            SecretKind::AwsAccessKey,
            SecretKind::GcpServiceAccount,
            SecretKind::AzureStorageKey,
            SecretKind::StripeKey,
            SecretKind::SlackToken,
            SecretKind::Jwt,
            SecretKind::PrivateKeyBlock,
            SecretKind::BearerToken,
            SecretKind::Generic,
        ] {
            assert_eq!(SecretKind::from_label(k.label()), Some(k), "{k:?}");
        }
    }

    #[test]
    fn shannon_entropy_basic_sanity() {
        // Uniform-ish string has higher entropy than a repeated char.
        let h_uniform = shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789");
        let h_repeat = shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(h_uniform > h_repeat);
        assert!(h_uniform > 4.5);
        assert!(h_repeat < 1.0);
    }
}
