//! Upstream URL construction and inbound URI sanitisation.
//!
//! Implements RFC-0003 §H4. Every byte of the upstream URL is
//! either drawn from a trusted source (the `RELIX_UPSTREAM` we
//! parsed at start-up) or has passed through this module.
//!
//! Two layers of defence:
//!
//! 1. **Allow-list** of known LLM API paths. An unknown path falls
//!    through to the `passthrough` protocol which forwards bytes
//!    unchanged but still subjects the URI to the syntactic check
//!    in (2). Allow-listing is the strongest defence; even a flaw
//!    in (2) cannot reach the upstream API surface.
//!
//! 2. **Syntactic rejection** of dangerous bytes in the path:
//!    `..`, NUL, CR, LF, encoded slashes (`%2F`), and any unescaped
//!    control character. These appear in path-traversal,
//!    HTTP-smuggling, and log-injection attacks; none of them are
//!    valid in a legitimate LLM API request.
//!
//! Building the upstream URL itself goes through `Url::set_path`,
//! never string concatenation. `set_path` re-percent-encodes,
//! reuses the parsed authority, and refuses bytes the WHATWG URL
//! spec rejects.

use std::fmt;

use axum::http::Uri;
use url::Url;

/// LLM API request paths Relix actively understands.
///
/// Paths outside this list reach upstream only via the
/// `passthrough` protocol after passing the syntactic check. The
/// list is intentionally conservative; widen it explicitly when a
/// new endpoint is supported by a protocol adapter.
const ALLOWED_PROTOCOL_PATHS: &[&str] = &[
    // Anthropic Messages API
    "/v1/messages",
    "/v1/messages/count_tokens",
    // OpenAI Chat Completions / Completions
    "/v1/chat/completions",
    "/v1/completions",
    // OpenAI introspection (rarely streamed but commonly used)
    "/v1/models",
];

/// Reasons a request URI is rejected before the upstream is even
/// contacted.
///
/// Currently only [`UnsafePath`](Self::UnsafePath) is produced.
/// Additional variants are added when new rejection conditions
/// surface; they are not added speculatively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriRejection {
    /// The path contains a dangerous byte sequence (control char,
    /// `..`, encoded slash, NUL, CR, LF).
    UnsafePath,
}

impl fmt::Display for UriRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UriRejection::UnsafePath => f.write_str("unsafe path"),
        }
    }
}

impl std::error::Error for UriRejection {}

/// Outcome of looking up a request path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathDecision {
    /// Recognised LLM API path. Forward and inspect per the
    /// matching protocol.
    AllowedKnown,
    /// Path is syntactically clean but not in the allow-list.
    /// Forward via passthrough, no inspection.
    AllowedUnknown,
    /// Reject the request before contacting upstream.
    Reject(UriRejection),
}

/// Classify an inbound request path. The path here is the value
/// returned by `Uri::path()`, before percent-decoding.
pub fn classify_path(raw_path: &str) -> PathDecision {
    if !is_path_safe(raw_path) {
        return PathDecision::Reject(UriRejection::UnsafePath);
    }
    if ALLOWED_PROTOCOL_PATHS
        .iter()
        .any(|p| raw_path == *p || raw_path.starts_with(&format!("{p}/")))
    {
        PathDecision::AllowedKnown
    } else {
        PathDecision::AllowedUnknown
    }
}

/// Reject paths containing bytes that are valid HTTP but never
/// belong in an LLM API request URI.
///
/// Specifically refuses:
///
/// - `..` segments (path traversal),
/// - encoded forward slash `%2F` / `%2f` (smuggling),
/// - encoded dot `%2E` / `%2e` (path-traversal via double encoding;
///   one half of `%2e%2e` was previously not caught by the literal
///   `..` check),
/// - encoded backslash `%5C` / `%5c` (Windows path-equivalent
///   separator on upstreams that normalise to native paths),
/// - encoded NUL `%00`,
/// - any ASCII control character including NUL, CR, LF, TAB,
/// - any byte > 0x7E (non-printable ASCII; legitimate paths use
///   percent-encoding instead).
pub fn is_path_safe(raw_path: &str) -> bool {
    if raw_path.contains("..") {
        return false;
    }
    if raw_path.contains("%2F") || raw_path.contains("%2f") {
        return false;
    }
    if raw_path.contains("%2E") || raw_path.contains("%2e") {
        return false;
    }
    if raw_path.contains("%5C") || raw_path.contains("%5c") {
        return false;
    }
    if raw_path.contains("%00") {
        return false;
    }
    raw_path.bytes().all(|b| matches!(b, 0x21..=0x7E))
}

/// Build the upstream URL by combining a parsed `upstream_base` with
/// the inbound request URI. Uses `set_path` and `set_query` so the
/// result inherits the upstream's scheme, host, and port — string
/// concatenation is never used.
///
/// Returns `Err(UriRejection::UnsafePath)` when `is_path_safe`
/// rejects the inbound path. The caller is expected to check
/// [`classify_path`] first; this function repeats the check as a
/// defence-in-depth measure for any future call site that bypasses
/// the classifier.
pub fn build_upstream_url(upstream_base: &Url, client_uri: &Uri) -> Result<Url, UriRejection> {
    let path = client_uri.path();
    if !is_path_safe(path) {
        return Err(UriRejection::UnsafePath);
    }

    let mut url = upstream_base.clone();
    url.set_path(path);
    url.set_query(client_uri.query());
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Uri;
    use url::Url;

    fn upstream() -> Url {
        Url::parse("https://api.anthropic.com").unwrap()
    }

    #[test]
    fn path_safety_accepts_legitimate_paths() {
        assert!(is_path_safe("/v1/messages"));
        assert!(is_path_safe("/v1/chat/completions"));
        assert!(is_path_safe("/v1/messages/count_tokens"));
        assert!(is_path_safe(
            "/v1beta/models/gemini-1.5-pro:generateContent"
        ));
        assert!(is_path_safe("/anything?with=query")); // query is in raw_path
    }

    #[test]
    fn path_safety_rejects_dot_dot() {
        assert!(!is_path_safe("/v1/../etc/passwd"));
        assert!(!is_path_safe("/v1/messages/../admin"));
        assert!(!is_path_safe("/.."));
    }

    #[test]
    fn path_safety_rejects_encoded_slash() {
        assert!(!is_path_safe("/v1%2Fmessages"));
        assert!(!is_path_safe("/v1%2fmessages"));
    }

    #[test]
    fn rt_path_safety_rejects_encoded_dots() {
        // Red-team regression: `%2e%2e` decodes to `..`. Without the
        // `%2e` reject the literal `..` check is bypassed because the
        // raw path string only contains `%2e%2e`, never `..`.
        assert!(!is_path_safe("/v1/%2e%2e/etc/passwd"));
        assert!(!is_path_safe("/v1/%2E%2E/etc/passwd"));
        // Mixed case attackers also try.
        assert!(!is_path_safe("/v1/%2e./etc/passwd"));
    }

    #[test]
    fn rt_path_safety_rejects_encoded_backslash() {
        // Windows / WSL upstreams may normalise %5C ('\\') to a path
        // separator. Treat it the same as %2F.
        assert!(!is_path_safe("/v1%5Cmessages"));
        assert!(!is_path_safe("/v1%5cmessages"));
    }

    #[test]
    fn path_safety_rejects_nul() {
        assert!(!is_path_safe("/v1/messages%00.txt"));
    }

    #[test]
    fn path_safety_rejects_control_chars() {
        // CR
        assert!(!is_path_safe("/v1/mess\rages"));
        // LF
        assert!(!is_path_safe("/v1/mess\nages"));
        // TAB
        assert!(!is_path_safe("/v1/mess\tages"));
        // NUL
        assert!(!is_path_safe("/v1/mess\0ages"));
    }

    #[test]
    fn path_safety_rejects_high_bytes() {
        // Non-ASCII bytes must be percent-encoded.
        assert!(!is_path_safe("/v1/メッセージ"));
    }

    #[test]
    fn classify_recognises_known_paths() {
        assert_eq!(classify_path("/v1/messages"), PathDecision::AllowedKnown);
        assert_eq!(
            classify_path("/v1/chat/completions"),
            PathDecision::AllowedKnown
        );
        assert_eq!(
            classify_path("/v1/messages/count_tokens"),
            PathDecision::AllowedKnown
        );
    }

    #[test]
    fn classify_treats_unknown_as_unknown_not_rejected() {
        assert_eq!(
            classify_path("/v1beta/models/x:streamGenerateContent"),
            PathDecision::AllowedUnknown
        );
    }

    #[test]
    fn classify_rejects_unsafe() {
        assert_eq!(
            classify_path("/v1/../etc/passwd"),
            PathDecision::Reject(UriRejection::UnsafePath)
        );
    }

    #[test]
    fn build_url_uses_set_path_not_concat() {
        let uri: Uri = "/v1/messages?beta=cache".parse().unwrap();
        let built = build_upstream_url(&upstream(), &uri).unwrap();
        assert_eq!(built.scheme(), "https");
        assert_eq!(built.host_str(), Some("api.anthropic.com"));
        assert_eq!(built.path(), "/v1/messages");
        assert_eq!(built.query(), Some("beta=cache"));
    }

    #[test]
    fn build_url_preserves_upstream_with_trailing_slash() {
        // Construct an upstream that has a path itself (e.g. when
        // RELIX_UPSTREAM points at a routing prefix). `set_path`
        // replaces, not appends — that is the documented behaviour
        // and is what we want for transparent forwarding.
        let upstream_with_prefix = Url::parse("https://relay.example.com/").unwrap();
        let uri: Uri = "/v1/messages".parse().unwrap();
        let built = build_upstream_url(&upstream_with_prefix, &uri).unwrap();
        assert_eq!(built.path(), "/v1/messages");
    }

    #[test]
    fn build_url_rejects_unsafe_path_defence_in_depth() {
        let uri: Uri = "/v1/..%2fetc/passwd".parse().unwrap();
        let result = build_upstream_url(&upstream(), &uri);
        assert_eq!(result, Err(UriRejection::UnsafePath));
    }

    #[test]
    fn build_url_passes_through_subpaths_of_known_prefixes() {
        let uri: Uri = "/v1/messages/count_tokens?model=opus".parse().unwrap();
        let built = build_upstream_url(&upstream(), &uri).unwrap();
        assert_eq!(built.path(), "/v1/messages/count_tokens");
        assert_eq!(built.query(), Some("model=opus"));
    }
}
