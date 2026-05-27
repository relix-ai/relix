//! Placeholder format and id derivation (RFC-0004).
//!
//! Wire format:
//!
//! ```text
//! <RELIX_SECRET kind="github_pat" id="o4f7a3">
//! ```
//!
//! - `kind` is the lowercase [`crate::redact::SecretKind`] label.
//! - `id` is `blake3(secret || salt)[..ID_BYTES]` as hex.
//!
//! Determinism: identical `(secret, salt)` always yields the
//! identical `id`, so the same real value reappearing in a
//! later turn picks up the same placeholder. The salt is
//! per-process random so placeholders are not cross-machine
//! predictable.

use std::fmt;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::redact::detector::SecretKind;

/// Length of the placeholder id in bytes (hex output is `2 *
/// ID_BYTES` chars long). 3 bytes = 6 hex chars gives 16.7M
/// distinct ids per kind, vastly larger than the LRU cap, so
/// collisions are not a concern at v0.3 scale.
pub const ID_BYTES: usize = 3;

/// Maximum total placeholder length when serialised. Used by
/// the streaming restore state machine to size its trailing
/// buffer. Held conservatively above the actual worst case.
pub const MAX_PLACEHOLDER_LEN: usize = 128;

/// Per-process random salt used in [`PlaceholderId::derive`].
/// 16 bytes from the OS RNG.
#[derive(Debug, Clone, Copy)]
pub struct Salt(pub [u8; 16]);

impl Salt {
    /// Generate a fresh salt from the OS RNG. Panics if the OS
    /// cannot supply randomness, which on Linux means the system
    /// is unusable and refusing to start is the right behaviour.
    pub fn fresh() -> Self {
        let mut buf = [0u8; 16];
        getrandom_compat(&mut buf);
        Self(buf)
    }

    /// Constant salt for tests. **Never use in production code.**
    #[cfg(test)]
    pub fn zero() -> Self {
        Self([0u8; 16])
    }
}

/// Tiny shim so we do not pull `getrandom` directly: blake3
/// already depends on it transitively. We re-export via this
/// helper so the dependency is local and test-overridable.
fn getrandom_compat(dst: &mut [u8]) {
    // We deliberately use std-only randomness: pick from
    // /dev/urandom on unix. blake3 ships a dependency anyway,
    // but for the salt we want zero extra deps.
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom for salt");
    f.read_exact(dst).expect("read /dev/urandom for salt");
}

/// Opaque placeholder id (the blake3-derived `[u8; ID_BYTES]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlaceholderId([u8; ID_BYTES]);

impl PlaceholderId {
    /// Derive the id from `(secret, salt)`. Pure function of its
    /// inputs, so equal arguments always produce equal ids.
    pub fn derive(secret: &str, salt: &Salt) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&salt.0);
        hasher.update(secret.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; ID_BYTES];
        out.copy_from_slice(&digest.as_bytes()[..ID_BYTES]);
        Self(out)
    }

    /// Lowercase hex rendering used in the wire format.
    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(ID_BYTES * 2);
        for b in self.0.iter() {
            use std::fmt::Write;
            write!(s, "{:02x}", b).unwrap();
        }
        s
    }

    /// Inverse of [`Self::hex`]. Returns `None` on length or
    /// non-hex input.
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != ID_BYTES * 2 {
            return None;
        }
        let mut out = [0u8; ID_BYTES];
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = hex_nibble(hex.as_bytes()[i * 2])?;
            let lo = hex_nibble(hex.as_bytes()[i * 2 + 1])?;
            *byte = (hi << 4) | lo;
        }
        Some(Self(out))
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    Some(match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => 10 + (b - b'a'),
        b'A'..=b'F' => 10 + (b - b'A'),
        _ => return None,
    })
}

/// A parsed or constructed placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder {
    pub kind: SecretKind,
    pub id: PlaceholderId,
}

impl Placeholder {
    pub fn new(kind: SecretKind, id: PlaceholderId) -> Self {
        Self { kind, id }
    }

    /// Wire form. Always serialises to the same canonical string
    /// for the same `(kind, id)`.
    pub fn render(&self) -> String {
        format!(
            "<RELIX_SECRET kind=\"{}\" id=\"{}\">",
            self.kind.label(),
            self.id.hex()
        )
    }

    /// Try to parse a single placeholder from the start of `s`.
    /// Returns the parsed placeholder and the number of bytes
    /// consumed. Returns `None` on no match.
    pub fn parse_prefix(s: &str) -> Option<(Self, usize)> {
        let caps = PLACEHOLDER_RE.captures(s)?;
        let whole = caps.get(0)?;
        if whole.start() != 0 {
            return None;
        }
        let kind = SecretKind::from_label(caps.name("kind")?.as_str())?;
        let id = PlaceholderId::from_hex(caps.name("id")?.as_str())?;
        Some((Placeholder { kind, id }, whole.end()))
    }

    /// Iterate over every placeholder in `s`, yielding `(byte_range,
    /// placeholder)`. Non-overlapping, left-to-right.
    pub fn find_all(s: &str) -> Vec<(std::ops::Range<usize>, Self)> {
        let mut out = Vec::new();
        for caps in PLACEHOLDER_RE.captures_iter(s) {
            let Some(whole) = caps.get(0) else { continue };
            let Some(kind_m) = caps.name("kind") else {
                continue;
            };
            let Some(id_m) = caps.name("id") else {
                continue;
            };
            let Some(kind) = SecretKind::from_label(kind_m.as_str()) else {
                continue;
            };
            let Some(id) = PlaceholderId::from_hex(id_m.as_str()) else {
                continue;
            };
            out.push((whole.start()..whole.end(), Placeholder { kind, id }));
        }
        out
    }
}

impl fmt::Display for Placeholder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Strict placeholder regex. Captures must agree with the
/// `render()` output exactly: angle brackets, fixed attribute
/// names, exact spacing, double-quoted values.
static PLACEHOLDER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<RELIX_SECRET kind="(?P<kind>[a-z_]+)" id="(?P<id>[0-9a-f]+)">"#).unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_uses_canonical_format() {
        let id = PlaceholderId::derive("hello", &Salt::zero());
        let p = Placeholder::new(SecretKind::GithubPat, id);
        let s = p.render();
        assert!(s.starts_with("<RELIX_SECRET kind=\"github_pat\" id=\""));
        assert!(s.ends_with("\">"));
        assert_eq!(
            s.len(),
            "<RELIX_SECRET kind=\"github_pat\" id=\"".len() + ID_BYTES * 2 + 2
        );
    }

    #[test]
    fn derive_is_deterministic_for_same_secret_and_salt() {
        let salt = Salt::zero();
        let a = PlaceholderId::derive("AKIAIOSFODNN7EXAMPLE", &salt);
        let b = PlaceholderId::derive("AKIAIOSFODNN7EXAMPLE", &salt);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_differs_for_different_salts() {
        let s1 = Salt([0u8; 16]);
        let s2 = Salt([1u8; 16]);
        let a = PlaceholderId::derive("same", &s1);
        let b = PlaceholderId::derive("same", &s2);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_differs_for_different_secrets() {
        let salt = Salt::zero();
        let a = PlaceholderId::derive("alpha", &salt);
        let b = PlaceholderId::derive("beta", &salt);
        assert_ne!(a, b);
    }

    #[test]
    fn parse_prefix_roundtrip() {
        let p = Placeholder::new(SecretKind::Jwt, PlaceholderId([0xab, 0xcd, 0xef]));
        let rendered = p.render();
        let (parsed, consumed) = Placeholder::parse_prefix(&rendered).expect("parse");
        assert_eq!(parsed, p);
        assert_eq!(consumed, rendered.len());
    }

    #[test]
    fn parse_prefix_rejects_unknown_kind() {
        let s = r#"<RELIX_SECRET kind="not_a_real_kind" id="abcdef">"#;
        assert!(Placeholder::parse_prefix(s).is_none());
    }

    #[test]
    fn parse_prefix_rejects_bad_id_length() {
        let s = r#"<RELIX_SECRET kind="github_pat" id="abc">"#;
        assert!(Placeholder::parse_prefix(s).is_none());
    }

    #[test]
    fn parse_prefix_rejects_non_hex_id() {
        let s = r#"<RELIX_SECRET kind="github_pat" id="xyzxyz">"#;
        assert!(Placeholder::parse_prefix(s).is_none());
    }

    #[test]
    fn find_all_returns_every_occurrence() {
        let p1 = Placeholder::new(SecretKind::GithubPat, PlaceholderId([1, 2, 3])).render();
        let p2 = Placeholder::new(SecretKind::Jwt, PlaceholderId([4, 5, 6])).render();
        let s = format!("Authorization: {p1} and JWT {p2} end");
        let hits = Placeholder::find_all(&s);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].1.kind, SecretKind::GithubPat);
        assert_eq!(hits[1].1.kind, SecretKind::Jwt);
    }

    #[test]
    fn find_all_ignores_malformed_lookalikes() {
        // Adjacent bytes, missing quotes, wrong attribute names.
        let s = r#"<RELIX_SECRET kind=github_pat id=abcdef>"#;
        assert!(Placeholder::find_all(s).is_empty());
    }

    #[test]
    fn placeholder_id_hex_roundtrip() {
        for (i, byte) in (0u8..=255).enumerate() {
            let id = PlaceholderId([byte, byte.wrapping_add(1), byte.wrapping_add(2)]);
            let hex = id.hex();
            let parsed = PlaceholderId::from_hex(&hex).unwrap();
            assert_eq!(parsed, id, "fail at byte {i}");
        }
    }

    #[test]
    fn rendered_length_never_exceeds_max() {
        // Worst-case kind label is currently `gcp_service_account` (19
        // chars). Render and verify under the cap.
        let p = Placeholder::new(
            SecretKind::GcpServiceAccount,
            PlaceholderId([0xff; ID_BYTES]),
        );
        assert!(p.render().len() <= MAX_PLACEHOLDER_LEN);
    }
}
