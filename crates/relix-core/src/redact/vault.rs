//! Process-local secret vault (RFC-0004 §Vault).
//!
//! Maps [`PlaceholderId`] → real secret string, with:
//!
//! - **Memory hygiene**: real values wrapped in [`secrecy::Secret`]
//!   so they are zeroized on drop and never accidentally
//!   `Debug`-printed.
//! - **TTL eviction**: entries idle for longer than the configured
//!   TTL are removed by [`Vault::evict_expired`], which the
//!   integration layer schedules from a background task.
//! - **LRU eviction**: when capacity is exceeded, the
//!   least-recently-used entry is dropped (and a `tracing::warn`
//!   records the eviction so capacity pressure is visible).
//! - **No serialisation**: [`VaultEntry`] does not implement
//!   `Serialize`. New fields added to the vault cannot
//!   accidentally end up in the audit log.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use secrecy::{ExposeSecret, Secret};
use tokio::sync::RwLock;

use crate::redact::detector::SecretKind;
use crate::redact::placeholder::{Placeholder, PlaceholderId, Salt};

/// One vault entry. Owns the [`Secret`] string and carries
/// metadata needed for eviction. **Never** derive `Serialize` or
/// `Debug` here.
pub struct VaultEntry {
    secret: Secret<String>,
    kind: SecretKind,
    last_used: Instant,
}

impl VaultEntry {
    /// Borrow the real secret value. Callers are expected to use
    /// this *only* on the restore path inside the proxy. The
    /// return type is `&str` (not `Secret<String>`) on purpose:
    /// the caller will splice it into a `Bytes` buffer and the
    /// double indirection of forwarding `Secret` is unhelpful.
    pub fn expose(&self) -> &str {
        self.secret.expose_secret()
    }

    pub fn kind(&self) -> SecretKind {
        self.kind
    }
}

/// The vault itself. Cheap to clone (it wraps an `Arc`); the same
/// instance is shared across all request handlers.
#[derive(Clone)]
pub struct Vault {
    inner: Arc<RwLock<Inner>>,
    salt: Salt,
    cap: usize,
}

struct Inner {
    entries: HashMap<PlaceholderId, VaultEntry>,
}

impl Vault {
    /// Create a fresh vault with the given capacity. `cap` must
    /// be > 0 (see [`crate::redact::RedactConfig::validate`]).
    pub fn new(cap: usize, salt: Salt) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                entries: HashMap::new(),
            })),
            salt,
            cap,
        }
    }

    /// Convenience constructor that picks a fresh per-process salt.
    pub fn with_fresh_salt(cap: usize) -> Self {
        Self::new(cap, Salt::fresh())
    }

    /// Insert (or update `last_used` on an existing entry) and
    /// return the canonical placeholder. Idempotent: the same
    /// `(secret, kind)` always yields the same placeholder.
    ///
    /// On capacity overflow, the LRU entry is evicted and a
    /// `tracing::warn` is emitted.
    pub async fn insert(&self, secret: &str, kind: SecretKind) -> Placeholder {
        let id = PlaceholderId::derive(secret, &self.salt);
        let mut guard = self.inner.write().await;
        if let Some(existing) = guard.entries.get_mut(&id) {
            existing.last_used = Instant::now();
            return Placeholder::new(existing.kind, id);
        }
        if guard.entries.len() >= self.cap {
            evict_lru(&mut guard);
        }
        guard.entries.insert(
            id,
            VaultEntry {
                secret: Secret::new(secret.to_string()),
                kind,
                last_used: Instant::now(),
            },
        );
        Placeholder::new(kind, id)
    }

    /// Restore lookup. Updates `last_used` on hit so frequently
    /// referenced entries survive LRU pressure. Returns `None`
    /// on miss — the caller treats that as "leave the placeholder
    /// untouched and warn" (RFC-0004 S05 forged placeholder).
    pub async fn lookup(&self, id: PlaceholderId) -> Option<RestoredValue> {
        let mut guard = self.inner.write().await;
        let entry = guard.entries.get_mut(&id)?;
        entry.last_used = Instant::now();
        Some(RestoredValue {
            kind: entry.kind,
            value: entry.secret.expose_secret().clone(),
        })
    }

    /// Evict every entry whose `last_used` is older than `ttl`.
    /// Returns the number of evicted entries.
    pub async fn evict_expired(&self, ttl: std::time::Duration) -> usize {
        let now = Instant::now();
        let mut guard = self.inner.write().await;
        let before = guard.entries.len();
        guard
            .entries
            .retain(|_, e| now.duration_since(e.last_used) < ttl);
        before - guard.entries.len()
    }

    /// Number of live entries. For tests + diagnostics.
    pub async fn len(&self) -> usize {
        self.inner.read().await.entries.len()
    }

    /// Is the vault empty? Convenience for tests.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Borrow the per-process salt. Exposed so the integration
    /// layer (and tests) can derive a [`PlaceholderId`] from a
    /// known real value without going through the vault.
    pub fn salt(&self) -> Salt {
        self.salt
    }
}

/// The materialised restore result. We deliberately yield a
/// `String` (not `&str`) so the read lock can be released
/// immediately. The proxy splices it into the outbound buffer
/// and drops the `String` as soon as forwarding completes.
#[derive(Debug, Clone)]
pub struct RestoredValue {
    pub kind: SecretKind,
    pub value: String,
}

fn evict_lru(guard: &mut Inner) {
    let Some((victim_id, _)) = guard
        .entries
        .iter()
        .min_by_key(|(_, e)| e.last_used)
        .map(|(k, v)| (*k, v.last_used))
    else {
        return;
    };
    guard.entries.remove(&victim_id);
    tracing::warn!(
        "vault at capacity; evicted LRU entry (this should be rare; raise redact.vault_cap if frequent)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn insert_returns_deterministic_placeholder() {
        let v = Vault::new(16, Salt::zero());
        let a = v.insert("secret-A", SecretKind::OpenaiKey).await;
        let b = v.insert("secret-A", SecretKind::OpenaiKey).await;
        assert_eq!(a, b);
        assert_eq!(v.len().await, 1);
    }

    #[tokio::test]
    async fn lookup_round_trips_the_real_value() {
        let v = Vault::new(16, Salt::zero());
        let p = v.insert("the-real-secret", SecretKind::GithubPat).await;
        let restored = v.lookup(p.id).await.expect("lookup hit");
        assert_eq!(restored.value, "the-real-secret");
        assert_eq!(restored.kind, SecretKind::GithubPat);
    }

    #[tokio::test]
    async fn lookup_on_unknown_id_returns_none() {
        let v = Vault::new(16, Salt::zero());
        let nope = PlaceholderId::derive("never-inserted", &Salt::zero());
        assert!(v.lookup(nope).await.is_none());
    }

    #[tokio::test]
    async fn lru_eviction_when_cap_exceeded() {
        let v = Vault::new(2, Salt::zero());
        let p1 = v.insert("s1", SecretKind::Generic).await;
        let _p2 = v.insert("s2", SecretKind::Generic).await;
        // Touch p1 so p2 is the LRU.
        let _ = v.lookup(p1.id).await;
        // Force a third insert. p2 should be evicted.
        let _p3 = v.insert("s3", SecretKind::Generic).await;
        assert_eq!(v.len().await, 2);
        assert!(v.lookup(p1.id).await.is_some(), "p1 must still be present");
    }

    #[tokio::test]
    async fn evict_expired_removes_idle_entries() {
        let v = Vault::new(16, Salt::zero());
        let p = v.insert("idle", SecretKind::Generic).await;
        // Wait long enough that any nonzero TTL has elapsed.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let evicted = v.evict_expired(std::time::Duration::from_millis(1)).await;
        assert_eq!(evicted, 1);
        assert!(v.lookup(p.id).await.is_none());
    }

    #[tokio::test]
    async fn evict_expired_keeps_fresh_entries() {
        let v = Vault::new(16, Salt::zero());
        let p = v.insert("fresh", SecretKind::Generic).await;
        let evicted = v.evict_expired(std::time::Duration::from_secs(3600)).await;
        assert_eq!(evicted, 0);
        assert!(v.lookup(p.id).await.is_some());
    }

    #[tokio::test]
    async fn same_secret_different_kinds_collide_on_id_first_kind_wins() {
        // The id is derived purely from (secret, salt); the kind
        // is just metadata. The first insert wins on kind, the
        // second insert refreshes the entry but does not change
        // kind. This is RFC-0004 "idempotent on same secret".
        let v = Vault::new(16, Salt::zero());
        let p1 = v.insert("xxx", SecretKind::OpenaiKey).await;
        let p2 = v.insert("xxx", SecretKind::AnthropicKey).await;
        assert_eq!(p1.id, p2.id);
        let restored = v.lookup(p1.id).await.unwrap();
        assert_eq!(restored.kind, SecretKind::OpenaiKey);
    }
}
