//! Redaction subsystem configuration (RFC-0004 §Configuration).
//!
//! Defaults track the production profile described in the RFC.
//! Operators override via:
//!
//! - `RELIX_REDACT_*` environment variables (numeric / bool fields),
//! - `relix.toml` (parsed in the CLI; this crate is IO-free and
//!   only owns the data structure + env decoding).
//!
//! Environment names use uppercase `RELIX_REDACT_<FIELD>` matching
//! the field name verbatim (`vault_ttl_secs` → `RELIX_REDACT_VAULT_TTL_SECS`).

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::redact::detector::DetectorConfig;

/// Top-level redaction config.
///
/// All knobs have sensible defaults. The CLI loads this struct
/// from `relix.toml` and then applies environment overrides via
/// [`Self::apply_env`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedactConfig {
    /// Master switch. When `false`, the proxy skips both redaction
    /// and restore. Disabling is logged as a warning at startup.
    pub enabled: bool,

    /// Idle TTL (seconds) for a single vault entry. The background
    /// eviction task removes entries whose `last_used` is older than
    /// this. Default 24h.
    pub vault_ttl_secs: u64,

    /// Maximum number of live vault entries. On overflow, LRU
    /// eviction kicks in and a `tracing::warn` records each
    /// eviction so capacity pressure is visible. Default 10000.
    pub vault_cap: usize,

    /// Shannon entropy threshold for the fallback layer. `0.0`
    /// disables the entropy fallback entirely. Default 4.0.
    pub entropy_threshold: f64,

    /// Minimum string length (chars) before the entropy fallback
    /// considers a candidate. Default 32.
    pub min_entropy_len: usize,

    /// When `true`, an upstream response whose body contains a
    /// literal real secret value triggers a mid-stream block via
    /// the existing inspection lifecycle. Default `true`.
    pub block_on_upstream_leak: bool,

    /// Paths to extra user-supplied detection rules. Reserved for
    /// v0.4; ignored in v0.3.
    pub rule_files: Vec<String>,
}

impl Default for RedactConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            vault_ttl_secs: 86_400,
            vault_cap: 10_000,
            entropy_threshold: 4.0,
            min_entropy_len: 32,
            block_on_upstream_leak: true,
            rule_files: Vec::new(),
        }
    }
}

impl RedactConfig {
    /// Validate the config. Returns an error for nonsensical
    /// values that would otherwise produce surprising runtime
    /// behaviour.
    pub fn validate(&self) -> Result<(), String> {
        if self.vault_cap == 0 {
            return Err("redact.vault_cap must be > 0".into());
        }
        if self.entropy_threshold < 0.0 {
            return Err("redact.entropy_threshold must be >= 0".into());
        }
        if !self.entropy_threshold.is_finite() {
            return Err("redact.entropy_threshold must be finite".into());
        }
        Ok(())
    }

    /// Apply environment-variable overrides. Each variable is
    /// optional. Parse errors are returned, never silently
    /// ignored — a typo in `RELIX_REDACT_VAULT_TTL_SECS=abc`
    /// should fail startup, not silently default.
    pub fn apply_env(&mut self) -> Result<(), String> {
        if let Some(v) = read_env_bool("RELIX_REDACT_ENABLED")? {
            self.enabled = v;
        }
        if let Some(v) = read_env_u64("RELIX_REDACT_VAULT_TTL_SECS")? {
            self.vault_ttl_secs = v;
        }
        if let Some(v) = read_env_usize("RELIX_REDACT_VAULT_CAP")? {
            self.vault_cap = v;
        }
        if let Some(v) = read_env_f64("RELIX_REDACT_ENTROPY_THRESHOLD")? {
            self.entropy_threshold = v;
        }
        if let Some(v) = read_env_usize("RELIX_REDACT_MIN_ENTROPY_LEN")? {
            self.min_entropy_len = v;
        }
        if let Some(v) = read_env_bool("RELIX_REDACT_BLOCK_ON_UPSTREAM_LEAK")? {
            self.block_on_upstream_leak = v;
        }
        self.validate()
    }

    /// TTL as a `Duration`. Saturates at `Duration::MAX`.
    pub fn vault_ttl(&self) -> Duration {
        Duration::from_secs(self.vault_ttl_secs)
    }

    /// Build a [`DetectorConfig`] view over the detection knobs.
    /// The detector module owns its own struct so it can be used
    /// standalone in tests without depending on the whole
    /// `RedactConfig`.
    pub fn detector(&self) -> DetectorConfig {
        DetectorConfig {
            entropy_threshold: self.entropy_threshold,
            min_entropy_len: self.min_entropy_len,
        }
    }
}

fn read_env_str(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(s) => Some(s),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => None,
    }
}

fn read_env_bool(name: &str) -> Result<Option<bool>, String> {
    let Some(s) = read_env_str(name) else {
        return Ok(None);
    };
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        other => Err(format!("{name}: expected bool, got {other:?}")),
    }
}

fn read_env_u64(name: &str) -> Result<Option<u64>, String> {
    let Some(s) = read_env_str(name) else {
        return Ok(None);
    };
    s.parse::<u64>()
        .map(Some)
        .map_err(|e| format!("{name}: {e}"))
}

fn read_env_usize(name: &str) -> Result<Option<usize>, String> {
    let Some(s) = read_env_str(name) else {
        return Ok(None);
    };
    s.parse::<usize>()
        .map(Some)
        .map_err(|e| format!("{name}: {e}"))
}

fn read_env_f64(name: &str) -> Result<Option<f64>, String> {
    let Some(s) = read_env_str(name) else {
        return Ok(None);
    };
    s.parse::<f64>()
        .map(Some)
        .map_err(|e| format!("{name}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_rfc() {
        let c = RedactConfig::default();
        assert!(c.enabled);
        assert_eq!(c.vault_ttl_secs, 86_400);
        assert_eq!(c.vault_cap, 10_000);
        assert_eq!(c.entropy_threshold, 4.0);
        assert_eq!(c.min_entropy_len, 32);
        assert!(c.block_on_upstream_leak);
        assert!(c.rule_files.is_empty());
    }

    #[test]
    fn validate_rejects_zero_cap() {
        let mut c = RedactConfig::default();
        c.vault_cap = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_negative_entropy() {
        let mut c = RedactConfig::default();
        c.entropy_threshold = -1.0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_nan_entropy() {
        let mut c = RedactConfig::default();
        c.entropy_threshold = f64::NAN;
        assert!(c.validate().is_err());
    }

    #[test]
    fn detector_view_reflects_top_level_knobs() {
        let mut c = RedactConfig::default();
        c.entropy_threshold = 5.5;
        c.min_entropy_len = 40;
        let d = c.detector();
        assert_eq!(d.entropy_threshold, 5.5);
        assert_eq!(d.min_entropy_len, 40);
    }
}
