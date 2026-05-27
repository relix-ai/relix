//! `relix-rules`: helpers for loading, validating, and subscribing to
//! Relix rule files. Most of the heavy lifting lives in `relix-core`;
//! this crate exists so we can later add network subscription and
//! signature verification without touching the engine.

pub use relix_core::{Rule, RuleAction, RuleSet, Severity};

/// Stable identifier for the bundled rule pack version.
pub const BUNDLED_VERSION: &str = env!("CARGO_PKG_VERSION");
