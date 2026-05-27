//! Secret redaction & restore (RFC-0004).
//!
//! Public surface:
//!
//! - [`detector`]: regex + entropy detection, IO-free.
//! - [`placeholder`]: format / parse / blake3-derive
//!   `<RELIX_SECRET kind="..." id="...">` markers.
//! - [`vault`]: process-local store of placeholder → real secret,
//!   wrapped in [`secrecy::Secret`], TTL + LRU bounded.
//! - [`config`]: knobs that operators can tune.
//!
//! This module is IO-free. The integration layer that hooks it
//! into the proxy lives in `relix-cli::proxy::redact`.

pub mod config;
pub mod detector;
pub mod placeholder;
pub mod restore;
pub mod vault;

pub use config::RedactConfig;
pub use detector::{detect, Detection, SecretKind};
pub use placeholder::{Placeholder, PlaceholderId};
pub use restore::{StreamRestore, StreamRestoreStep};
pub use vault::Vault;
