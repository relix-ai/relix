use std::path::Path;

use anyhow::{Context, Result};
use relix_core::RuleSet;
use tracing::info;

/// Load all `*.yaml` / `*.yml` files under `path` into a single RuleSet.
/// If `path` is a single file, just load it.
pub fn load_rules(path: &Path) -> Result<RuleSet> {
    if !path.exists() {
        // It's fine to start with no rules — pass-through proxy mode.
        info!(path = %path.display(), "rules path does not exist, starting with empty ruleset");
        return Ok(RuleSet::default());
    }

    let mut combined = RuleSet::default();
    if path.is_file() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("read rules file {}", path.display()))?;
        let rs = RuleSet::from_yaml(&content)
            .with_context(|| format!("parse rules file {}", path.display()))?;
        combined.merge(rs);
        return Ok(combined);
    }

    // Recursively collect yaml files.
    let mut entries: Vec<_> = walkdir(path)?
        .into_iter()
        .filter(|p| matches!(p.extension().and_then(|s| s.to_str()), Some("yaml" | "yml")))
        .collect();
    entries.sort();
    for file in entries {
        let content =
            std::fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
        match RuleSet::from_yaml(&content) {
            Ok(rs) => combined.merge(rs),
            Err(err) => {
                tracing::warn!(file = %file.display(), error = %err, "skip invalid rules file");
            }
        }
    }
    info!(count = combined.rules.len(), "loaded rules");
    Ok(combined)
}

fn walkdir(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("read dir {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}

pub fn expand_tilde(s: &str) -> std::path::PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).join(rest);
        }
    }
    std::path::PathBuf::from(s)
}
