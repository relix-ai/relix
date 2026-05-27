use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Permit the request, but emit an audit event.
    Log,
    /// Permit, but inject a system warning back to the agent.
    Warn,
    /// Reject. Return an error response to the agent.
    Block,
}

/// Where in the LLM traffic the rule looks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Matcher {
    /// Match if the upstream host equals or matches a domain pattern.
    UpstreamHost { domain: String },

    /// Match a tool_call by name (exact) plus an optional substring inside
    /// the JSON-serialized tool input.
    ToolCall {
        name: String,
        #[serde(default)]
        input_contains: Vec<String>,
    },

    /// Regex match against the JSON-serialized tool input.
    ToolInputRegex {
        name: Option<String>,
        pattern: String,
    },

    /// Substring/regex match against the system prompt portion of the
    /// outbound request payload.
    SystemPromptRegex { pattern: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    pub action: RuleAction,
    pub matcher: Matcher,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let parsed: RuleSet = serde_yaml::from_str(yaml)?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn merge(&mut self, other: RuleSet) {
        self.rules.extend(other.rules);
    }

    fn validate(&self) -> Result<()> {
        let mut seen: HashMap<&str, ()> = HashMap::new();
        for rule in &self.rules {
            if seen.insert(rule.id.as_str(), ()).is_some() {
                return Err(Error::InvalidRule(format!(
                    "duplicate rule id: {}",
                    rule.id
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_ruleset() {
        let yaml = r#"
rules:
  - id: relix.test.001
    name: Block uname
    severity: low
    action: block
    matcher:
      kind: tool_call
      name: Bash
      input_contains: ["uname"]
"#;
        let rs = RuleSet::from_yaml(yaml).unwrap();
        assert_eq!(rs.rules.len(), 1);
        assert_eq!(rs.rules[0].id, "relix.test.001");
    }

    #[test]
    fn rejects_duplicate_ids() {
        let yaml = r#"
rules:
  - id: relix.x
    name: a
    severity: low
    action: log
    matcher: { kind: upstream_host, domain: example.com }
  - id: relix.x
    name: b
    severity: low
    action: log
    matcher: { kind: upstream_host, domain: other.com }
"#;
        assert!(RuleSet::from_yaml(yaml).is_err());
    }
}
