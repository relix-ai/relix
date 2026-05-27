# Security policy

## Reporting a vulnerability

Vulnerabilities should be reported through GitHub's private security
advisory channel:

https://github.com/relix-ai/relix/security/advisories/new

Reports should include:

- a description of the vulnerability,
- reproduction steps,
- the affected version or commit,
- the reporter's preferred attribution, if any.

Acknowledgement is targeted within 72 hours. Initial triage is
targeted within seven days. A dedicated `security@relix.dev` mailbox
will be provisioned alongside the public website; until then, the
GitHub advisory channel is the canonical reporting path.

Public issues should not be used for unfixed vulnerabilities.

## Scope

In scope:

- The Relix CLI and gateway (`relix-cli`).
- The detection engine (`relix-core`).
- The bundled rule set (`rules/`).
- Bypasses of detection by an actively malicious upstream.

Out of scope:

- Behavior of the upstream LLM API.
- Behavior of agents that consume Relix.
- The simulated `poisoned-relay` example, which is intentionally
  vulnerable for demonstration.

## Information requested during triage

The maintainers may request:

- Sanitized request and response payloads, with secrets redacted.
- The rule set and version that triggered or failed to trigger.
- Operating system and Relix version.

The maintainers will not request:

- API keys, tokens, or other secrets.
- Unredacted audit logs.
- Source code unrelated to the vulnerability.

## Disclosure

After a fix is shipped and an embargo period has elapsed (typically
90 days), a sanitized post-mortem may be published. Reporters who
wish to be credited will be acknowledged.
