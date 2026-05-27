# Relix design notes

This document records the goals, constraints, and architectural
choices of the Relix project. It is the reference for "why does
Relix work the way it does"; mechanics and usage live in the
[`README`](README.md), and license design lives in
[`LICENSING.md`](LICENSING.md).

## Problem

AI coding agents (Claude Code, Cursor, Codex, Cline, Aider, Continue,
and similar tools) execute shell commands, edit source files, and
install packages under user authority. Many of these agents are
configurable to use a third-party HTTPS endpoint in place of the
official LLM API. Common reasons include cost arbitrage, regional
availability, and account aggregation.

Such a third-party endpoint:

- terminates TLS in front of the model provider
- can read every request and rewrite every response
- is generally not subject to independent security review
- is not visible to the agent or to any tool the user already runs

A compromised endpoint can therefore cause the agent to perform
actions the user did not request — for example, by injecting a
`tool_use` block into a model response that instructs the agent to
read a credential file and exfiltrate it. The agent has no signal to
distinguish such an instruction from a legitimate one.

Existing defenses do not cover this position:

- Shell hooks observe only the finalized command line, after the
  malicious tool invocation has been committed to.
- Static analyzers scan installed components, not network traffic.
- Per-agent runtime hooks are scoped to one agent and do not
  generalize across the surface.

Relix targets this gap by inspecting traffic on the wire between the
agent and the LLM API.

## Goals

1. Inspect every request and response between agent and LLM API,
   including streaming responses.
2. Block tool invocations and prompt manipulations that match
   community-maintained detection rules, before the agent acts.
3. Operate as a local proxy: a single static binary, no daemons,
   no telemetry, no required network calls beyond LLM upstream.
4. Provide a stable, embeddable detection engine that other
   gateways can adopt as a library.
5. Maintain the threat-intelligence rule set as a public,
   community-licensed corpus, separable from the engine.

## Non-goals

- Replacing shell hooks, sandboxes, or static scanners. Relix is
  one layer in a defense-in-depth stack.
- Defending against attacks that bypass the configured base URL,
  including agents that hard-code an endpoint.
- Defending against vulnerabilities in the LLM model itself.
- Detecting all prompt-injection variants. The rule set covers
  documented patterns; a model-based semantic layer is scheduled
  for a later milestone.

## Operational principles

These principles constrain the implementation. They are intended to
be checked at code review, not asserted in marketing material.

- **Local-first.** No network call originates from Relix to any
  destination other than the configured LLM upstream. No telemetry
  is collected. No phone-home behavior exists by default and none
  is planned.
- **Body opacity.** Audit logs record inspection events and verdicts.
  Request and response bodies are never written to the audit log.
- **Failure mode is forwarding.** When inspection fails internally
  (parse error, regex compilation failure, unknown protocol),
  traffic is forwarded unchanged and the failure is recorded. The
  proxy never fails closed in a way that breaks the user's
  workflow.
- **Cross-agent compatibility.** Any agent that accepts a custom
  base URL for an OpenAI-compatible or Anthropic-compatible API
  is in scope. Per-agent integrations are not required for the
  proxy to function.

## License design

The repository uses a multi-license structure: the engine is
Apache-2.0, the gateway binary is AGPL-3.0-or-later, the threat
intelligence rule set is CC-BY-SA-4.0. Reasoning is in
[`LICENSING.md`](LICENSING.md).

The structure is intended to allow embedding in other projects while
preventing the gateway product itself from being repackaged into a
closed, hosted service.

## References

- [Sigma](https://github.com/SigmaHQ/sigma) — community-maintained SIEM detection rules
- [MITRE ATT&CK](https://attack.mitre.org/) — tactic and technique taxonomy
- [Anthropic Messages API](https://docs.anthropic.com/en/api/messages) — protocol reference
- [OpenAI Chat Completions API](https://platform.openai.com/docs/api-reference/chat) — protocol reference
