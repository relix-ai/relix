<h1 align="center">Relix</h1>

<p align="center">
  A local security gateway for AI coding agents.
</p>

<p align="center">
  <a href="LICENSE-AGPL"><img alt="CLI license" src="https://img.shields.io/badge/cli-AGPL--3.0-1f6feb.svg" /></a>
  <a href="LICENSE-APACHE"><img alt="Core license" src="https://img.shields.io/badge/core-Apache--2.0-1f6feb.svg" /></a>
  <a href="rules/LICENSE"><img alt="Rules license" src="https://img.shields.io/badge/rules-CC--BY--SA--4.0-1f6feb.svg" /></a>
  <a href="https://www.rust-lang.org"><img alt="Rust" src="https://img.shields.io/badge/rust-1.78%2B-dea584.svg" /></a>
  <a href="https://github.com/relix-ai/relix/releases"><img alt="Status" src="https://img.shields.io/badge/status-pre--release-orange.svg" /></a>
</p>

<p align="center">
  <a href="https://github.com/relix-ai/relix/discussions">Discussions</a> ·
  <a href="MANIFESTO.md">Design notes</a> ·
  <a href="LICENSING.md">Licensing</a> ·
  <a href="#chinese-summary">中文</a>
</p>

---

## Overview

Relix is a local proxy that mediates traffic between an AI coding
agent and the LLM API it depends on. It parses each request and
response, evaluates them against a configured rule set, and blocks
tool invocations that match known attack patterns before the agent
acts on them.

The intended deployment is the developer's own machine. The proxy
listens on a local port, the agent's `*_BASE_URL` is redirected to
that port, and traffic is forwarded over rustls to the configured
upstream.

## Threat model

Relix targets the threats listed below. Other threats are out of
scope for v0.

| ID  | Threat                                                         | Detection layer          |
| --- | -------------------------------------------------------------- | ------------------------ |
| T01 | Compromised third-party API relay rewriting model responses    | Response inspection      |
| T02 | Adversarial system prompt injected by an upstream proxy        | Request inspection       |
| T03 | Tool-call payload exfiltrating credentials                     | Rule engine (tool_input) |
| T04 | Tool-call payload running pipe-to-shell installers             | Rule engine (tool_input) |
| T05 | Reverse-shell tool invocations                                 | Rule engine (tool_input) |
| T06 | Cross-call patterns (read sensitive file, then exfiltrate) [*] | Behavioral correlation   |
| T07 | Misrouted `*_BASE_URL` pointing at a known-bad host            | Upstream-host rule       |

[*] Not yet implemented in v0.1; scheduled for v0.4.

Out of scope:

- Local code Relix did not originate (file edits made by the user,
  by CI, or by a non-LLM tool).
- Attacks that bypass the configured base URL, including agents that
  hard-code an endpoint.
- Vulnerabilities in the LLM model itself.

## Architecture

```
┌─────────────────────┐     ┌────────────────────────────────────┐     ┌──────────────────┐
│                     │     │             Relix gateway          │     │                  │
│   AI coding agent   │     │                                    │     │  LLM API         │
│   (Claude Code,     ├────►│  ┌──────────┐    ┌──────────────┐  ├────►│  (Anthropic,     │
│    Cursor, Codex,   │ TLS │  │ Protocol │───►│  Rule engine │  │ TLS │   OpenAI,        │
│    Cline, …)        │     │  │ parser   │    │  evaluator   │  │     │   Gemini, …)     │
│                     │     │  └────┬─────┘    └──────┬───────┘  │     │                  │
└─────────────────────┘     │       │ event           │ verdict   │     └──────────────────┘
                            │       ▼                 ▼          │
                            │  ┌─────────────────────────────┐   │
                            │  │  jsonl audit log (local;    │   │
                            │  │  request and response       │   │
                            │  │  bodies are not recorded)   │   │
                            │  └─────────────────────────────┘   │
                            └────────────────────────────────────┘
```

The gateway is a single static binary. v0.1 performs structured
inspection on non-streaming responses; SSE assembly is on the v0.2
milestone.

`relix-core` is dependency-light, I/O-free, and intended to be
embeddable in third-party gateways. The Apache-2.0 license on the
engine is intentional; see [`LICENSING.md`](LICENSING.md).

## Getting started

### Requirements

- Rust 1.78 or newer (binary releases are not yet published).
- macOS, Linux, or Windows.
- An LLM API endpoint the agent normally talks to.

### Build

```sh
git clone https://github.com/relix-ai/relix
cd relix
cargo build --release
```

The resulting binary is at `target/release/relix`.

### Run

```sh
relix start \
  --port 7777 \
  --upstream https://api.anthropic.com \
  --rules ./rules \
  --audit ~/.relix/audit.jsonl
```

All flags also read from environment variables: `RELIX_PORT`,
`RELIX_UPSTREAM`, `RELIX_RULES`, `RELIX_AUDIT`.

### Redirecting an agent

| Agent       | Configuration                                                    |
| ----------- | ---------------------------------------------------------------- |
| Claude Code | `export ANTHROPIC_BASE_URL=http://localhost:7777`                |
| Cursor      | Settings → Models → OpenAI Base URL → `http://localhost:7777/v1` |
| Codex CLI   | `export OPENAI_BASE_URL=http://localhost:7777/v1`                |
| Cline       | Provider config → Custom base URL                                |
| Continue    | `~/.continue/config.json` → model `apiBase`                      |
| Aider       | `aider --openai-api-base http://localhost:7777/v1`               |

The proxy forwards traffic unchanged when no rule matches, so any
agent that accepts a custom base URL for an OpenAI-compatible or
Anthropic-compatible endpoint should function. Per-agent integration
testing for v0.1 is incomplete; please file an issue if a specific
tool misbehaves.

### Verifying a block

A simulated compromised upstream is included for testing. It returns
a fabricated `tool_use` instructing the agent to read
`~/.ssh/id_rsa`.

```sh
# Terminal 1: the simulated compromised upstream
cargo run -p poisoned-relay
# binds to 127.0.0.1:9999

# Terminal 2: Relix in front of it
relix start --upstream http://127.0.0.1:9999

# Terminal 3: any LLM client
curl -s -X POST http://127.0.0.1:7777/v1/messages \
     -H 'content-type: application/json' \
     -d '{}'
```

The expected response is HTTP `403`, with the header
`x-relix-blocked: 1` and a body identifying the rule that matched
(for example, `relix.bash.read-private-key`).

### Audit log

```sh
relix logs --audit ~/.relix/audit.jsonl
jq 'select(.verdict.decision.block)' ~/.relix/audit.jsonl
```

The audit log records inspection events and verdicts. Request and
response bodies are not written to it.

## Repository layout

```
crates/
  relix-core/      Detection engine. Pure Rust, no I/O. Apache-2.0.
  relix-cli/       Gateway binary built on axum and rustls. AGPL-3.0.
  relix-rules/     Rule loading and (planned) signed feed support.

examples/
  poisoned-relay/  Reference compromised upstream used in tests and demos.

rules/
  ioc/             Observed bad infrastructure and shell patterns.
  ttp/             Tactic-level descriptions (prompt-injection styles).
  behavior/        Cross-call behavioral signatures (planned).

docs/              Documentation source (CC-BY-4.0).
```

## Adjacent tools

Relix is one layer in a defense-in-depth stack. The table below
records the position of each layer.

| Layer                  | Examples                            | Position              | Visibility                                |
| ---------------------- | ----------------------------------- | --------------------- | ----------------------------------------- |
| API gateway            | Relix                               | Between agent and LLM | Each request and response, every tool_use |
| Shell hook             | Tirith, claude-code-safety-net      | Between agent and OS  | Finalized shell command lines             |
| Per-agent runtime hook | Lasso hooks, Anthropic native hooks | Inside a single agent | tool_use JSON for that agent              |
| Static scanner         | Snyk agent-scan, Cisco mcp-scanner  | Filesystem            | Installed MCPs, skills, configurations    |
| Sandbox                | microsandbox, gVisor                | Operating system      | Side effects of executed commands         |

## Project status

This is a v0 release. Interfaces and rule schemas may change.
Suitable for individual developer use and security research; not yet
recommended for unattended production traffic.

| Concern                | Status                                                          |
| ---------------------- | --------------------------------------------------------------- |
| Anthropic Messages API | Non-streaming inspection in v0.1; streaming planned for v0.2    |
| OpenAI Chat API        | Forwarded; structured inspection planned                        |
| Gemini API             | Forwarded; structured inspection planned                        |
| Rule schema            | Stable for `tool_call`, `upstream_host`, regex matchers         |
| Audit log format       | Stable jsonl; field set may grow but not shrink                 |
| CLI flags              | Stable                                                          |
| Bundled rules in v0.1  | 7 rules (5 exfiltration, 2 prompt-injection patterns)           |
| Performance            | Target sub-5 ms overhead on clean requests; not yet benchmarked |

A benchmark harness is planned for v0.2.

## Roadmap

| Milestone | Theme                  | Highlights                                                                  |
| --------- | ---------------------- | --------------------------------------------------------------------------- |
| v0.1      | Foundation             | Transparent gateway, non-streaming inspection, initial rule pack, audit log |
| v0.2      | Streaming              | Anthropic SSE assembly, OpenAI streaming, Gemini parser, benchmark harness  |
| v0.3      | Threat-intel ecosystem | Signed rule subscription feed, community rule contribution flow             |
| v0.4      | Behavioral correlation | Cross-call pattern detection                                                |
| v0.5      | Optional ML inspection | Llama-Guard 3 1B integration as opt-in semantic layer                       |
| v1.0      | Production hardening   | Forensic timeline, rollback of agent edits, formal stability guarantees     |

## License

The repository uses a multi-license structure. The complete table
and reasoning are in [`LICENSING.md`](LICENSING.md).

| Component                                   | License           |
| ------------------------------------------- | ----------------- |
| `crates/relix-core/`, `crates/relix-rules/` | Apache-2.0        |
| `crates/relix-cli/`                         | AGPL-3.0-or-later |
| `rules/`                                    | CC-BY-SA-4.0      |
| `examples/`                                 | MIT               |
| `docs/`                                     | CC-BY-4.0         |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Code contributions require
a signed [Contributor License Agreement](CLA.md).

## Security

Vulnerabilities should be reported through GitHub's private advisory
channel. See [`SECURITY.md`](SECURITY.md).

---

<a id="chinese-summary"></a>

## 中文摘要

Relix 是一个本地代理,部署在 AI 编程助手与 LLM API 之间,对每条请求和响应进行结构化解析,根据可配置的规则集判定放行、警告或拦截,目的是阻止被第三方中转 API 注入到响应中的恶意 `tool_use`。

完整说明、安装方式、威胁模型、规则贡献流程见上方英文章节及
[`MANIFESTO.md`](MANIFESTO.md) / [`LICENSING.md`](LICENSING.md)。

社区交流:[GitHub Discussions](https://github.com/relix-ai/relix/discussions)。
漏洞披露:[GitHub Security Advisories](https://github.com/relix-ai/relix/security/advisories/new)。
