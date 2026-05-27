# Contributing

This repository accepts contributions in three categories: detection
rules, engine code, and documentation. Each has a slightly different
process.

## Detection rules

Rules live under `rules/` as YAML files. They are grouped by
detection layer:

- `rules/ioc/` — known-bad infrastructure, shell patterns, package
  identifiers.
- `rules/ttp/` — tactic-level descriptions, including prompt-injection
  patterns.
- `rules/behavior/` — cross-call behavioral signatures (planned for
  v0.4; the directory is reserved).

Every rule must declare `id`, `name`, `severity`, `action`, and a
`matcher`. See the existing files in `rules/` for the schema.

A rule submission should also include:

- a `description` explaining the suspicious behavior,
- a `references` list with links to disclosure posts or incident
  reports, where applicable,
- `tags` for grouping,
- a regression test under `tests/` for regex-based matchers.

Rules describing a specific incident should cite the public source.
Rule submissions are reviewed for accuracy and false-positive risk.

## Engine code

For changes beyond bug fixes or formatting, open an issue first to
discuss the approach. The current architecture is deliberately small
and dependency-light.

Changes likely to be accepted:

- additional protocol parsers (OpenAI Chat Completions, Gemini),
- streaming SSE assembly for tool-use blocks,
- platform packaging (Homebrew, apt, dnf, scoop).

Changes that require prior discussion:

- new dependencies in `relix-core`, which is required to remain
  I/O-free and small,
- features that introduce network calls from the engine,
- features that log request or response bodies by default.

## Style

- Run `cargo fmt` and `cargo clippy --all-targets`.
- Provide tests for any change to matcher behavior.
- Commit messages follow the conventional style: `type: short
summary`, for example `feat: add openai protocol parser`.

## Contributor License Agreement

Code contributions require a signed Contributor License Agreement.
The CLA permits the project to relicense the contribution under
future OSI-approved open-source licenses and to grant additional
commercial licenses alongside the open-source license.

The CLA exists to keep license decisions correctable as the project
evolves. The full text is in [`CLA.md`](CLA.md). See
[`LICENSING.md`](LICENSING.md) for the rationale.

CLA signing is automated by the cla-assistant bot on the first pull
request from a contributor. Subsequent contributions do not require
re-signing.

## Security

Vulnerabilities should be reported privately. See [`SECURITY.md`](SECURITY.md).
