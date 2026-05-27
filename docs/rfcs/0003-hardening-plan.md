# RFC-0003: Hardening plan

| Field            | Value              |
| ---------------- | ------------------ |
| Status           | Draft              |
| Target milestone | v0.2-step3 → v0.3  |
| Author           | Relix maintainers  |
| Last updated     | 2026-05-27         |
| References       | RFC-0001, RFC-0002 |

## Summary

This RFC consolidates the medium-priority items from the v0.2-step2
red-team self-audit into a single, ordered plan. Each item carries
an exact remediation derived from the engineering best-practices
study referenced below.

The five **High** items from the audit (A1, A3, A4, B5, C1) are
already shipped (`b6bf083`). The nine items here are **not**
release-blockers for v0.2-step3 but **must** ship before any v0.3
public announcement.

## Items

### H1 — Reqwest timeout configuration

**Problem.** The current upstream `reqwest::Client` is built with
`.timeout(Duration::from_secs(120))`. That is a hard end-to-end
deadline and will kill legitimate long streaming responses
(LLM streams can run 5+ minutes on long-form generation).
Conversely, no `read_timeout` means a slow-loris upstream emitting
one byte per minute will hold the connection forever.

**Resolution.** Replace the single `timeout` with a stacked
configuration:

```rust
reqwest::Client::builder()
    .connect_timeout(Duration::from_secs(10))
    // No total .timeout(): streaming runs may legitimately take
    // many minutes. Stalls are detected by per-read timeout.
    .read_timeout(Duration::from_secs(60))
    .pool_idle_timeout(Duration::from_secs(60))
    .pool_max_idle_per_host(32)
    .tcp_keepalive(Duration::from_secs(30))
    .http2_keep_alive_interval(Duration::from_secs(30))
    .http2_keep_alive_timeout(Duration::from_secs(10))
    .https_only(true)
    .build()
```

Non-streaming endpoints (`/v1/messages/count_tokens`) carry an
explicit `RequestBuilder::timeout(Duration::from_secs(60))`
override.

**File.** New `crates/relix-cli/src/proxy/client.rs` consolidates
client construction; `main.rs` calls into it.

### H2 — Audit log: bounded mpsc + single writer

**Problem.** Each streaming `tool_use` finalisation does
`tokio::spawn(async move { audit.record(...).await })`. Under a
malicious flood of micro `tool_use` blocks this spawns thousands
of tasks contending on the same `Arc<Mutex<File>>`.

**Resolution.** Replace the audit log with a bounded
`mpsc::channel(256)` plus a dedicated writer task. The hot
inspection path uses `try_send`. On full channel: do **not** drop
(a security tool must not lose audit trail) — fall back to a
blocking write on a `spawn_blocking` thread plus a counter and
warning. This applies backpressure precisely to attackers
generating audit pressure, while normal traffic remains
lock-free.

A supervisor in `main.rs` watches the writer's `JoinHandle`. If
the writer panics, the process shuts down (fail-closed: a security
audit tool with a dead audit log is mis-advertising itself).

**File.** Rewrite of `crates/relix-cli/src/audit.rs`.

### H3 — Tool name canonicalisation against homoglyphs

**Problem.** Rule matchers compare tool names as raw strings.
A poisoned upstream that emits `tool_use` with name `B\u{0430}sh`
(Cyrillic 'а' instead of Latin 'a') will not match a rule
written for `Bash`.

**Resolution.** Introduce
`relix-core::normalize::canonicalize(name: &str) -> String` that
applies, in order:

1. NFKC (Unicode compatibility composition).
2. ASCII case folding via `to_lowercase`.
3. UTS #39 confusables `skeleton()` (via the `unicode-security`
   crate) to map Cyrillic / Greek / mathematical look-alikes to
   their Latin originals.

Both the rule's declared name and the runtime tool name are
canonicalised before comparison. Original strings remain in audit
records — analysts must see the actual attack payload.

**Crate additions.** `unicode-normalization`, `unicode-security`.
Both are unicode-rs maintained, low-churn, no advisories.

**File.** New `crates/relix-core/src/normalize.rs`. Existing
matchers in `inspect.rs` switch to `canonicalize_eq(a, b)` for
name fields.

### H4 — URL sanitisation for upstream forwarding

**Problem.** The driver currently builds the upstream URL by
string concatenation:

```rust
let upstream_url = format!("{}{}", upstream.trim_end_matches('/'),
                            parts.uri.path_and_query()...);
```

A client request such as `GET /v1/messages/../../etc/passwd` is
forwarded path-and-all. `reqwest` will likely reject it, but the
resulting error path is uncomfortably late.

**Resolution.** Apply both an allow-list and an explicit
`url::Url::set_path` step. Allow-listed paths today:

- `/v1/messages`
- `/v1/messages/count_tokens`
- `/v1/chat/completions`
- `/v1/completions`

Unknown paths fall through to the passthrough adapter and reach
upstream **only if** the path passes a syntactic check (no `..`,
no `%00`, no `\r`, no `\n`, no `%2F`/`%2f`). Anything that fails
returns 400 and is recorded in the audit log.

**File.** New `crates/relix-cli/src/proxy/url.rs`.

### H5 — Per-stream hard deadline

**Problem.** Even with `read_timeout`, a streaming inspection
task could run indefinitely if the upstream maintains chunks at
exactly 59-second intervals. There is no upper bound.

**Resolution.** Wrap the streaming forward task in
`tokio::time::timeout(Duration::from_secs(15 * 60), …)`. Fifteen
minutes accommodates any plausible legitimate response length
while preventing socket holding indefinitely. On timeout, the
task emits an audit record (`stream_deadline_exceeded`) and
splices a synthetic block frame.

**File.** `crates/relix-cli/src/proxy/driver.rs::forward_streaming`.

### H6 — End-to-end test infrastructure

**Problem.** All 23 tests are unit-level. There is no
"real client → Relix → real upstream → block" coverage.

**Resolution.** New `tests/common/` module providing:

- `spawn_proxy(rules: RuleSet) -> SocketAddr` — boots Relix on
  a `127.0.0.1:0` random port and returns the address.
- `spawn_clean_upstream(handler: Fn) -> SocketAddr` — boots an
  in-process hyper server.
- `spawn_poisoned_upstream(payload: &[u8]) -> SocketAddr` —
  reuses the `examples/poisoned-relay/` handler.
- `golden_sse(name: &str) -> Vec<u8>` — loads recorded SSE byte
  traces from `tests/golden/`.

End-to-end test files cover each documented threat (T01-T13),
each compatibility relay, and each red-team regression at the
HTTP layer.

**Note.** The engineering best-practices study flagged that
`wiremock = "0.6"` may not handle byte-level streaming timing
control; if so, fall back to a hand-rolled hyper mock. This is
implementation-time research, not blocking the RFC.

### H7 — Outbound `messages` inspection

**Problem.** The current Anthropic adapter inspects only the
top-level `system` field on outbound requests. `messages[]`
entries — including `tool_result` blocks where the user's prior
tool output is fed back to the model — pass through uninspected.
A user who has already been compromised by a poisoned tool
output could re-feed the malicious instruction into the next
turn.

**Resolution.** Outbound inspection extended to walk
`messages[].content[]` and surface text content from any block
type (`text`, `tool_result`, `tool_use`) to a new
`Matcher::OutboundMessageRegex` rule type. Existing `Matcher`
variants are unchanged.

**File.** `crates/relix-core/src/rules.rs` (new matcher),
`crates/relix-cli/src/proxy/protocols/anthropic.rs` (extraction
in `request_filter`), `rules.yaml` schema documentation update.

### H8 — Audit-log structural privacy guarantee

**Problem.** Today the audit record type contains only the
`InspectionEvent` and `Verdict`, neither of which carry prompt
content. A future maintainer adding a `matched_text` field to
`Verdict` for debuggability would silently begin writing prompt
fragments to disk, breaking the project's stated privacy
contract.

**Resolution.** Add a `#[deny(missing_redaction_attribute)]`
clippy lint **or**, more practically, mark `Verdict` and
`InspectionEvent` `#[non_exhaustive]` and require new
serialisable fields to use a `#[serde(skip_serializing_if = ...)]`
explicit redaction attribute. The Apache-2.0-licensed
`relix-core` crate will document this in its module-level
comments. Privacy is enforced by the type system, not by
convention.

**File.** `crates/relix-core/src/inspect.rs`,
`crates/relix-core/src/model.rs`.

### H9 — Per-chunk size cap

**Problem.** `reqwest::Response::bytes_stream()` may yield
arbitrary-sized chunks. A malicious upstream that sends a
single 1 GB chunk over chunked transfer encoding would force the
SSE decoder buffer to grow to 1 GB before the existing 1 MiB cap
kicks in (the cap is checked once per `next_frame` call; one
push of 1 GB still allocates).

**Resolution.** In `forward_streaming`, slice incoming chunks
into ≤ 64 KiB pieces before feeding them to the assembler. The
cap is enforced eagerly. This also reduces tail latency for
inspection on legitimate fragmented streams.

**File.** `crates/relix-cli/src/proxy/driver.rs::forward_streaming`.

## Sequencing

| Item | Phase | Rationale                                                    |
| ---- | ----- | ------------------------------------------------------------ |
| H1   | step3 | Required before recommending Relix for any non-trivial use.  |
| H4   | step3 | Cheap, stops a class of bypass before OpenAI ships.          |
| H6   | step3 | Tests written alongside step3 protocol code, not after.      |
| H2   | step3 | Audit pressure is a real DoS vector once OpenAI scope opens. |
| H9   | step3 | Cheap; finishes the streaming hardening story.               |
| H3   | step4 | Needs accompanying rule-format documentation update.         |
| H5   | step4 | Lower priority; rare in practice.                            |
| H7   | step4 | Requires new `Matcher` variant; bigger surface change.       |
| H8   | step4 | Codifies an existing invariant; no behaviour change.         |

step3 thus carries five hardening items alongside the OpenAI
protocol work. step4 picks up the rest. v0.3 ships as a coherent
package: streaming inspection across three protocols + the full
hardening matrix + the rule subscription feed.

## Non-goals

This RFC does not:

- Define rule-versioning or signature semantics for the threat
  intelligence corpus. That is the subject of a future RFC-0004.
- Specify a `Llama-Guard`-based semantic layer. v0.5 work.
- Mandate any specific test-coverage threshold beyond "every
  threat in the model has at least one regression".
