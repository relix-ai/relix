# RFC-0001: Multi-protocol gateway architecture

| Field            | Value             |
| ---------------- | ----------------- |
| Status           | Draft             |
| Target milestone | v0.2              |
| Author           | Relix maintainers |
| Last updated     | 2026-05-27        |

## Summary

This RFC defines the architecture of the Relix gateway as it must
evolve to support inspection of streaming responses from multiple LLM
providers (Anthropic, OpenAI, Gemini) on a single local proxy. It is
the design reference for the v0.2 rewrite of `relix-cli/src/proxy.rs`
and `relix-core/src/protocol.rs`. The current v0.1 implementation
performs only non-streaming, Anthropic-only inspection and will be
replaced.

The design draws on three external references:

- **Anthropic Messages API** — protocol authority. SDKs released
  under MIT (Python, TypeScript) confirm the wire format used here.
- **LiteLLM** (MIT) — a survey of how a multi-protocol gateway
  organises adapter layers, streaming reassembly, and fallback.
- **Cloudflare Pingora** (Apache-2.0) — a study of an
  industrial-grade Rust reverse proxy. We do not adopt it as a
  dependency; we adopt its lifecycle abstraction.

Reasoning and code references for each are recorded in
[`learning-notes/`](../learning-notes/) sibling to this directory.

## Goals

1. Inspect streaming responses, not only buffered ones, with
   negligible added latency to the first byte the user sees.
2. Support Anthropic Messages, OpenAI Chat Completions, and Gemini
   `generateContent` simultaneously on the same proxy instance,
   selected per request by URL path.
3. Forward unmodified bytes when no rule matches and no protocol
   parsing is required, preserving streaming semantics end-to-end.
4. Keep the rule engine ignorant of HTTP and SSE; it operates on
   parsed protocol events.
5. Fail open: if inspection encounters an internal error, the
   request is forwarded unchanged and the failure is logged.

## Non-goals

- Cross-protocol translation (e.g. accepting OpenAI requests and
  forwarding to Anthropic upstream). LiteLLM does this; Relix does
  not need to.
- Provider-side fallback or load balancing. The user configures one
  upstream per agent.
- Streaming multiplexing at the HTTP/2 level. v0.2 supports HTTP/1.1
  and HTTP/2 client connections forwarded as HTTP/1.1 to the
  upstream.

## Architecture

### Layered model

```
┌──────────────────────────────────────────────────────────────────┐
│ Transport layer                                                  │
│   axum + hyper + rustls. Accepts agent traffic on a local port.  │
│   Forwards to upstream over rustls. Handles connection re-use,   │
│   timeouts, and back-pressure. No protocol awareness.            │
├──────────────────────────────────────────────────────────────────┤
│ Lifecycle layer                                                  │
│   Trait `LlmProxy` defines hook points modeled on Pingora's      │
│   `ProxyHttp`. The transport layer drives the trait; concrete    │
│   protocols implement it.                                        │
├──────────────────────────────────────────────────────────────────┤
│ Protocol layer                                                   │
│   One implementation per provider:                               │
│     - AnthropicProtocol  (Messages API + SSE)                    │
│     - OpenAiProtocol     (Chat Completions + SSE)                │
│     - GeminiProtocol     (generateContent + SSE)                 │
│   Each parses request/response into a common InspectionEvent.    │
├──────────────────────────────────────────────────────────────────┤
│ Inspection layer                                                 │
│   relix-core: rule engine sees only InspectionEvent. No I/O.     │
│   Existing in v0.1; preserved unchanged for v0.2 except for      │
│   adding a `Streaming` discriminator on tool_use events.         │
└──────────────────────────────────────────────────────────────────┘
```

### Lifecycle hooks (the `LlmProxy` trait)

Modeled on Pingora's `ProxyHttp`. The names and ordering are
identical so that future migration to Pingora is mechanical.

| Hook                       | When called                                  | Mutability               | Use in Relix                                                                                                                                             |
| -------------------------- | -------------------------------------------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `request_filter`           | After request fully read, before upstream    | async, may short-circuit | Outbound rule evaluation; system-prompt pattern checks. May return `block` to abort without contacting upstream.                                         |
| `upstream_request_filter`  | Just before sending to upstream              | async, mutable headers   | Strip hop-by-hop headers; rewrite `host`.                                                                                                                |
| `upstream_response_filter` | Upstream response headers received           | sync, mutable headers    | Detect `text/event-stream` and switch to streaming branch.                                                                                               |
| `response_body_filter`     | Each body chunk before being sent downstream | sync, mutable bytes      | Feed bytes to the protocol's stream parser; emit events to the rule engine. May rewrite a chunk into a synthetic block error if a rule fires mid-stream. |
| `fail_to_connect`          | Upstream connect failure                     | sync                     | Log and surface; v0.2 does not attempt fallback.                                                                                                         |
| `fail_to_proxy`            | Any other terminal error                     | async                    | Build a structured 502 `relix_proxy_error` body.                                                                                                         |
| `logging`                  | Request finished, success or error           | async                    | Append the inspection event and verdict to the audit log.                                                                                                |

The trait is defined in `relix-cli/src/proxy/lifecycle.rs`. The
existing `proxy_handler` is rewritten as the transport-layer driver
that calls these hooks in order.

### Protocol selection

Routing is done by URL path on the local listener. There is no
protocol auto-detection.

| Path prefix                                                                  | Protocol                                         |
| ---------------------------------------------------------------------------- | ------------------------------------------------ |
| `/v1/messages`                                                               | Anthropic                                        |
| `/v1/chat/completions`, `/v1/completions`, `/v1/responses`                   | OpenAI                                           |
| `/v1beta/models/*:streamGenerateContent`, `/v1beta/models/*:generateContent` | Gemini                                           |
| anything else                                                                | passthrough (no protocol parsing, no inspection) |

The `passthrough` branch exists so that an agent's auxiliary calls
(token-count endpoints, model-list endpoints) are forwarded
without crashing the parser. It is implemented as a
`PassthroughProtocol` whose `request_filter` always returns
`Allow` and whose body filter never inspects.

### Streaming inspection: the SSE pipeline

```
upstream bytes
    │
    ▼
┌──────────────────┐
│ SSE frame splitter (eventsource-stream-like, written by us)        │
│   Yields `(event_name, data_bytes)` pairs.                          │
└──────────────────┘
    │
    ▼
┌──────────────────┐
│ Protocol parser (one per provider)                                  │
│   Maintains per-block accumulator state.                             │
│   Emits high-level events:                                           │
│     - StreamStart { model }                                          │
│     - SystemPrompt(&str)                                             │
│     - ToolUseStart { index, id, name }                               │
│     - ToolUseInputDelta { index, partial_json }                      │
│     - ToolUseFinalised { index, name, input: serde_json::Value }     │
│     - StreamEnd { stop_reason, usage }                               │
└──────────────────┘
    │
    ▼
┌──────────────────┐
│ Rule engine                                                          │
│   Runs on `ToolUseFinalised` and on the request's outbound system    │
│   prompt. Tool-call rules never run on partial input.                │
└──────────────────┘
    │
    ▼
verdict ─► (a) Allow:  forward chunk unchanged
           (b) Warn:   forward chunk; record verdict
           (c) Block:  rewrite the in-flight tool_use block into an
                      `error` SSE event for the agent to consume,
                      then close the upstream connection
```

The crucial invariant comes from the Anthropic spec: a `tool_use`
block's `input` is **only complete at `content_block_stop`**.
Inspection runs at that point, never on a partial buffer. This
means the maximum inspection latency added to a streaming response
equals the time between `content_block_start` and
`content_block_stop` for the offending block — measured at the
upstream side, not added by Relix.

### Per-block accumulator (Anthropic)

Pseudocode:

```
state = HashMap<u32, BlockState>

on content_block_start(idx, cb):
    state[idx] = match cb.type:
        text       -> Text { buf: "" }
        tool_use   -> ToolUse { id: cb.id, name: cb.name, json_buf: "" }
        thinking   -> Thinking { buf: "", signature: None }
        _other     -> Pass

on content_block_delta(idx, delta):
    let s = state[idx]
    match (s, delta.type):
        (Text, text_delta)              -> s.buf.push_str(delta.text)
        (ToolUse, input_json_delta)     -> s.json_buf.push_str(delta.partial_json)
        (Thinking, thinking_delta)      -> s.buf.push_str(delta.thinking)
        (Thinking, signature_delta)     -> s.signature = Some(delta.signature)
        _                                -> drop silently (forward bytes unchanged)

on content_block_stop(idx):
    let s = state.remove(idx)
    if let ToolUse { name, json_buf, .. } = s:
        match serde_json::from_str(&json_buf):
            Ok(input)  -> emit ToolUseFinalised { idx, name, input }
            Err(_)     -> emit ToolUseFinalised { idx, name, input: Value::Null }
                          // rule engine treats null input as inert; FP cost low
```

OpenAI Chat Completions and Gemini `generateContent` use different
SSE shapes; their parsers normalise to the same event vocabulary.

### Failure handling

- Upstream connect failure → 502 with `x-relix-error: upstream-connect`.
- Upstream TLS failure → same.
- Upstream sends invalid SSE → forward unchanged, log a parse-error
  metric, do not block. (This is the fail-open property.)
- Rule regex compilation failure (during rule load) → rule is
  skipped at startup with a warning; never fails a request.
- Inspection panics → caught by tokio task isolation; the request
  forwards unchanged and the panic is logged.

### Audit log shape (unchanged in v0.2)

The jsonl record format is preserved from v0.1. Streaming adds one
field, `streaming: true`, to events generated from SSE chunks.
Bodies remain excluded.

## Embedding `relix-core` in third-party gateways

`relix-core` is the only public Rust API. Its surface is:

- `RuleSet` — load/parse YAML rules.
- `InspectionContext` — hold a parsed event plus optional system prompt.
- `evaluate(ruleset, ctx) -> Verdict` — pure function.

A third-party gateway (LiteLLM proxy, claude-code-router, custom
enterprise proxy) integrates by:

1. Parsing its own protocol into Relix's `InspectionEvent` shape.
2. Calling `evaluate`.
3. Acting on the `Verdict` (block, warn, log).

This integration is intentionally simple. The protocol parser is
the embedder's responsibility; we do not export ours from the core
crate. (Anthropic-specific parsing lives in `relix-cli`. If demand
appears, we extract it into a separate `relix-protocol` crate.)

## Why not adopt Pingora as a dependency

Pingora is the closest reference to what Relix is doing in Rust. We
considered it carefully and rejected it for v0.2:

- Pingora's optimisations target edge-scale traffic. Relix runs on
  developer laptops at single-digit QPS.
- Pingora's TLS backend is selected at compile time via mutually
  exclusive Cargo features. For a tool we need to ship to
  Mac/Linux/Windows, this is awkward.
- Pingora's `Server::run_forever()` is a blocking main loop. Relix
  needs to run a proxy plus an admin endpoint plus rule
  hot-reload, which axum + tower's `Router::merge` handles
  trivially.
- The lifecycle abstraction we want from Pingora can be reproduced
  in ~200 lines on top of axum. We are reproducing it.

If Relix ever becomes an edge-deployable SaaS, this decision is
reversible: the lifecycle hook trait keeps the same names, so most
implementations are mechanically portable.

## Why not adopt LiteLLM patterns wholesale

LiteLLM treats OpenAI Chat Completions as the canonical internal
representation and translates everything to and from it. This is
correct for a tool whose primary job is letting users talk to one
provider through another's SDK.

Relix is a proxy. It does not translate. The user picks one
provider per agent and the proxy preserves bytes wherever
possible. We borrow LiteLLM's ideas selectively:

- The shape of the streaming reassembly state machine, but not its
  flag-soup implementation; we use an explicit Rust enum.
- The notion of a `BaseConfig` per provider, expressed in Rust as
  the `Protocol` trait.
- The pass-through model where streaming bytes are forwarded
  unchanged and parsing happens on a side channel for
  inspection — Relix takes this further than LiteLLM by also
  rewriting in-band when a rule blocks.

## Compatibility with v0.1

The v0.1 release consists of:

- Buffer-the-whole-response Anthropic inspection in
  `crates/relix-cli/src/proxy.rs`.
- A non-streaming `AnthropicMessageResponse::tool_calls` helper.
- The rule engine in `relix-core::inspect`, which is unchanged
  by this RFC.

The v0.2 work plan is:

1. Introduce the `LlmProxy` trait and `Protocol` abstraction.
   Move Anthropic logic to `protocols/anthropic.rs`. Existing
   tests pass.
2. Implement the SSE frame splitter and the per-block accumulator
   for Anthropic. Add streaming integration tests using the
   `poisoned-relay` example.
3. Implement OpenAI Chat Completions parsing. Add fixture tests
   from real recorded streams (with secrets stripped).
4. Implement Gemini parsing. Same.
5. Replace `proxy_handler` with the lifecycle driver.
6. Remove the v0.1 buffered code path; ship v0.2.

Each step lands as a separate PR with an integration test.

## Open questions

- **Tool-name 64-character truncation when bridging to OpenAI**:
  the LiteLLM analysis shows OpenAI tool names cap at 64 chars and
  that LiteLLM hashes long names. Relix does not bridge protocols
  in v0.2, so this is moot — but it is the kind of detail a future
  bridge layer would have to solve.
- **HTTP/2 to upstream**: v0.2 forwards over HTTP/1.1. Anthropic
  accepts both. Whether to switch is a perf question for v0.3.
- **Per-block deadline**: should Relix time out a `tool_use` block
  whose `input_json_delta` stream stalls? Anthropic's docs say
  models emit "one complete key/value at a time", so genuine
  stalls are rare. Default decision: no timeout in v0.2; revisit
  if reports surface.

## References

- Anthropic Messages API: https://docs.anthropic.com/en/api/messages
- Anthropic streaming reference: https://docs.anthropic.com/en/api/messages-streaming
- anthropic-sdk-python (MIT): https://github.com/anthropics/anthropic-sdk-python
- anthropic-sdk-typescript (MIT): https://github.com/anthropics/anthropic-sdk-typescript
- LiteLLM (MIT): https://github.com/BerriAI/litellm
- Pingora (Apache-2.0): https://github.com/cloudflare/pingora
- Pingora user guide: https://github.com/cloudflare/pingora/tree/main/docs/user_guide
