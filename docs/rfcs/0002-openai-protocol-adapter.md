# RFC-0002: OpenAI protocol adapter

| Field            | Value             |
| ---------------- | ----------------- |
| Status           | Draft             |
| Target milestone | v0.2 (step 3)     |
| Author           | Relix maintainers |
| Last updated     | 2026-05-27        |
| References       | RFC-0001          |

## Summary

Defines how Relix terminates and inspects OpenAI Chat Completions
traffic, in the same gateway process that already handles Anthropic
Messages. The adapter follows the [`LlmProxy`](../../crates/relix-cli/src/proxy/lifecycle.rs)
trait introduced in RFC-0001, reusing the lifecycle hooks and the
streaming pipeline.

In scope for v0.2-step3:

- `POST /v1/chat/completions` (the `Chat Completions` API).
- `POST /v1/completions` (legacy completions).
- Streaming responses (`text/event-stream`) and buffered responses
  (`application/json`).
- Inbound system-prompt extraction from `messages[role:"system"]`.
- Inbound `tool_calls` and legacy `function_call` normalization.
- Outbound `tool_calls` reassembly across `delta.tool_calls[].function.arguments`
  fragments.

Explicitly out of scope for v0.2:

- The new `/v1/responses` (Responses API). It uses a different SSE
  shape with 50+ named events; its surface is large and most agent
  ecosystems do not yet target it. Scheduled for v0.4.
- Cross-protocol translation (Anthropic ↔ OpenAI). Translation
  loses inspection signal at the protocol boundary
  (`cache_control`, `tool_use` indices, etc.); we leave it to
  upstream tools (LiteLLM, claude-code-router) and remain a
  protocol-faithful auditor.

## Threat model additions

T01-T07 from RFC-0001 transfer unchanged. Specific OpenAI-shaped
attacks we must still detect:

| ID  | Threat                                                                 |
| --- | ---------------------------------------------------------------------- |
| T08 | Mid-stream `delta.content` injection of system-style prompt            |
| T09 | Tampered `tool_calls[].function.arguments` carrying malicious commands |
| T10 | Substituted `tool_calls[].function.name` redirecting to a riskier tool |
| T11 | Pre-`[DONE]` extra chunks (billing inflation, hidden continuation)     |
| T12 | Forged `finish_reason=stop` to truncate sensitive output               |
| T13 | Poisoned `delta.reasoning_content` (DeepSeek/智谱 chain-of-thought)    |

The adapter's responsibility is to surface enough structured signal
that the rule engine can express each of these.

## Wire format reference

### SSE shape

OpenAI streams use **`data:`-only** frames, no `event:` line, with
either `\n\n`, `\r\r`, or `\r\n\r\n` between frames. Comment lines
(starting with `:`) MUST be discarded. Some compatibility relays
(notably OpenRouter, anecdotally) interleave `: ...` keepalive
comments; ignoring them is required for clean parsing.

The terminating sentinel is the literal `data: [DONE]`. The
official Python SDK uses `sse.data.startswith("[DONE]")`, so
implementations should be tolerant of `[DONE]` with any trailing
content (whitespace, fragments).

### Chunk payload

```jsonc
{
  "id": "chatcmpl-...",
  "object": "chat.completion.chunk",
  "created": 1730000000,
  "model": "gpt-4o-2024-...",
  "choices": [
    {
      "index": 0,
      "delta": {
        "role": "assistant",
        "content": "...",
        "tool_calls": [
          {
            "index": 0,
            "id": "call_xyz",
            "type": "function",
            "function": { "name": "Bash", "arguments": "{\"co" },
          },
        ],
        "function_call": { "name": "...", "arguments": "..." }, // legacy
        "refusal": "...", // o-series
      },
      "finish_reason": null,
    },
  ],
  "usage": null,
}
```

### `tool_calls` reassembly invariants

- The join key is `(choice.index, tool_call.index)`. Both are
  required across chunks.
- `id`, `type`, and `function.name` are typically present only on
  the first chunk of a given tool call. Implementations must accept
  them on any chunk and treat repeats as idempotent overwrites.
  Some compatibility relays delay or repeat them.
- `function.arguments` is concatenated as raw bytes across chunks
  with no JSON boundary guarantee. Parsing is only safe after
  `finish_reason="tool_calls"` (or `"function_call"`) is observed
  for the same `choice.index`.
- After `finish_reason` is set on a choice, that choice's deltas
  are complete; subsequent chunks for that choice should be
  treated as a protocol violation and surfaced as a parse error.

### Completion signals

| `finish_reason`  | Meaning                                                     |
| ---------------- | ----------------------------------------------------------- |
| `stop`           | Natural completion                                          |
| `length`         | Hit `max_tokens`                                            |
| `tool_calls`     | Model is calling tools; reassembled args are now valid JSON |
| `function_call`  | Legacy equivalent of `tool_calls`                           |
| `content_filter` | Filtered by upstream policy                                 |

The frame carrying `finish_reason` typically has an empty `delta`.
The implementation must not treat that as a separate inspection
event.

### Optional usage chunk

When the request includes `stream_options: {"include_usage": true}`,
one additional chunk arrives **before** `[DONE]` carrying
`choices: []` and a populated `usage`. We forward it unchanged but
do not derive inspection events from it.

## Differences from Anthropic adapter

| Concern            | Anthropic                                                      | OpenAI                                                                                 |
| ------------------ | -------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| SSE event line     | `event: <type>` required                                       | absent; `data:`-only                                                                   |
| Frame discriminant | `event:` and JSON `type` cross-checked (RFC-0001 hardening A1) | JSON `object` and `choices[].finish_reason` only                                       |
| Tool-call boundary | `content_block_stop`                                           | `finish_reason` on the parent choice                                                   |
| Tool-call key      | `index` (block index)                                          | `(choice.index, tool_call.index)`                                                      |
| Argument fragment  | `delta.partial_json`                                           | `delta.tool_calls[].function.arguments`                                                |
| System prompt      | top-level `system` field (string or array)                     | `messages[role:"system"]` (or `developer` in newer specs)                              |
| Tool definition    | `tools: [{name, description, input_schema}]`                   | `tools: [{type:"function", function:{name, description, parameters}}]`                 |
| Tool-result role   | `user` message with `tool_result` block                        | `tool` message with `tool_call_id`                                                     |
| `max_tokens`       | required                                                       | optional                                                                               |
| Chain-of-thought   | `thinking` content block                                       | non-standard `delta.reasoning_content` (DeepSeek/智谱); `reasoning` items in Responses |

## Adapter design

### Module layout

```
crates/relix-cli/src/proxy/protocols/
├── anthropic.rs       (existing)
├── openai.rs          (new in this RFC)
└── passthrough.rs     (existing)

crates/relix-core/src/streaming.rs
  Existing SseFrameDecoder is reused (already handles \n\n / \r\n\r\n,
  comment lines, oversize cap). New OpenAiStreamAssembler lives here
  alongside AnthropicStreamAssembler.
```

### `OpenAiStreamAssembler`

Owns:

- An `SseFrameDecoder` (shared crate-level type, already hardened).
- A map keyed by `(choice_index, tool_call_index)` of tool-call
  state buffers.
- A per-choice `finished` flag.
- A per-stream `model` cache.

States per tool call:

```rust
struct ToolCallBuffer {
    id:       Option<String>,   // late-binding
    name:     Option<String>,   // late-binding
    args_buf: String,           // raw concatenation, possibly partial JSON
    finalised: bool,
}
```

Accumulator pseudocode:

```text
on chunk(payload):
    for choice in payload.choices:
        ci = choice.index
        if choice.delta:
            for tc in choice.delta.tool_calls (if any):
                key = (ci, tc.index)
                buf = state[key].or_insert_default()
                buf.id   = buf.id.or(tc.id).map(sanitize_label)
                buf.name = buf.name.or(tc.function.name).map(sanitize_label)
                buf.args_buf.push_str(tc.function.arguments)
                if buf.args_buf.len() > MAX_TOOL_INPUT_BYTES:
                    finalise_with_overflow(buf)

            if choice.delta.function_call (legacy):
                synthesize tool_call at (ci, 0) and merge

        if choice.finish_reason in {"tool_calls", "function_call"}:
            for buf at (ci, *) not yet finalised:
                emit ToolUseFinalised { id, name, input: parse_or_null(buf.args_buf) }
                buf.finalised = true

on data: [DONE]:
    set stream finished
    for any buffer not yet finalised: emit ParseError("tool_calls without finish_reason")
        + force-finalise with parse_or_null
```

Reuses the public `StreamEvent` enum from `relix-core::streaming`,
so the rule engine sees a unified event stream regardless of
upstream protocol.

### Outbound (request) processing

1. Locate the `system` role in `messages[]`. There may be zero, one,
   or multiple. Concatenate all of them with `\n` for inspection.
   Some clients use `developer` instead of `system`; treat both
   the same.
2. If `tools[]` exist, surface their `function.name` values to the
   rule engine as candidate tool names — a future TTP rule may
   match on declared but unused tool names.
3. Inspect via the existing rule engine.

### Error responses

OpenAI's de-facto mid-stream error format (per the official Python
SDK) is a `data:` frame whose JSON contains an `error` object.
Relix's block notice in OpenAI mode follows that shape:

Streaming:

```
data: {"error":{"type":"relix_blocked","code":"relix_blocked","message":"Relix blocked: <reason>","rule_id":"<id>"}}\n\n
```

Connection is closed without sending `[DONE]`.

Non-streaming:

```
HTTP/1.1 403 Forbidden
content-type: application/json
x-relix-blocked: 1

{"error":{"type":"relix_blocked","code":"relix_blocked","message":"Relix blocked: <reason>","rule_id":"<id>"}}
```

This is structurally distinct from the Anthropic-mode block
notice, which is intentional: clients written against either API
should see errors in the shape they expect.

### Legacy `function_call` handling

Inbound: synthesised into a single-element `tool_calls[]` entry
with `index: 0` for the rule engine. The rule engine therefore
never needs two code paths.

Outbound: passed through unchanged. Mirroring LiteLLM's policy,
we do not actively rewrite legacy responses. Older clients still
in production can keep working.

### Reasoning content

`delta.reasoning_content` (DeepSeek, 智谱) is captured into a
separate audit field but **not** forwarded to the rule engine
in v0.2-step3. The rule engine vocabulary will be extended in a
later RFC if a real-world rule justifies it. Forwarded bytes are
not modified.

## Routing

Path-based, in `protocols::select`:

| Path prefix            | Protocol                 |
| ---------------------- | ------------------------ |
| `/v1/messages*`        | Anthropic                |
| `/v1/chat/completions` | OpenAI                   |
| `/v1/completions`      | OpenAI                   |
| `/v1/responses*`       | passthrough (until v0.4) |
| anything else          | passthrough              |

The OpenAI adapter is content-type-aware: streaming responses are
forwarded chunk-by-chunk through the per-stream assembler;
buffered responses go through a one-shot inspector that parses the
final `Choice.message`.

## Compatibility relays

Relix is not built to match every relay quirk, but the following
known divergences from canonical OpenAI must not break us:

| Provider           | Quirk                                                     | Adapter behaviour                        |
| ------------------ | --------------------------------------------------------- | ---------------------------------------- |
| DeepSeek           | `delta.reasoning_content` field present                   | Captured, audited, not blocked           |
| Moonshot Kimi      | Occasional empty chunks in long-context streams           | Tolerated (skipped, not error)           |
| Qwen DashScope     | Multiple compatible endpoints (OpenAI, Anthropic, native) | Supported only on `/v1/chat/completions` |
| 智谱 GLM           | `reasoning_content` similar to DeepSeek                   | Same as DeepSeek                         |
| OpenRouter         | Possible `: ...` keepalive comment lines                  | Already discarded by `SseFrameDecoder`   |
| LiteLLM proxy      | Normalises upstream protocols to OpenAI shape             | Treated as plain OpenAI                  |
| claude-code-router | Exposes Anthropic to its agent client                     | Hits the Anthropic adapter, not OpenAI   |

A `tests/golden/openai/<provider>/` directory will accumulate
real recorded SSE traces (with sensitive headers stripped) so
regressions in compatibility are detected.

## Testing strategy

Unit tests in `relix-core::streaming`:

- `[DONE]` sentinel recognition (with and without trailing space).
- Comment-line discard.
- `tool_calls` assembly with split `arguments` across many chunks.
- Late-binding `id` / `name` (only on second chunk).
- Parallel `tool_calls` (two indices, interleaved chunks).
- Legacy `function_call` synthesised to `tool_calls`.
- `finish_reason="tool_calls"` triggers finalisation.
- Missing `finish_reason` followed by `[DONE]` triggers
  force-finalisation with `ParseError`.
- `MAX_TOOL_INPUT_BYTES` cap on aggregated `arguments`.

Integration tests in `tests/`:

- End-to-end: client → Relix → poisoned upstream → block.
- End-to-end: client → Relix → clean upstream → allow.
- Compatibility: replay each provider's recorded trace through
  Relix and assert that benign content forwards intact, malicious
  content is blocked.

## Migration path

1. Add `protocols/openai.rs` implementing `LlmProxy`.
2. Add `OpenAiStreamAssembler` in `relix-core::streaming` next to
   the existing `AnthropicStreamAssembler`. Both reuse
   `SseFrameDecoder`.
3. Extend `protocols::select` to route OpenAI paths.
4. Bundle 5-8 starter rules targeting OpenAI-shaped payloads in
   `rules/ioc/openai-tool-calls.yaml`.
5. Smoke test with a real client (Aider / Cursor / Codex CLI).

Each step lands as its own pull request with its own tests.

## Open questions

- **Sanitising `developer`-role messages**: the new spec uses
  `developer` instead of `system` for o-series models. Treat
  identically to `system` for inspection purposes.
- **Streaming usage chunk**: should we surface `usage` to the
  audit log? Useful for cost-anomaly rules, but not security-
  relevant. Decision: not in v0.2-step3; revisit when usage-based
  rules are proposed.
- **Blocking mid-stream while a parallel `tool_call` is in
  flight**: do we cancel only the offending tool call or the whole
  stream? RFC-0001 specifies stream-level cancellation. We keep
  that, since a partial cancellation would leave the agent in an
  ambiguous state.
