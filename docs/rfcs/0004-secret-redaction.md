# RFC-0004: Secret redaction & restore

| Field            | Value             |
| ---------------- | ----------------- |
| Status           | Draft             |
| Target milestone | v0.3              |
| Author           | Relix maintainers |
| Last updated     | 2026-05-27        |
| References       | RFC-0001          |

## Summary

Relix transparently rewrites outbound LLM requests to replace any
detected secret (API keys, tokens, private keys) with semantic
placeholders before they reach the upstream model, and reverses
the substitution on the inbound response so the client sees the
real values restored. The model never observes the real secret;
the client experiences no UX change.

This sits alongside the existing tool-injection inspection
(RFC-0001/RFC-0002): inspection blocks **dangerous tool calls in
the response**, redaction prevents **secrets from leaving the
client over the prompt channel**. They are complementary,
share no code, and run in opposite directions.

## Threat model

| ID  | Threat                                                             |
| --- | ------------------------------------------------------------------ |
| S01 | User pastes a token into a prompt; upstream sees and may log it    |
| S02 | Compromised relay records prompt traffic and harvests secrets      |
| S03 | Upstream legitimately stores prompts for training / fine-tuning    |
| S04 | Upstream **responds** with a secret (reverse poisoning / leakage)  |
| S05 | Upstream / attacker injects a forged `<RELIX_SECRET ...>` to probe |
| S06 | Attacker concatenates a placeholder with extra bytes to bypass     |
| S07 | DoS via huge high-entropy input forcing detector overload          |

S01-S04 motivate the feature. S05-S07 shape the design.

## Design

### Components

```
relix-core/src/redact/
├── mod.rs           re-exports
├── detector.rs      regex + Shannon entropy, IO-free
├── rules.rs         gitleaks-derived corpus, compile-time embed
├── placeholder.rs   format/parse, blake3 derivation
├── vault.rs         Arc<RwLock<HashMap>>, TTL, LRU, secrecy::Secret
├── config.rs        RedactConfig with defaults + env overrides
└── stream.rs        trailing-buffer state machine for streaming restore
```

`relix-cli/src/proxy/redact.rs` is the integration layer:
exposes `redact_outbound(body) -> body'` and a per-stream
restore filter that plugs into `forward_streaming` after H9
chunk slicing.

### Detection

Two layers:

1. **Pattern corpus**: forked from gitleaks (MIT). At least the
   following are present in v0.3:
   - OpenAI (`sk-...`, `sk-proj-...`)
   - Anthropic (`sk-ant-...`)
   - GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
   - AWS access key (`AKIA[0-9A-Z]{16}`)
   - GCP service account JSON (PEM block + project_id)
   - Azure storage / AAD
   - Stripe (`sk_live_`, `pk_live_`, `rk_live_`)
   - Slack (`xoxb-`, `xoxp-`, `xoxa-`)
   - JWT (three base64 segments)
   - SSH / TLS PEM block (`-----BEGIN ... PRIVATE KEY-----`)
   - Generic Bearer header tokens

2. **Entropy fallback**: Shannon entropy ≥ `redact.entropy_threshold`
   (default 4.0) over strings ≥ `redact.min_entropy_len` (default
   32 chars). Catches custom-format secrets the corpus misses.
   Defaults to on; users can disable by setting the threshold to
   `0`.

Both layers run on **outbound** request bodies. On the response
path the detector is also active so we can fail closed when the
upstream returns a literal secret value (S04), but the response
detector **does not redact** — it surfaces a `BlockMidStream`
verdict identical in shape to a rule-engine hit.

### Placeholder format

```
<RELIX_SECRET kind="github_pat" id="o4f7a3">
```

- `kind` is the detector category, lowercase snake_case.
- `id` is `blake3(secret || process_salt)[..6]` rendered as hex.
- The format is XML-ish so the model parses it as a structured
  marker and can continue to reason ("this is a GitHub PAT, I
  can pass it to `gh` CLI") without learning the value.
- The bracket characters are not used in natural English text;
  collisions with legitimate prompt content are effectively
  impossible.

Same secret → same placeholder, deterministically, across
turns and across processes that share the salt. Salt is
**per-process random** in v0.3, so placeholders are unique to a
Relix instance. Cross-process persistence is out of scope; it
would require a keyed exchange and pulls in scope creep.

### Vault

`HashMap<PlaceholderId, VaultEntry>`, where:

```rust
struct VaultEntry {
    secret: secrecy::Secret<String>,  // zeroized on Drop
    kind: SecretKind,
    last_used: Instant,
}
```

- Wrapped in `Arc<RwLock<...>>`. `read` lock on every restore,
  `write` lock only when inserting a new placeholder.
- Capacity bounded by `redact.vault_cap` (default 10000); LRU
  eviction with `tracing::warn` on each eviction so operators
  see capacity pressure.
- TTL `redact.vault_ttl_secs` (default 86400 = 24h). A background
  task evicts entries whose `last_used` is older than TTL every
  5 minutes.
- **Never serialised**, never written to disk. The audit log
  carries placeholder + kind, never the real value. Enforced by
  the type system: `VaultEntry` does not implement `Serialize`.

### Streaming restore

Streaming responses are restored in `forward_streaming` after
H9 chunk slicing. State per stream:

```rust
struct RestoreState {
    trailing: String,  // bytes held back, up to MAX_PLACEHOLDER_LEN
    redacted_count: u32,
}
```

On each ≤ 64 KiB slice:

1. Prepend `trailing` to the slice.
2. Scan for placeholder matches.
3. Replace matches with vault lookups; lookup miss leaves the
   placeholder unchanged and emits a `tracing::warn` (possible
   forged placeholder, S05).
4. Take the new tail (up to `MAX_PLACEHOLDER_LEN ≈ 64 bytes`)
   into `trailing` for the next slice.
5. Forward the rest.

`MAX_PLACEHOLDER_LEN` is the maximum possible serialised
placeholder length (kind 32 chars + id 6 hex + format overhead).
Concrete cap is 128 bytes for headroom.

On stream end, any remaining `trailing` is flushed verbatim.

### Configuration

Loaded from `relix.toml` next to the binary or from environment
variables (env wins). All configurable; defaults track the
sensible production case.

| Key                             | Default | Meaning                             |
| ------------------------------- | ------- | ----------------------------------- |
| `redact.enabled`                | `true`  | Master switch                       |
| `redact.vault_ttl_secs`         | `86400` | Per-entry idle TTL                  |
| `redact.vault_cap`              | `10000` | LRU capacity cap                    |
| `redact.entropy_threshold`      | `4.0`   | 0 = disable entropy fallback        |
| `redact.min_entropy_len`        | `32`    | Min string length for entropy       |
| `redact.block_on_upstream_leak` | `true`  | Block if upstream sends real secret |
| `redact.rule_files`             | `[]`    | Extra user-supplied detection rules |

Env naming: `RELIX_REDACT_VAULT_TTL_SECS=3600`.

### Response headers

Every response carries a non-secret diagnostic header so power
users / IDE plugins can show transparency:

```
x-relix-redacted-count: 2
```

Set to the number of distinct placeholders restored on this
response. Absent if zero.

### Failure modes (fail-safe)

| Scenario                               | Behaviour                            |
| -------------------------------------- | ------------------------------------ |
| Detector hits something legitimate     | Redact anyway; never wrong-direction |
| Vault miss on restore (forged S05)     | Leave placeholder verbatim, warn     |
| Placeholder concatenation attack (S06) | Match is anchored on `<...>`; ext.   |
|                                        | bytes break the match → unchanged    |
| Detector OOM / very long input (S07)   | Capped by H9 slice + entropy minlen  |
| Vault full                             | LRU evict + warn                     |
| Background TTL task crashes            | TTL eviction stops; LRU still works  |

### Red-team checks (must pass before v0.3)

- R-A: forged `<RELIX_SECRET kind="x" id="abcdef">` from upstream
  — must not resolve to anything; pass through, warn.
- R-B: upstream returns a literal real secret value (`AKIA...`)
  — detector hits, response blocked with `block_on_upstream_leak`.
- R-C: model emits `<RELIX_SECRET kind="x" id="abcdef">trailing`
  — placeholder restored, trailing preserved; the result is
  `<real_value>trailing`, which is the _intended_ behaviour
  (`gh CLI -H "Bearer <real>extra"` cases). This is **not** a
  vulnerability: the attacker would need to already control the
  model's output content to exploit it, and they would already
  control everything if they did.
- R-D: vault cap exhaustion attack: 20000 unique high-entropy
  strings in one prompt — LRU evicts oldest, restore for
  evicted entries falls back to "no restore" (visible to user
  via diagnostic header `x-relix-redacted-count` being lower
  than expected).
- R-E: cross-chunk placeholder split — fixture with placeholder
  spanning two ≤ 64 KiB slices; restore must still work.

### Non-goals

- Cross-process persistence (deferred until a real use case
  surfaces; brings key-management complexity).
- Detecting secrets the user **types into the conversation
  history** in past turns that Relix never saw (impossible
  without history rescanning, deferred to v0.4 if needed).
- Hardware-backed key storage (HSM/Keychain integration).
  Currently `Secret<String>` in process memory only.

## Migration

1. `relix-core::redact::detector` + `placeholder` first, IO-free,
   unit-tested in isolation.
2. `vault` with `secrecy` + `zeroize`, unit tests on insertion,
   eviction, TTL.
3. `config` + defaults + env overrides.
4. `relix-cli::proxy::redact` integration; hooked into Anthropic
   and OpenAI `request_filter`.
5. Streaming restore state machine; hooked into
   `forward_streaming` after H9.
6. e2e: roundtrip / cross-chunk / upstream-leak-block /
   forged-placeholder.
7. RFC-0001/0002 threat-model table extended with S01-S07.

Each step lands as its own PR with its own tests.

## Red-team review (post-S5 self-audit)

After landing all five stages the residual gaps below were
identified. R-A through R-C are flagged for v0.4; the rest are
either resolved (R-D) or out of scope.

### R-A: nested JSON-escape levels

The placeholder regex accepts at most one `\` before each inner
quote (`\\?"`). A response body that wraps a JSON inside another
JSON string would render the placeholder as `\\\"...\\\"` (two
backslashes), and we would miss it. Currently no observed
upstream double-encodes responses, but we should support
`\\*"` semantically (any escape depth) once a real-world case
appears. Fix: allow the regex to match `\*` and verify
roundtrip when the upstream is known to multi-encode.

### R-B: streaming + JSON escape interaction

Anthropic SSE delivers `tool_use.input` as `partial_json`
strings — placeholders inside those fields will already be
`\"`-escaped on the wire. The `StreamRestore` state machine
only knows about literal placeholders. If the model echoes a
placeholder back in a tool_use argument, we currently do not
restore it inside the SSE frame. Fix: surface the JSON-decoded
view of partial_json fragments to the restore step, then
re-encode after substitution.

### R-C: detector false positives on response path

`detect_upstream_leak` flags any response substring matching
the detector corpus that is not already wrapped in a
`<RELIX_SECRET>` placeholder. A model that _invents_ a string
that coincidentally matches one of our regexes would trigger
a false-positive block. Real risk is low (the corpus is
specific) but the cost is request blocked. Mitigations to
consider: only block on shapes that derive deterministically
(AKIA, ghp\_, JWT) and downgrade entropy-fallback hits to a
warning.

### R-D: salt rotation across process restart (resolved as designed)

Salts are per-process. After a restart, the model can no
longer reference placeholders from the previous run because
they will lookup-miss. This is intentional: the alternative
(persisting the salt + vault) brings key-management
complexity that v0.3 deliberately avoids. The cost is the
user has to repaste secrets after a Relix restart. Reopen
when a real workflow makes this painful.

## Open questions

None at draft time. Configuration knobs absorb all the points
that would otherwise be open questions.
