# vervet

An AI-native adversary-emulation instrument. Infection Monkey, inverted: the
LLM is the orchestrator, vervet is a fleet of atomic, deterministic emulation
primitives that emit a typed evidence envelope (vq1). The CLI **is** the
contract — no Island, no server, no MCP glue.

**Authorized use only.** Every state-changing technique requires an
Ed25519-signed scope manifest. Out-of-scope is a hard, typed refusal.

## Crate layout

| crate | purpose |
|---|---|
| `vervet-core` | foundational types: ATT&CK ids, the vq1 envelope, content-addressed evidence |
| `vervet-scope` | authorization spine: signed `Manifest`, IPv4 CIDR scope, the unforgeable `Grant` token, audit chain |
| `vervet-technique` | the `Technique` trait + `inventory` registry (self-registration) |
| `vervet-techniques` | the techniques themselves — one self-contained file per ATT&CK id |
| `vervet-engage` | orchestration: authorize → engage → emit an audited `Receipt` (the one path every technique-firing verb funnels through) |
| `vervet-cli` | the verb surface: `describe`, `schema`, `recon`, `explain` |

`recon` emits a **Receipt** — a vq1 evidence envelope bound to a tamper-evident
audit chain. Each `audit[n].prev` is the blake3 handle of `audit[n-1]`, so any
removed or altered action breaks every later link.

## Invariants

- **`Grant` is unforgeable.** It has no public constructor; only
  `vervet_scope::Gate::authorize` mints one. A technique takes `&Grant`, so it
  cannot act outside an approved scope. This is enforced by the type system.
- **Compile-time registration only.** Techniques register via `inventory` — no
  dynamic plugin loading, so every technique is in-tree, reviewed, and gated.
- **Add a technique = add one file** in `vervet-techniques/src/` plus one `mod`
  line. `describe`, `schema` and dispatch read the registry; nothing else
  changes.
- **One concept per file; `mod.rs` only re-exports.** Enforced in CI by
  `scripts/check-line-budget.sh` — no source file may exceed 200 lines.

## Honest limits

Live network observations are timestamped facts, not bitwise-reproducible.
`recon` cannot know whether your blue team saw it — evidence is marked
`unobserved`, never `undetected`.
