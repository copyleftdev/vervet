# vervet — AI-native adversary emulation & breach-and-attack simulation in Rust

[![CI](https://github.com/copyleftdev/vervet/actions/workflows/ci.yml/badge.svg)](https://github.com/copyleftdev/vervet/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/vervet-cli.svg)](https://crates.io/crates/vervet-cli)
[![docs.rs](https://img.shields.io/docsrs/vervet-core?label=docs.rs)](https://docs.rs/vervet-core)
[![license: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

> **vervet** is a Rust **adversary-emulation** and **breach-and-attack-simulation
> (BAS)** instrument designed for **AI / LLM orchestration**. Every primitive maps
> to **MITRE ATT&CK**, emits typed, content-addressed, tamper-evident evidence,
> and refuses to act outside an Ed25519-signed authorization scope. Built for
> **red team**, **purple team**, **detection engineering**, and **security
> automation** — atomic offensive **TTPs** an LLM can drive, in the spirit of
> Caldera, Infection Monkey, and Atomic Red Team but inverted around the model.

**An AI-native adversary-emulation instrument.** Infection Monkey, inverted: the
LLM is the orchestrator, vervet is a fleet of atomic, deterministic emulation
primitives that emit a typed evidence envelope (vq1). The CLI **is** the
contract — no Island, no server, no MCP glue.

> ⚠️ **Authorized use only.** Every state-changing technique requires an
> Ed25519-signed scope manifest. Out-of-scope is a hard, typed refusal — vervet
> cannot act against a target the signed manifest does not name.

## What it is

vervet is the inverse of a monolithic breach-and-attack platform. Instead of a
server that drives agents, it is a single static binary of small, reviewed
emulation primitives. An AI orchestrator calls one verb at a time and reads back
structured evidence:

- **`describe`** is the self-describing contract — protocol, verbs, and every
  registered technique with the `inputs` it expects. An orchestrator calls it
  once to bootstrap; no external docs required.
- **`emulate <ATTACK_ID>`** authorizes against a signed manifest, fires the
  technique, and emits a **receipt**: a vq1 evidence envelope bound to a
  tamper-evident audit chain.
- **`report`** folds receipts into an ATT&CK coverage map, grouped by tactic.

Every technique-firing path funnels through one audited pipeline
(`authorize → engage → emit`), so authorization is a property of the type
system, not a convention you can forget.

## Build

```sh
cargo build --release                            # default: static, protocol-level probes only
cargo build --release -p vervet-cli --features ssh-auth   # credential-asserting SSH backend
```

Requires Rust 1.88+ (edition 2024). The default binary is dependency-light and
ships protocol probes only; `--features ssh-auth` pulls in libssh2 (via `ssh2`)
for real password authentication — opt-in so the default stays lean.

## The loop

### 1. Sign a scope manifest

A manifest is the signed authorization for one engagement: which CIDRs, which
techniques, which time window. The signing key is held by the authorizing
party — never by vervet. A dev signer ships as an example:

```sh
# claims.json — the engagement you are authorizing
{
  "engagement_id": "acme-2026-q2",
  "operator": "dj@codetestcode.io",
  "authorized_cidrs": ["10.10.0.0/24"],
  "excluded_cidrs": ["10.10.0.1/32"],
  "technique_allowlist": ["T1046", "T1110.003"],
  "valid_from": 0,
  "valid_until": 4102444800
}
```

```sh
cargo run -p vervet-scope --example sign -- <seed-hex-32-bytes> claims.json > manifest.json
# prints the authority public key to stderr:
#   authority: 4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29
```

The **authority** (the public key) is what the gate checks signatures against.
It is supplied out-of-band — a self-signed manifest would be forgeable, so the
gate never trusts a key carried inside the manifest itself.

### 2. Discover what you can fire

```sh
vervet describe
```

```jsonc
{
  "tool": "vervet",
  "protocol": { "schema": "vq1", "version": "0.1.0" },
  "verbs": ["describe", "schema", "emulate", "report", "explain", "help"],
  "authorization": "every engagement requires an Ed25519-signed scope manifest",
  "techniques": [
    {
      "id": "T1046",
      "name": "Network Service Discovery",
      "tactic": "discovery",
      "inputs": ["target", "ports (default 445,22,3389 = SMB,SSH,RDP)"],
      ...
    }
  ]
}
```

### 3. Emulate a technique

```sh
vervet emulate T1046 \
  --manifest manifest.json \
  --authority 4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29 \
  --target 10.10.0.5 --ports 22,80 \
  --store ./runs
```

It emits a receipt — the evidence envelope plus the audit chain that records the
authorization and the engagement as two linked actions:

```jsonc
{
  "envelope": {
    "header": { "schema": "vq1", "version": "0.1.0" },
    "summary": {
      "name": "Network Service Discovery",
      "attack_id": "T1046",
      "tactic": "discovery",
      "engagement_id": "acme-2026-q2",
      "observation_count": 0
    },
    "handles": {}
  },
  "audit": [
    { "seq": 0, "engagement_id": "acme-2026-q2",
      "action": "authorize T1046 target=10.10.0.5", "prev": "ev:genesis" },
    { "seq": 1, "engagement_id": "acme-2026-q2",
      "action": "engage T1046 observations=0", "prev": "ev:412c0a8637502e7a" }
  ]
}
```

Each `audit[n].prev` is the blake3 handle of `audit[n-1]`, so removing or
altering any action breaks every later link. `--store ./runs` (or the
`VERVET_STORE` env var) persists the receipt to a content-addressed run store
grouped by engagement.

A request the manifest does not authorize is refused with a typed reason and
**exit code 2** — never a silent failure:

```sh
$ vervet emulate T1046 ... --target 192.168.1.1
denied: target is not within any authorized CIDR        # exit 2

$ vervet emulate T1046 ... --target 10.10.0.1
denied: target falls within an excluded CIDR            # exit 2

$ vervet emulate T1021 ...
denied: technique is not in the manifest allowlist      # exit 2
```

### 4. Report coverage

```sh
vervet report --store ./runs --engagement acme-2026-q2
# or pipe receipt files directly:  vervet report run-a.json run-b.json
```

```jsonc
{
  "schema": "vq1-coverage",
  "tactics": { "discovery": ["T1046"] },
  "techniques": [
    { "id": "T1046", "name": "Network Service Discovery", "tactic": "discovery",
      "engagements": 1, "observations": 0, "detection": "unobserved" }
  ],
  "totals": { "engagements": 1, "techniques": 1, "observations": 0 },
  "detection_note": "detection is unobserved — vervet does not see your blue team; feed SIEM evidence to populate"
}
```

## Verbs

| verb | purpose |
|---|---|
| `describe` | Protocol, verbs, and every registered technique with its `inputs` (machine-readable contract) |
| `schema` | The engagement-receipt contract as JSON Schema |
| `emulate <ATTACK_ID>` | Authorize against a signed manifest, fire the technique, emit an audited receipt |
| `report <receipts…>` | Fold receipts into an ATT&CK coverage map (or `--store <dir> [--engagement <id>]`) |
| `explain` | Resolve one evidence handle from a receipt (`--run <receipt.json> --handle <ev:…>`) |
| `help` | The human-facing verb surface (`-h` / `--help`); `-V` / `--version` for the version |

## Techniques

| ATT&CK id | name | tactic |
|---|---|---|
| `T1046` | Network Service Discovery | discovery |
| `T1021` | Remote Services | lateral movement |
| `T1078` | Valid Accounts | initial access |
| `T1110.003` | Password Spraying | credential access |

Each technique is one self-contained file in `vervet-techniques/src/`. Adding a
technique is adding one file plus one `mod` line — `describe`, `schema`, and
dispatch all read the registry, so no CLI or central dispatch is ever edited.

## Authorization model

- **`Grant` is unforgeable.** It has no public constructor; only
  `vervet_scope::Gate::authorize` mints one. A technique takes `&Grant`, so it
  *cannot* act outside an approved scope. This is enforced by the type system,
  not by review.
- **Compile-time registration only.** Techniques register via `inventory` — no
  dynamic plugin loading. Every technique is in-tree, reviewed, and gated.
- **The audit chain is tamper-evident.** Each entry commits to the previous
  entry's blake3 handle; any edit or deletion breaks the chain.

## The verifier seam

Credential-access techniques judge attempts through a pluggable `Verifier`.

- The **default** build ships protocol-level probes only. The SSH probe does a
  real RFC-4253 version exchange — it confirms the service and captures its
  banner, reaching at most `ssh_confirmed`. It never asserts whether a
  credential is valid.
- The **`--features ssh-auth`** build adds `SshAuth`, a credential-asserting
  backend that performs real password authentication and returns
  `valid` / `invalid`. Its end-to-end test stands up a real `sshd` with
  testcontainers (`cargo test -p vervet-verify --features ssh-auth`, needs
  Docker) and is kept out of the default suite.

Password material is **never written to evidence**, regardless of verdict.

## Testing

```sh
cargo test --workspace                          # full default suite, no Docker
cargo test -p vervet-scope                       # includes the proptest suites
```

The default suite is hermetic — no Docker, no network services. The
credential-asserting path is proven end to end against **real** containerized
services (testcontainers), gated so the default build needs no Docker:

```sh
cargo test -p vervet-verify --features ssh-auth   # the SshAuth backend vs a real sshd
cargo test -p vervet-e2e    --features ssh-auth   # the full authorize → engage → emit pipeline
cargo test -p vervet-cli    --features ssh-auth   # the real `vervet` binary, emulate → store → report
```

`vervet-e2e` stands up a real `sshd`, signs a scope manifest, and drives the
canonical pipeline against it — asserting true `valid`/`invalid` verdicts,
password redaction, and a linking audit chain. `vervet-cli` does the same as a
black box through the compiled binary, including `report` aggregation.

## Crate layout

| crate | purpose |
|---|---|
| `vervet-core` | foundational types: ATT&CK ids, the vq1 envelope, content-addressed evidence |
| `vervet-scope` | authorization spine: signed `Manifest`, IPv4 CIDR scope, the unforgeable `Grant`, audit chain |
| `vervet-technique` | the `Technique` trait + `inventory` registry (self-registration) |
| `vervet-techniques` | the techniques themselves — one self-contained file per ATT&CK id |
| `vervet-verify` | the auth-verifier seam: pluggable backends that judge an attempt → `Verdict` |
| `vervet-engage` | orchestration: authorize → engage → emit an audited `Receipt` |
| `vervet-report` | fold receipts into an ATT&CK coverage map — pure JSON aggregation |
| `vervet-store` | content-addressed run store: `<root>/<engagement>/<run-id>.json` |
| `vervet-cli` | the verb surface |
| `vervet-e2e` | Docker-backed end-to-end tests driving the full pipeline against real services |

## Honest limits

Live network observations are timestamped facts, not bitwise-reproducible.
vervet cannot know whether your blue team saw it — evidence is marked
`unobserved`, never `undetected`. Feed SIEM evidence back in to populate
detection.

## Invariants (enforced in CI)

- **One concept per file; `mod.rs` only re-exports.** No source file exceeds 200
  lines (`scripts/check-line-budget.sh`).
- **Add a technique = add one file** in `vervet-techniques/src/` plus one `mod`
  line. Nothing else changes.

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).

---

<sub>**Topics:** adversary-emulation · breach-and-attack-simulation · MITRE ATT&CK ·
red-team · purple-team · penetration-testing · offensive-security · detection-engineering ·
security-automation · TTP · Rust · CLI · AI · LLM-agent · cybersecurity</sub>
