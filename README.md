# SEL Deploy

**Cryptographically chained deployment timeline — built on SEL Core**

[![Version](https://img.shields.io/badge/version-0.2.1-blue.svg)](https://github.com/chokriabouzid-star/sel-deploy/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)

---

## Demo

[![SEL Deploy Demo](https://asciinema.org/a/LDZVa0z3OVdLt7Zv.svg)](https://asciinema.org/a/LDZVa0z3OVdLt7Zv)

## The Problem

Every post-mortem starts with the same question:
**"What exactly deployed before the incident?"**

CI logs get modified. Git doesn't record deployment execution.
Slack history is fragmented. Hours lost reconstructing timelines.

## The Solution

SEL Deploy creates a **cryptographically-verified deployment timeline**:

- Each deployment is captured: **full argv**, command hash, git commit, actor,
  host, cwd, duration, timestamp, exit code
- Chained to the previous deployment (tamper-evident)
- Signed with Ed25519 (cryptographically attributable)
- Local SQLite index for fast timeline queries — **rebuildable from JSON**

```bash
$ sel-deploy run --env production -- kubectl apply -f deploy.yaml
✔  Deployment attested
   Command    : kubectl apply -f deploy.yaml
   Hash       : sel:v1.0:sha256:3541d13ba0ffaf67...
   Chained to : sel:v1.0:sha256:1a2b3c4d5e6f7a8b...
   Signed     : 2026-08-18 16:51:00 UTC

$ sel-deploy timeline 2026-08-18T16:30:00
Deployments ±60 min of 2026-08-18 16:30:00 UTC

[16:51:00]  kubectl apply -f deploy.yaml  ✔  sel:v1.0:sha256:3541d13b... [production]
```

---

## What SEL Deploy Proves

```
✅ "This argv ran at this timestamp, on this host, as this actor"
✅ "The holder of key 5044c0906fe14ed6 authorized the record"
✅ "The deployment sequence has not been silently edited"
✅ "No remaining attestation has been modified without detection"
⚠️  Deletion of the entire storage directory is still possible (see Threat Model)
```

**What it does NOT prove (v0.2):**

```
❌ Code is running in production right now
❌ The deployment "succeeded" beyond the process exit code
❌ The actor string is an authenticated identity (it is best-effort $USER / $SEL_DEPLOY_ACTOR)
❌ Compliance (SOC 2, ISO, …) — claims are explicit opt-in bits, not an audit
```

---

## Quick Start

### Install

```bash
git clone https://github.com/chokriabouzid-star/sel-deploy
cd sel-deploy
cargo build --release --locked
sudo cp target/release/sel-deploy /usr/local/bin/
```

### Setup

```bash
sel-deploy keygen
```

### Attest a deployment

```bash
sel-deploy run --env production -- kubectl apply -f deploy.yaml
sel-deploy run --env production -- ./scripts/deploy.sh
sel-deploy run -- helm upgrade myapp ./chart
```

`sel-deploy run` **exits with the wrapped command’s exit code** so CI fails
when the deploy fails. Use `--ignore-fail` only if you want to record a
failure and still pass the step.

### Query your timeline

```bash
# Recent deployments (shows the command, not only a hash)
sel-deploy history

# Around a specific time (for post-mortems)
sel-deploy timeline 2026-08-18T16:30:00 --window 60

# Verify chain integrity — exits 1 if anything is wrong
sel-deploy verify

# Verify a single attestation file
sel-deploy verify --file "$SEL_DEPLOY_HOME/attestations/<file>.json"

# Rebuild the SQLite index from JSON (source of truth)
sel-deploy rebuild
```

---

## Commands

| Command | Description | Notable exit codes |
|---------|-------------|--------------------|
| `keygen [--force]` | Generate Ed25519 signing keypair | `1` if key exists and `--force` was not given |
| `run [--env ENV] [--claim CLAIM] [--ignore-fail] -- CMD` | Execute command and attest it | wrapped command’s code (`--ignore-fail` → `0`) |
| `history [--limit N]` | Show recent deployments (default: 20) | |
| `timeline TIME [--window N]` | Query deployments around a timestamp | `1` on bad timestamp |
| `verify [--file PATH]` | Verify chain integrity or a single file | `1` if tampered, broken, or predecessor missing |
| `export [--format json] [--output PATH]` | Export attestations as JSON | `2` if format is not `json` |
| `rebuild` | Recreate `timeline.db` from JSON files | |

---

## How It Works

Each attestation is a JSON document (v0.2):

```json
{
  "version": "0.2",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-08-18T16:51:00.123456789Z",
  "command": ["kubectl", "apply", "-f", "deploy.yaml"],
  "command_hash": "sel:v1.0:sha256:3f8a2c1b...",
  "git_commit": "abc123",
  "exit_code": 0,
  "environment": "production",
  "cwd": "/srv/app",
  "actor": "ci-bot",
  "hostname": "runner-7",
  "duration_ms": 842,
  "previous_hash": "sel:v1.0:sha256:1a2b3c4d...",
  "attestation_hash": "sel:v1.0:sha256:7f8e9d2c...",
  "signature": "<ed25519-hex>",
  "signer": { "key_id": "5044c0906fe14ed6" },
  "compliance_hints": { "soc2_cc8": false, "change_management": false }
}
```

The **hash chain** links every deployment to the previous one.
Modifying any attestation breaks the chain — detected by `verify`, which
**fails the process** so CI cannot greenwash it.

Canonicalization and the `sel:v1.0:sha256:` digest are produced by
[SEL Core v1.2.1](https://github.com/chokriabouzid-star/SEL)
(`sel-common::canonicalize_json_value` + `sel_common::canonical::versioned_hash`).
The **spec version inside the hash stays `v1.0`** — crate 1.2.1 did not
change `CANONICAL_SPEC_VERSION`. v0.1 files keep their original hash path
so old signatures still verify.

Hash format: `sel:v1.0:sha256:<64-char-hex>`

Filenames are `{UTC-second}-{id-prefix}.json`. Two deploys in the same
second do not overwrite each other. Writes are atomic (`*.tmp` + rename).

---

## Environment

| Variable | Meaning |
|----------|---------|
| `SEL_DEPLOY_HOME` | Data directory (attestations, keys, `timeline.db`). Default: platform user data dir (`~/.local/share/sel-deploy` on Linux). |
| `SEL_DEPLOY_ACTOR` | Overrides the recorded actor (otherwise `$USER` / `$LOGNAME` / `$USERNAME`). |
| `SEL_DEPLOY_HOSTNAME` | Overrides the recorded hostname. |

Use `SEL_DEPLOY_HOME` in tests and CI so machines do not share a timeline.

---

## Security Notes

**Signing:** Each attestation is signed with Ed25519 over the canonical
payload. Verification needs only the public key.

**Attribution:** Records are attributable to the holder of the signing key.
The `actor` field is **not** an authentication proof.

**Chain integrity:** Edits are detected. A *missing* predecessor (deleted
or overwritten file) is also reported as a failure. `verify` exits `1`.

**Key storage:** Private keys live at `$SEL_DEPLOY_HOME/keys/default.pem`
as PEM (`BEGIN ED25519 PRIVATE KEY`) with `0600` permissions. v0.1 raw
32-byte files still load. Never commit them.

**Key rotation:** `keygen --force` archives the previous public key under
`keys/archive/{key_id}.pub`. `verify` tries archived keys.

**Compliance bits:** `compliance_hints` are **false unless you pass
`--claim`**. They are not an audit, a certification, or evidence of SOC 2.

---

## Threat Model

**SEL Deploy protects against:**

- CI log tampering after the fact (given the JSON files still exist)
- Retroactive edits of a recorded deployment
- Timeline ambiguity in post-mortems
- Silent modification of any remaining attestation

**SEL Deploy does NOT protect against:**

- Compromised signing key — an attacker with the private key can forge attestations
- Malicious authorized deployer — an authorized user can reset the local chain
- Infrastructure compromise — root access defeats all local guarantees
- Storage deletion — deleting `$SEL_DEPLOY_HOME` removes the entire history

Remote append-only backup and hardware keys are not in v0.2.

---

## Storage

```
$SEL_DEPLOY_HOME/          # or ~/.local/share/sel-deploy
├── attestations/          ← JSON source of truth
│   ├── 2026-08-18T16-51-00-550e8400.json
│   └── 2026-08-18T16-51-12-7f8e9d2c.json
├── keys/
│   ├── default.pem        ← Private key (chmod 0600, PEM)
│   ├── default.pub        ← Public key  (chmod 0644, PEM)
│   └── archive/           ← Previous public keys after --force
└── timeline.db            ← SQLite index (rebuildable: `sel-deploy rebuild`)
```

JSON files are the source of truth. The chain tip used by `run` is read
from JSON, not from SQLite. If the index is deleted or diverges:

```bash
sel-deploy rebuild
```

---

## Deployment Event Attestation

SEL Deploy records **what command ran, when, where, as whom, with what
result**, and chains those records. Artifact signing (Sigstore) and
SLSA provenance sit at a different layer. They are complementary.

---

## Built On

[SEL Core v1.2.1](https://github.com/chokriabouzid-star/SEL/tree/v1.2.1) —
`sel-common` provides canonical JSON and versioned SHA-256.
Hash format remains `sel:v1.0:sha256:<hex>` (spec 1.0, independent of
crate version). Ed25519 signing of *deployments* is implemented here and
is **not** the mission-key path (`~/.sel/ed25519.key`).

---

## Migrating from 0.1

1. Upgrade the binary.
2. Existing JSON files continue to verify (legacy hash path).
3. Existing raw 32-byte keys continue to load. New keys are PEM.
4. `history` after a `timeline.db` delete now tells you to `rebuild`
   instead of pretending there were never any deploys.
5. CI scripts that assumed `sel-deploy run` always exits 0 must add
   `--ignore-fail` or handle the real deploy exit code.
6. Do not treat `compliance_hints` on old files as evidence — v0.1
   wrote `true` unconditionally.

See [CHANGELOG.md](CHANGELOG.md).

---

## Roadmap

| Version | Status | Focus |
|---------|--------|-------|
| v0.1.0 | shipped | Local CLI, single-user (integrity gaps — do not rely on it) |
| v0.2.0 | shipped | Honest records, CI-safe exit codes, rebuild, key archive |
| v0.2.1 | **now** | SEL Core v1.2.1 pin; hash spec stays `sel:v1.0` |
| next | planned | GitHub Action, release binaries, remote append-only log |

---

## License

MIT © 2026 Chokri Bouzid

---

*SEL Deploy — Deployment accountability, cryptographically enforced.*
