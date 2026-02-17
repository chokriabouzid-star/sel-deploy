# SEL Deploy

**Cryptographically chained deployment timeline — built on SEL Core**

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/chokriabouzid-star/sel-deploy/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)

---

## The Problem

Every post-mortem starts with the same question:
**"What exactly deployed before the incident?"**

CI logs get modified. Git doesn't record deployment execution.
Slack history is fragmented. Hours lost reconstructing timelines.

## The Solution

SEL Deploy creates a **cryptographically-verified deployment timeline**:

- Each deployment is captured: command hash, git commit, timestamp, exit code
- Chained to the previous deployment (tamper-evident)
- Signed with Ed25519 (cryptographically attributable)
- Local SQLite index for fast timeline queries
```bash
$ sel-deploy run -- kubectl apply -f deploy.yaml
✔  Deployment attested
   Hash       : sel:v1.0:sha256:3541d13ba0ffaf67...
   Chained to : sel:v1.0:sha256:1a2b3c4d5e6f7a8b...
   Signed     : 2026-02-17 16:51:00 UTC

$ sel-deploy timeline 2026-02-17T16:30:00
Deployments ±60 min of 2026-02-17 16:30:00 UTC

[16:51:00]  —  kubectl apply  ✔  sel:v1.0:sha256:3541d13b... [production]
[16:51:12]  —  kubectl apply  ✔  sel:v1.0:sha256:605be7f8... [production]
```

---

## What SEL Deploy Proves
```
✅ "This command ran at this exact time"
✅ "The holder of key 5044c0906fe14ed6 authorized it"
✅ "The deployment sequence has not been altered"
✅ "No attestation has been modified without detection"
⚠️  Deletion of the entire storage directory is still possible (see Threat Model)
```

**What it does NOT prove (v0.1):**
```
❌ Code is running in production right now  (planned v0.3)
❌ The deployment succeeded at runtime      (planned v0.3)
```

---

## Quick Start

### Install
```bash
git clone https://github.com/chokriabouzid-star/sel-deploy
cd sel-deploy
cargo build --release
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

### Query your timeline
```bash
# Recent deployments
sel-deploy history

# Around a specific time (for post-mortems)
sel-deploy timeline 2026-02-17T16:30:00 --window 60

# Verify chain integrity
sel-deploy verify

# Verify a single attestation file
sel-deploy verify --file ~/.local/share/sel-deploy/attestations/2026-02-17T16-51-00.json
```

---

## Commands

| Command | Description |
|---------|-------------|
| `keygen [--force]` | Generate Ed25519 signing keypair |
| `run [--env ENV] -- CMD` | Execute command and attest it |
| `history [--limit N]` | Show recent deployments (default: 20) |
| `timeline TIME [--window N]` | Query deployments around a timestamp |
| `verify [--file PATH]` | Verify chain integrity or single attestation |
| `export [--format json] [--output PATH]` | Export attestations as JSON |

---

## How It Works

Each attestation is a JSON document:
```json
{
  "version": "0.1",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-02-17T16:51:00Z",
  "command_hash": "sel:v1.0:sha256:3f8a2c1b...",
  "git_commit": "abc123",
  "exit_code": 0,
  "environment": "production",
  "previous_hash": "sel:v1.0:sha256:1a2b3c4d...",
  "attestation_hash": "sel:v1.0:sha256:7f8e9d2c...",
  "signature": "<ed25519-hex>",
  "signer": { "key_id": "5044c0906fe14ed6" },
  "compliance_hints": { "soc2_cc8": true, "change_management": true }
}
```

The **hash chain** links every deployment to the previous one.
Modifying any attestation breaks the chain — detected instantly by `verify`.

The canonical hash is computed from structured fields — not from raw JSON text —
ensuring stable verification independent of field ordering or formatting.

Hash stability is inherited from
[SEL Core v1.0.0](https://github.com/chokriabouzid-star/SEL):
once a hash is produced under `sel:v1.0`, it remains valid for verification
indefinitely regardless of tool version.

Hash format: `sel:v1.0:sha256:<64-char-hex>`

---

## Security Notes

**Signing:** Each attestation is signed with Ed25519. The signature covers a
canonicalized payload — deterministic regardless of JSON formatting. Verification
requires only the public key.

**Attribution:** Attestations are cryptographically attributable to the holder
of the signing key at the time of signing. This assumes the private key is
secured and unshared. See Threat Model below.

**Chain integrity:** Any modification to a past attestation causes hash
verification to fail on the next `verify` run. The chain itself cannot be
silently altered.

**Key storage:** Private keys are stored at
`~/.local/share/sel-deploy/keys/default.pem` with `0600` permissions.
Never commit them to version control.

---

## Threat Model

**SEL Deploy protects against:**
- CI log tampering after the fact
- Retroactive deployment record edits
- Timeline ambiguity in post-mortems
- Modification of any past attestation (detected on verify)

**SEL Deploy does NOT protect against:**
- Compromised signing key — an attacker with the private key can forge attestations
- Malicious authorized deployer — an authorized user can reset the local chain
- Infrastructure compromise — root access defeats all local guarantees
- Storage deletion — deleting `~/.local/share/sel-deploy/` removes the entire history

Remote backup and hardware key support are planned for v0.3.

---

## Storage
```
~/.local/share/sel-deploy/
├── attestations/           ← JSON source of truth (never modified by the tool)
│   ├── 2026-02-17T16-51-00.json
│   └── 2026-02-17T16-51-12.json
├── keys/
│   ├── default.pem         ← Private key (chmod 0600)
│   └── default.pub         ← Public key  (chmod 0644)
└── timeline.db             ← SQLite index (rebuildable from JSON)
```

JSON files are the source of truth. The SQLite database is a fast query index
only — it can be deleted and rebuilt from JSON at any time.

---

## Deployment Event Attestation

SEL Deploy focuses on **deployment event attestation**: recording what command
ran, when, with what result, and chaining those records cryptographically.

Artifact signing solutions (e.g., Sigstore) solve a different layer of the
supply chain. These approaches are complementary, not competing.

---

## Built On

[SEL Core v1.0.0](https://github.com/chokriabouzid-star/SEL) —
Deterministic execution engine with cryptographic guarantees.
(33/33 tests, 20/20 determinism stress test)

---

## Roadmap

| Version | Status | Focus |
|---------|--------|-------|
| v0.1.0 | ✅ Now | Local CLI, single-user, tamper-evident log |
| v0.2.0 | 📋 Q2 2026 | Multi-user signing, cloud timeline sync |
| v0.3.0 | 📋 Q3 2026 | Runtime agents, remote backup |
| v1.0.0 | 📋 Q4 2026 | Enterprise: SSO, compliance reports |

---

## License

MIT © 2026 Chokri Bouzid

---

*SEL Deploy — Deployment accountability, cryptographically enforced.*
