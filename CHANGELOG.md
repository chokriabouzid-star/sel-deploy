# Changelog

All notable changes to SEL Deploy are documented here.

## [0.2.0] — 2026-08-18

Integrity release. The v0.1 CLI could not answer “what deployed?”,
overwrote same-second files, and exited 0 on a broken chain.

### Breaking

- Attestation document version is now `0.2`. v0.1 files still **verify**.
- `sel-deploy run` now exits with the wrapped command’s exit code.
  Use `--ignore-fail` to keep the old “always 0 after attesting” behaviour.
- `sel-deploy verify` exits `1` when any hash, signature, gap, or missing
  predecessor is found.
- `sel-deploy keygen` without `--force` exits `1` if a key already exists.
- `sel-deploy export --format <other>` exits `2`. The “Enterprise tier”
  message is gone.
- `compliance_hints` default to `false`. Record a claim only with
  `--claim soc2_cc8` / `--claim change_management`.
- Command hash is taken over a canonical JSON argv (argument boundaries
  are preserved). v0.1 used `join(" ")`.
- Private/public keys are written as PEM. Raw 32-byte v0.1 key files
  still load.

### Added

- `command`, `cwd`, `actor`, `hostname`, `duration_ms` on every attestation.
- Unique filenames `{utc-second}-{id-prefix}.json` and atomic writes.
- `SEL_DEPLOY_HOME` overrides the data directory.
- `sel-deploy rebuild` reconstructs `timeline.db` from JSON.
- `keygen --force` archives the previous public key under `keys/archive/`.
  `verify` tries archived keys, so history survives rotation.
- Chain audit treats a lost genesis / overwritten predecessor as a failure.
- `Cargo.lock` is tracked for reproducible builds.
- CLI integrity tests (exit codes, overwrite, rebuild, key rotation).

### Fixed

- History / timeline now show the command, not only a hash.
- Hashing and canonical JSON go through `sel-common` (SEL Core v1.0.0).
- `cargo fmt --check` and `clippy -D warnings` pass (CI was red on every run).

## [0.1.0] — 2026-02-17

Initial local CLI: Ed25519-signed hash chain, SQLite index, JSON store.
