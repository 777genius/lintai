# lintai Public Compatibility Policy

This file defines the compatibility promises for the publishable `v0.1` core.

## Stable Surface

- `lintai-api` is the only stable and publishable contract crate in `v0.1`.
- `lintai-testing` is intentionally internal during `v0.1` because it still depends on unpublished engine internals.
- All other crates in `lintai/` are internal-only.
- The `lintai` CLI is public product surface, but machine-readable stability promises still attach to `scan`, `config`, JSON, and SARIF first.

## `lintai-api`

- Changes are additive-only during the `v0.1` line.
- `RuleProvider`, `Finding`, `StableKey`, `ScanContext`, `WorkspaceScanContext`, and `RuleMetadata` do not change shape without a new charter decision.
- Rule codes are stable after release.

## JSON Output

- JSON machine output is a public contract.
- The envelope uses `schema_version = 1`.
- Changes are additive-only during the `v0.1` line.
- `stable_key` remains the source of truth for deduplication semantics.

## SARIF Output

- SARIF fingerprints remain derived from `stable_key`.
- Release-grade SARIF output must not use fake metadata placeholders.
- Any SARIF shape changes must preserve fingerprint stability.

## CLI Commands

- `scan`, `explain-config`, `config-schema`, and `help` remain public CLI surface.
- `fix` is additive public CLI surface.
- The presence of the `fix` command is stable after introduction, but autofix availability is rule-specific and may expand over time.
- The current safe autofix allowlist is limited to `SEC101` and `SEC103`.
- No machine-readable `fix` output format is promised in this line.

## Config Contract

- `lintai.toml` remains strict and deterministic.
- Unknown keys are errors.
- Reserved sections stay explicitly unsupported until a charter update says otherwise.
- Arrays use replace semantics, not implicit merge semantics.
