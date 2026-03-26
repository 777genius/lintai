# Architecture Gaps

This file tracks the remaining deltas between the implemented `lintai/` workspace and the canonical decisions in [docs/ARCHITECTURE_DECISIONS.md](docs/ARCHITECTURE_DECISIONS.md) and [docs/VISION.md](docs/VISION.md).

## Required For v0.1

No remaining `Required For v0.1` gaps.

## Deferred To v0.2+

- Split `lintai-adapters` into explicit FORMAT and DOMAIN crates after interfaces stabilize.
- Add isolated provider execution for true hard timeout enforcement and future subprocess/WASM layers.
- Expand beyond the locked `v0.1` platform scope and add broader registry/pre-install workflows.
- Add safe-first public `lintai fix` UX after fix coverage and safety policy are wider.
- Revisit `lintai-testing` as a public crate only after it is fully decoupled from engine internals.

## Resolved By Implementation Or Contract Change

- `RuleProvider` no longer duplicates full-scan semantics through both `requires_full_scan()` and provider capabilities.
- The engine now supports real workspace execution through `ScanScope::Workspace` and `WorkspaceScanContext`.
- CLI output now supports `text`, `json`, and `sarif`.
- JSON output now uses `schema_version` instead of a loose `"v0"` string.
- Cursor Plugin scope now includes manifests, hooks config, hook scripts, command docs, and agent docs.
- Capabilities/policy now exists as a real config contract and a working mismatch rule layer.
- Provider timeout is now enforced as truthful soft-budget accounting with deterministic runtime errors.
- `FileTypeDetector` remains an orchestration concern, but routing rules are declared in adapters and can be overridden through config.
- Explain-config now reports detection and policy state, not just severity overrides.
- Findings now carry typed structured evidence and rules carry explicit `RuleTier`.
- Checked-in config schema is now generated from the typed raw config model instead of a separate dedicated builder.
- `lintai-testing` is no longer treated as a publishable `v0.1` crate.
- Corpus, compatibility snapshots, sample repos, and cross-platform smoke are now wired into release workflows.
