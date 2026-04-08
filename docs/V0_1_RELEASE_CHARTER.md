# lintai v0.1 Release Charter

This file is the canonical source of truth for what counts as `v0.1`.

## Product Contract

- One native offline-first binary.
- Deterministic findings with explicit evidence.
- Stable `text`, `json`, and `sarif` outputs.
- Exit codes:
  - `0` no blocking findings
  - `1` blocking findings present
  - `2` execution/config error

## Locked v0.1 Scope

- `SKILL.md`
- `CLAUDE.md`
- `.mdc`
- `.cursorrules`
- `mcp.json`
- `.cursor-plugin/plugin.json`
- `.cursor-plugin/hooks.json`
- `.cursor-plugin/hooks/**/*.sh`
- `.cursor-plugin/commands/**/*.md`
- `.cursor-plugin/agents/**/*.md`

## Required Technical Guarantees

- `lintai-api` is the only stable contract crate.
- `lintai-testing` remains internal during `v0.1`.
- Workspace execution exists through backend-owned `ScanScope::Workspace`.
- Detection can be overridden through config.
- `stable_key` is the source of truth for dedup and SARIF fingerprints.
- Findings carry typed structured evidence.
- JSON machine output is versioned through `schema_version`.
- Config is strict and explainable.
- Policy mismatch detection is implemented for project capabilities vs observed behavior.
- Shipped built-in providers execute behind an internal isolated backend with hard timeouts.

## Rule Tiers

- `stable` rules define the release baseline and must emit structured evidence.
- `preview` rules are tested but do not define the release baseline.

## Explicit Non-Goals For v0.1

- 14+ platform support
- YARA as mandatory runtime
- WASM/plugin runtime
- registry or pre-install scanning
- LSP
- broad public `lintai fix` UX

## Release Gate

`v0.1` is release-ready only when all of the following are true:

- Every `Required For v0.1` item in `ARCH_GAPS.md` is closed.
- Root README and sample repo commands are truthful and validated by the docs-command suite.
- Must-scope repositories scan end-to-end.
- `json` and `sarif` outputs are stable under snapshot/contract tests.
- Policy mismatch coverage exists in regression tests.
- Compatibility promises in `PUBLIC_COMPATIBILITY_POLICY.md` are true in code.
- Cross-platform smoke checks are green.
