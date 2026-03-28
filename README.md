# lintai

Offline-first security scanner for AI agent supply chain artifacts.

`lintai` scans repository-local agent instructions, MCP configs, Cursor rules, and Cursor Plugin surfaces with deterministic rules and CI-friendly output.

Public beta release: `v0.1.0-beta.1`

## Product Position

`lintai` is intentionally narrow in `v0.1`: offline-first, deterministic, and precision-first.

- Best fit: teams scanning repository-local skills, MCP configs, Cursor rules, and Cursor Plugins in CI.
- Primary value: high-signal security findings with stable rule ids, structured evidence, SARIF output, and explicit remediation support.
- Not the goal in `v0.1`: cloud-managed threat intel, broad registry scanning, “scan every AI platform”, or aggressive heuristic coverage at the cost of noise.
- Honest posture: strong public beta / early-adopter tool, not yet a broad `1.0` ecosystem platform.
- Public beta channel: GitHub Releases with prebuilt binaries only for the CLI in this phase.

Canonical positioning and non-goals live in [`docs/POSITIONING_AND_SCOPE.md`](docs/POSITIONING_AND_SCOPE.md).
Public beta release contract lives in [`docs/PUBLIC_BETA_RELEASE.md`](docs/PUBLIC_BETA_RELEASE.md).
The current beta evidence base is in [`docs/EXTERNAL_VALIDATION_REPORT.md`](docs/EXTERNAL_VALIDATION_REPORT.md).

## What It Scans

The current `v0.1` product contract covers:

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

## Start Here

If you just opened the repo, these are the only root `.md` files you need to care about:

- [`README.md`](README.md): product entry point, quick start, sample repos
- [`V0_1_RELEASE_CHARTER.md`](V0_1_RELEASE_CHARTER.md): what exactly counts as `v0.1`
- [`PUBLIC_COMPATIBILITY_POLICY.md`](PUBLIC_COMPATIBILITY_POLICY.md): compatibility promises for API, config, JSON, and SARIF
- [`ARCH_GAPS.md`](ARCH_GAPS.md): release-gap tracker; currently clear for `v0.1`

Everything else product/architecture-related is indexed from [`docs/INDEX.md`](docs/INDEX.md).

## Public Beta Install

The public beta CLI is distributed through GitHub Releases only in this phase.

1. Download the prebuilt binary for `v0.1.0-beta.1` from the GitHub Release.
2. Verify the release notes in [`docs/releases/v0.1.0-beta.1.md`](docs/releases/v0.1.0-beta.1.md).
3. Run:

```bash
lintai help
lintai config-schema
lintai scan .
lintai scan-known --scope=both
```

`lintai-api` remains the only stable publishable crate. This beta does not yet promise Homebrew, npm, or `cargo install` distribution for the CLI.

## Beta Evaluation Guide

The right way to evaluate the public beta is:

1. Run `lintai` on repositories that already contain supported surfaces.
2. Treat `Stable` findings as the release-quality baseline and `Preview` findings as non-baseline signals.
3. Treat `diagnostics` separately from findings; recoverable parsing does not imply a security hit.
4. Expect conservative behavior rather than maximal heuristic coverage.

Wave 2 external validation across `24` pinned public repositories is summarized in [`docs/EXTERNAL_VALIDATION_REPORT.md`](docs/EXTERNAL_VALIDATION_REPORT.md).

## Quick Start

Repo-root commands that are always truthful from this repository:

```bash
cargo run -- help
cargo run -- config-schema
cargo run -- scan-known --scope=both
```

End-to-end scan examples are intentionally documented against the checked-in sample repos, because config resolution is based on the working directory.

### Clean Sample

Expected exit: `0`

```bash
cd sample-repos/clean/repo
cargo run --manifest-path ../../../Cargo.toml -- scan .
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=json
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=sarif
```

### MCP-Heavy Sample

Findings are expected, but non-blocking under the sample config. Expected exit: `0`

```bash
cd sample-repos/mcp-heavy/repo
cargo run --manifest-path ../../../Cargo.toml -- scan .
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=json
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=sarif
```

### Cursor Plugin Sample

Blocking findings are expected. Expected exit: `1`

```bash
cd sample-repos/cursor-plugin/repo
cargo run --manifest-path ../../../Cargo.toml -- scan .
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=json
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=sarif
```

### Policy Mismatch Sample

Scan exit: `0`  
`explain-config` exit: `0`

```bash
cd sample-repos/policy-mismatch/repo
cargo run --manifest-path ../../../Cargo.toml -- scan .
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=json
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=sarif
cargo run --manifest-path ../../../Cargo.toml -- explain-config custom/agent.md
```

### Fixable Comments Sample

Preview exit: `0`  
Apply exit: `0`

```bash
cd sample-repos/fixable-comments/repo
cargo run --manifest-path ../../../Cargo.toml -- scan .
cargo run --manifest-path ../../../Cargo.toml -- fix .
```

`lintai fix` now serves two roles:

- safe autofix where a deterministic rewrite exists
- actionable manual remediation suggestions where automatic apply would be unsafe
- candidate patch previews for a narrow set of preview-only remediations

## Exit Codes

- `scan`: `0` means no blocking findings, `1` means blocking findings were emitted
- `scan-known`: `0` means no blocking findings across discovered known roots, `1` means at least one discovered root emitted a blocking finding
- `fix`: `0` means fixes were previewed or applied successfully, `1` means one or more selected fixes were skipped safely
- `2`: execution or configuration error

## Known Roots Scan

`scan-known` is the first ecosystem-oriented orchestration command. It does not broaden the parser/rule contract by itself; instead it auto-discovers the **currently supported** artifact surfaces in common client locations and scans only the roots that actually exist.

Current coverage in this command:

- `lintable` roots: client paths that resolve to existing `lintai` artifact kinds today, such as `SKILL.md`, `mcp.json`, `.mdc`, `.cursorrules`, and Cursor plugin surfaces
- `discovered_only` roots: known client paths that `scan-known` can inventory honestly today, but that do not yet map to current `lintai` parser/rule coverage

Examples:

```bash
lintai scan-known --scope=global
lintai scan-known --scope=both --client=cursor
lintai scan-known --client=codex --format=json
```

### Support Matrix

`scan-known` now reports client paths through a simple support matrix:

| State | Meaning |
|------|---------|
| `root discovered` | A manifest path exists on disk and is reported in `discovered_roots[]`. |
| `surface recognized` | Files under that root currently map to existing `lintai` artifact kinds. |
| `rules available` | Current providers can emit real findings for those recognized artifacts. |

Practical interpretation:

- `lintable` means `root discovered` + `surface recognized` + `rules available`
- `discovered_only` means `root discovered`, but `surface recognized` and `rules available` are not claimed yet

The checked-in manifest currently includes registry coverage for:

- Cursor
- Claude Code
- Claude Desktop
- Codex
- OpenCode
- Windsurf
- Junie
- VS Code / Copilot
- Continue
- Gemini CLI
- Kiro
- Amazon Q
- Roo
- Cline
- Zed
- Goose
- Aider
- Amp

## Sample Repos

- [`sample-repos/clean`](sample-repos/clean/README.md): clean mixed-surface workspace with zero findings
- [`sample-repos/fixable-comments`](sample-repos/fixable-comments/README.md): first safe-first `lintai fix` example with comment-removal fixes
- [`sample-repos/mcp-heavy`](sample-repos/mcp-heavy/README.md): MCP-focused repo with representative MCP findings
- [`sample-repos/cursor-plugin`](sample-repos/cursor-plugin/README.md): Cursor Plugin repo with manifest, hooks, commands, and agents
- [`sample-repos/policy-mismatch`](sample-repos/policy-mismatch/README.md): policy mismatch repo with `explain-config` coverage

Each sample repo README contains the exact commands to run from that repo's `repo/` directory and the expected exit behavior.

## Config Highlights

`lintai.toml` is strict: unknown top-level keys fail fast. The current config surface includes:

- file include/exclude
- category and rule overrides
- detection overrides
- suppress policy
- CI policy
- capabilities
- policy conflict mode

Example:

```toml
[capabilities]
network = "none"
exec = "none"

[policy]
capability_conflicts = "deny"

[[detection.overrides]]
files = ["custom/**/*.md"]
kind = "cursor_plugin_agent"
format = "markdown"
```

## Compatibility Notes

- `lintai-api` is the only stable publishable contract crate in `v0.1`
- the public beta CLI release is `v0.1.0-beta.1`
- the CLI distribution channel for this phase is GitHub Releases with prebuilt binaries only
- findings carry structured `evidence`
- JSON machine output is versioned through `schema_version = 1`
- SARIF uses `stableKey` as the fingerprint source of truth
- shipped built-in providers run behind an internal isolated backend with hard timeout enforcement
- in-process provider backends and internal runner protocol details are not public product contract
- `lintai fix` is additive public CLI surface with safe autofix for a narrow allowlist, message suggestions, and preview-only candidate patch edits for selected stable rules
- root README commands are validated through the docs-command suite
- `lintai-testing` remains internal during `v0.1`

## Current Non-Goals

`lintai` does not yet attempt broad multi-platform semantic coverage, WASM/plugin runtime, registry scanning, or LSP workflows.
