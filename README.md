# lintai

Offline-first security scanner for AI agent supply chain artifacts.

`lintai` scans repository-local agent instructions, MCP configs, Cursor rules, and Cursor Plugin surfaces with deterministic rules and CI-friendly output.

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

## Quick Start

Repo-root commands that are always truthful from this repository:

```bash
cargo run -- help
cargo run -- config-schema
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

## Exit Codes

- `0`: no blocking findings
- `1`: blocking findings were emitted
- `2`: execution or configuration error

## Sample Repos

- [`sample-repos/clean`](sample-repos/clean/README.md): clean mixed-surface workspace with zero findings
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
- findings carry structured `evidence`
- JSON machine output is versioned through `schema_version = 1`
- SARIF uses `stableKey` as the fingerprint source of truth
- root README commands are validated through the docs-command suite
- `lintai-testing` remains internal during `v0.1`

## Product Position

`lintai` is intentionally narrow in `v0.1`: offline-first, deterministic, and precision-first. It does not yet attempt broad multi-platform coverage, WASM/plugin runtime, registry scanning, or LSP workflows.
