# lintai

Offline-first security scanner for AI agent supply chain artifacts.

`lintai` scans repository-local agent instructions, MCP configs, Cursor rules, and Cursor Plugin surfaces with deterministic rules and CI-friendly output. The current `v0.1` contract supports:

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

## Docs

- Product and architecture docs live in [`docs/`](docs/).
- Start with [`docs/INDEX.md`](docs/INDEX.md) for the canonical document map.
- Release constraints and remaining deltas live in [`V0_1_RELEASE_CHARTER.md`](V0_1_RELEASE_CHARTER.md) and [`ARCH_GAPS.md`](ARCH_GAPS.md).

## Current Commands

```bash
cargo run -- scan .
cargo run -- scan . --format=json
cargo run -- scan . --format=sarif
cargo run -- explain-config SKILL.md
cargo run -- config-schema
```

## Sample Repos

- [`sample-repos/clean`](sample-repos/clean/README.md): clean mixed-surface workspace with zero findings
- [`sample-repos/mcp-heavy`](sample-repos/mcp-heavy/README.md): MCP-focused repo with representative MCP findings
- [`sample-repos/cursor-plugin`](sample-repos/cursor-plugin/README.md): Cursor Plugin repo with manifest, hooks, commands, and agents
- [`sample-repos/policy-mismatch`](sample-repos/policy-mismatch/README.md): policy mismatch repo with `explain-config` coverage

Each sample repo README includes the exact commands to run from that repo's `repo/` directory so config resolution matches current CLI behavior.

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

- `lintai-api` is the only stable publishable contract crate in `v0.1`.
- Findings now carry structured `evidence`, not just free-form messages.
- JSON machine output is versioned through `schema_version = 1`.
- `lintai-testing` remains internal for `v0.1` because it still depends on engine internals.

## Product Position

`lintai` is intentionally narrow in `v0.1`: offline-first, deterministic, and precision-first. It does not yet attempt broad multi-platform coverage, WASM/plugin runtime, registry scanning, or LSP workflows.
