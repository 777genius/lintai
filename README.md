# lintai

Fast offline security checks for AI agent artifacts in your repo.

`lintai` helps you verify skills, MCP configs, agent rules, hooks, and plugin manifests before you trust them in local workflows or CI.
It can also run an opt-in advisory lane for committed npm lockfiles.

Public beta release: `v0.1.0-beta.1`

- Fast local and CI checks
- Deterministic findings with evidence
- Helps verify artifacts before use

`lintai` helps raise confidence and find risky patterns. It does not guarantee that an artifact is completely safe.

## Why `lintai` exists

Skills, MCP configs, agent rules, hooks, and plugin manifests are not just docs or metadata. They are trust surfaces that can change agent behavior, launch tools, route network access, and carry risky auth or execution patterns.

`lintai` exists to make those artifacts easier to verify before use, before sharing, and before merge. It is built for fast local runs, repeatable CI checks, and private repositories where offline-first verification matters.

Think of it as a Ruff/Biome-style workflow for agent artifact security: fast, deterministic, and meant to run often.

## Quick Start

Install the public beta CLI from GitHub Releases:

```bash
curl -fsSLO https://github.com/777genius/lintai/releases/download/v0.1.0-beta.1/lintai-installer.sh
sh ./lintai-installer.sh
```

Run a first scan:

```bash
lintai scan .
lintai scan . --format sarif
```

Exit codes:

- `0`: no blocking findings
- `1`: blocking findings were emitted
- `2`: execution or configuration error

Interpretation:

- `Stable` findings are the release-quality baseline.
- `Preview` findings are useful signals, but not the baseline trust bar.

## What It Scans

Current `v0.1` supported surfaces focus on files that steer agent behavior or launch agent tooling.

### Agent instructions

- `SKILL.md`
- `CLAUDE.md`
- `.mdc`
- `.cursorrules`
- `.github/copilot-instructions.md`

### MCP and client config artifacts

- `mcp.json`
- `claude_desktop_config.json`
- `server.json`
- supported known client roots discovered by `scan-known` and `inventory-os`

### Plugin and hook surfaces

- `.cursor-plugin/plugin.json`
- `.cursor-plugin/hooks.json`
- `.cursor-plugin/hooks/**/*.sh`
- `.cursor-plugin/commands/**/*.md`
- `.cursor-plugin/agents/**/*.md`

### Opt-in advisory lockfile surfaces

- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`

## Advisory Lane

The dependency advisory lane is intentionally opt-in. Enable it in the target repository root:

```toml
[presets]
enable = ["advisory"]
```

Then run the scan from that repository root so `lintai` picks up the local `lintai.toml`:

```bash
cd your-repo
lintai scan .
lintai explain-config lintai.toml
```

This lane matches installed versions from committed npm lockfiles against the active offline advisory snapshot, using the bundled dataset by default. It does not guess from `package.json` version ranges and it does not perform live network lookups during scan.

The bundled snapshot can also be inspected or normalized explicitly:

```bash
lintai advisory-db export-bundled
lintai advisory-db update --input advisories.json --output advisories.normalized.json
```

To scan with a custom normalized snapshot instead of the bundled one:

```bash
cd your-repo
LINTAI_ADVISORY_SNAPSHOT=/path/to/advisories.normalized.json lintai scan .
```

If the custom snapshot is unreadable or violates the advisory schema contract, `lintai scan` fails closed: it reports a runtime error and exits with code `2` instead of silently falling back to bundled data.

The advisory lane also fails closed when a committed lockfile records an advisory-tracked package with an invalid installed version string. That prevents false-clean scans when the lockfile data itself is malformed.

## What It Catches

Current `lintai` rules focus on high-signal repository-local risks such as:

- hidden or override-style instructions in agent-facing markdown
- unsafe shell execution paths in MCP or plugin configs
- insecure endpoints and TLS bypass patterns
- credential passthrough and literal secret material
- dangerous download-and-exec flows
- mismatches between declared safety claims and actual capabilities
- opt-in advisory matches between committed npm lockfiles and the active offline advisory snapshot

The full shipped rule catalog lives in [`docs/SECURITY_RULES.md`](docs/SECURITY_RULES.md).

## Trust Signal

`lintai` is designed to support a guarded trust signal, not an absolute one.

- For users: run `lintai` before trusting a skill, MCP config, or plugin artifact.
- For authors: use `lintai` before publishing or sharing an artifact.
- For teams: require `lintai` checks in CI for repo-local agent artifacts.

Practical language should be:

- `passed lintai checks`
- `helps verify`
- `gives confidence`

Not:

- `guaranteed safe`
- `fully secure`

## Stable vs Preview

`lintai` is intentionally precision-first.

- `Stable` rules are the current release-quality baseline and are meant to be deterministic, explainable, and low-noise.
- `Preview` rules are valuable, but they are still under usefulness and precision review.
- The goal is not maximal heuristic coverage. The goal is trustworthy findings you can run often.

This is especially important for markdown-like agent surfaces, where some security checks are useful but still more text-sensitive than the strongest structural rules.

## CI, SARIF, and Exit Codes

`lintai` is built for frequent local runs and CI integration.

- Text, JSON, and SARIF output are supported.
- Findings include stable rule ids and structured evidence.
- Exit codes are designed for gating workflows cleanly.

Examples:

```bash
lintai scan .
lintai scan . --format json
lintai scan . --format sarif
```

## Preset Policy

`lintai` now resolves findings through builtin policy presets declared in `lintai.toml`.

Default behavior:

- if `[presets]` is omitted, `lintai` enables `["recommended"]`
- `recommended` is the quiet practical default for most teams
- `base` remains the minimal stable baseline for compatibility-focused setups
- `preview` is explicit opt-in for deeper review
- `compat` is explicit opt-in for project policy mismatch rules such as `SEC401`-`SEC403`
- `governance` is explicit opt-in for workflow-policy review rules such as shared mutation authority and broad bare tool grants that should not read like headline security findings

Example:

```toml
[presets]
enable = ["recommended", "preview"]

[categories]
security = "warn"

[rules]
SEC201 = "deny"
```

Builtin preset intent:

- `recommended`: quiet practical default for most teams
- `base`: stable compatibility baseline
- `strict`: `recommended` plus stricter preset-level hardening
- `compat`: transition and project-policy mismatch lane
- `preview`: deeper review lane with broader and more context-sensitive findings
- `skills`: instruction and skills markdown overlays
- `mcp`: MCP and tool/server config overlays
- `claude`: Claude-specific config overlays
- `guidance`: advice-oriented guidance lane
- `governance`: opt-in review lane for shared mutation authority and broad default bare tool grants in checked-in AI-native frontmatter
- `supply-chain`: sidecar supply-chain hardening lane
- `advisory`: opt-in offline dependency vulnerability lane for committed npm lockfiles

Important merge rules:

- `[[overrides]]` can change severities for matching files, but cannot change preset membership
- category overrides do not implicitly activate rules outside the resolved preset set
- explicit `[rules] SECxxx = "..."` can opt a specific rule in on purpose
- shipped rule catalogs carry preset membership as source-of-truth metadata, so docs, engine resolution, and explainability stay aligned

For teams evaluating the beta, a good default is:

1. Start with `recommended`.
2. Add `preview` when you want deeper review.
3. Add `governance` only when you want shared-authority and least-privilege review.
4. Keep `diagnostics` separate from security findings.

Treat `diagnostics` separately from findings.

## Installed Artifact Audit

Repository scans are the primary workflow, but `lintai` can also help audit what your AI clients already have configured.

Use this as a secondary workflow to:

- audit known local client roots
- inventory discovered agent-related artifacts
- compare current installed state against a baseline

Examples:

```bash
lintai scan-known --scope=both
lintai inventory-os --scope=user
lintai inventory-os --scope=user --preset base --preset mcp --preset claude
lintai inventory-os --scope=user --write-baseline .lintai-baseline.json
lintai inventory-os --scope=user --diff-against .lintai-baseline.json
lintai policy-os --policy machine-policy.toml --scope=user
```

`scan-known` and `inventory-os` stay quiet by default and follow the `recommended` lane unless you opt into broader review with repeated `--preset` flags.

`policy-os` keeps a more diagnostic machine-policy default so explicit policy checks still evaluate MCP and Claude machine artifacts even when the main product default stays quiet.

This mode stays inventory-first: it reports what `lintai` can honestly discover and only emits findings for supported surfaces it can actually analyze today.

## Install Details

The current public beta is distributed through GitHub Releases with prebuilt binaries.

### macOS / Linux

```bash
curl -fsSLO https://github.com/777genius/lintai/releases/download/v0.1.0-beta.1/lintai-installer.sh
sh ./lintai-installer.sh
```

The installer downloads the tagged archive and `SHA256SUMS`, verifies the checksum, and installs `lintai` into `~/.local/bin` by default.

### Windows PowerShell

```powershell
Invoke-WebRequest -Uri https://github.com/777genius/lintai/releases/download/v0.1.0-beta.1/lintai-installer.ps1 -OutFile .\lintai-installer.ps1
powershell -ExecutionPolicy Bypass -File .\lintai-installer.ps1
```

The PowerShell installer downloads the tagged archive and `SHA256SUMS`, verifies the checksum, and installs `lintai.exe` into `%USERPROFILE%\.local\bin` by default.

### Manual archive install

1. Download the archive for your target from the GitHub Release.
2. Download `SHA256SUMS` from the same release and verify the archive checksum.
3. Extract `lintai` or `lintai.exe` into a directory on your `PATH`.

### Post-install verification

```bash
lintai help
lintai config-schema
lintai scan .
```

## Project Status and Docs

Current status:

- Public beta: `v0.1.0-beta.1`
- Precision-first security checks for supported agent artifact surfaces
- Best evaluated on real repositories that already contain those surfaces
- `Stable` findings are the current trust baseline
- Honest posture: strong public beta / early-adopter tool, not yet a broad `1.0` ecosystem platform

## Current Non-Goals

Not the goal in `v0.1`:

- cloud-managed threat intel
- broad registry crawling or package reputation services
- scan-everything coverage across every AI platform from day one
- aggressive heuristic coverage at the cost of materially more noise

Canonical docs:

- [`docs/POSITIONING_AND_SCOPE.md`](docs/POSITIONING_AND_SCOPE.md): product positioning and non-goals
- [`docs/PUBLIC_BETA_RELEASE.md`](docs/PUBLIC_BETA_RELEASE.md): current beta contract
- [`docs/EXTERNAL_VALIDATION_REPORT.md`](docs/EXTERNAL_VALIDATION_REPORT.md): checked-in beta evidence base
- [`docs/INDEX.md`](docs/INDEX.md): full project doc index

Repo-level orientation:

- [`V0_1_RELEASE_CHARTER.md`](V0_1_RELEASE_CHARTER.md)
- [`PUBLIC_COMPATIBILITY_POLICY.md`](PUBLIC_COMPATIBILITY_POLICY.md)
- [`ARCH_GAPS.md`](ARCH_GAPS.md)

`lintai-api` remains the only stable publishable crate. The CLI beta does not yet promise Homebrew, npm, or `cargo install` distribution.
