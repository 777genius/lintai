# lintai

Fast offline security checks for AI agent artifacts in your repo.

`lintai` helps you verify skills, MCP configs, agent rules, hooks, and plugin manifests before you trust them in local workflows or CI.

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

## What It Catches

Current `lintai` rules focus on high-signal repository-local risks such as:

- hidden or override-style instructions in agent-facing markdown
- unsafe shell execution paths in MCP or plugin configs
- insecure endpoints and TLS bypass patterns
- credential passthrough and literal secret material
- dangerous download-and-exec flows
- mismatches between declared safety claims and actual capabilities

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

For teams evaluating the beta, a good default is:

1. Gate on blocking `Stable` findings.
2. Review `Preview` findings separately.
3. Keep `diagnostics` separate from security findings.

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
lintai inventory-os --scope=user --write-baseline .lintai-baseline.json
lintai inventory-os --scope=user --diff-against .lintai-baseline.json
```

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
