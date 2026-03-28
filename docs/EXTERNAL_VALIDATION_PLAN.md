# External Validation Plan

> Canonical plan for the first external-repo validation wave.
> Scope: current `v0.1` security providers and repository-local agent artifacts only.

## Goal

Run `lintai` against a fixed cohort of `24` public repositories that materially match the current `v0.1` scan surface, then record:

- stable findings
- preview findings
- runtime parser issues
- false positives
- possible false negatives
- repo-level fit/noise verdicts

This wave is evaluation-only. It does not add new rules or change the public API.

## Cohort Design

The cohort is locked to `24` repositories with fixed category quotas:

- `10` `mcp`
- `6` `cursor_plugin`
- `8` `skills`

Important: `category` means the **primary validation focus** for the repo, not an exclusive taxonomy. A Cursor Plugin repo can be placed in the `mcp` bucket if the main external-validation target is its embedded `mcp.json` surface.

Each category includes:

- `stress` repos: richer network/auth/config surfaces
- `control` repos: expected clean or low-noise cases

## Selection Rules

A repo is admissible only if it:

- is public and non-archived
- contains at least one current `v0.1` target artifact
- is meaningfully about the selected validation focus
- is not just a list/index repo without scannable artifacts
- is not a giant unrelated monorepo where AI-agent artifacts are marginal

Target artifacts for this wave:

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

## Evaluation Workflow

For each shortlisted repo:

1. Clone and pin a commit SHA.
2. Inventory target surfaces.
3. Run:
   - `lintai scan .`
   - `lintai scan . --format=json`
4. Record:
   - stable findings
   - preview findings
   - findings by rule code
   - runtime parser errors
   - whether the repo stayed clean
5. Triage each finding as one of:
   - `true_positive`
   - `false_positive`
   - `ambiguous`
   - `expected_but_preview_only`
6. Record repo-level verdict as one of:
   - `strong_fit`
   - `useful_but_noisy`
   - `low_signal`
   - `out_of_scope`

Noise is judged primarily by `Stable` precision. `Preview` findings are evaluated for usefulness, not as release-blocking precision failures.

## Checked-In Artifacts

The external-validation package lives in:

- [validation/external-repos/repo-shortlist.toml](../validation/external-repos/repo-shortlist.toml)
- [validation/external-repos/ledger.toml](../validation/external-repos/ledger.toml)
- [validation/external-repos/README.md](../validation/external-repos/README.md)
- [EXTERNAL_VALIDATION_REPORT.md](EXTERNAL_VALIDATION_REPORT.md)

`repo-shortlist.toml` is the canonical selected cohort.

`ledger.toml` is the machine-readable result ledger and must include:

- repo identity + URL + pinned ref
- category + subtype
- surfaces present
- stable/preview counts
- stable/preview rule codes
- repo verdict
- stable precision notes
- preview signal notes
- false-positive notes
- possible false-negative notes
- follow-up action
- runtime errors

## Decision Policy

After each validation wave:

- recurring `Stable` FP clusters -> prioritize precision hardening
- clean `Stable` layer plus useful `Preview` signals -> prioritize structural rule expansion
- many `out_of_scope` repos -> tighten positioning/docs before rule expansion

The checked-in result of this first wave is documented in [EXTERNAL_VALIDATION_REPORT.md](EXTERNAL_VALIDATION_REPORT.md).
