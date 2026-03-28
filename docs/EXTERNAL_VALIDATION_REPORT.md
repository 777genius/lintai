# External Validation Report

> Second checked-in external validation summary for `lintai` after Phase 1 precision hardening.
> Cohort source of truth lives in [validation/external-repos/repo-shortlist.toml](../validation/external-repos/repo-shortlist.toml), current results in [validation/external-repos/ledger.toml](../validation/external-repos/ledger.toml), and wave 1 baseline in [validation/external-repos/archive/wave1-ledger.toml](../validation/external-repos/archive/wave1-ledger.toml).

## Cohort Composition

The current cohort still contains `24` public repositories:

- `10` `mcp`-focused repos
- `6` `cursor_plugin`-focused repos
- `8` `skills`-focused repos

## Overall Counts

Current checked-in wave 2 results:

- `24` repos evaluated
- `2` total findings
- `0` stable findings
- `2` preview findings
- `0` runtime parser errors
- `2` diagnostics

## Delta From Previous Wave

- stable findings: `0` -> `0`
- preview findings: `1` -> `2`
- runtime parser errors: `2` -> `0`
- diagnostics: `0` -> `2`
- repo verdict changes:
  - `cursor/plugins`: `useful_but_noisy` -> `strong_fit`
  - `datadog-labs/cursor-plugin`: `useful_but_noisy` -> `strong_fit`
  - `Emmraan/agent-skills`: `useful_but_noisy` -> `strong_fit`

## Stable Precision Summary

The current `Stable` layer remains clean across wave 2:

- no `Stable` findings were emitted
- no `Stable` false-positive cluster was observed
- no new `Stable` release-blocking noise signal surfaced in this wave

## Preview Usefulness Summary

Wave 2 produced `2` preview finding(s).

- `datadog-labs/cursor-plugin`: `improved`
- `zebbern/claude-code-guide`: `2` preview finding(s) via `SEC313`

## Runtime / Diagnostic Notes

- `cursor/plugins`: `improved`
- `Emmraan/agent-skills`: `improved`

## Top FP Clusters

1. No false-positive cluster observed in this wave.
2. No false-positive cluster observed in this wave.
3. No false-positive cluster observed in this wave.

## Top FN Clusters

1. No false-negative cluster observed in this wave.
2. No false-negative cluster observed in this wave.
3. No false-negative cluster observed in this wave.

## Recommended Next Step

`public beta`

Rationale:

- this report is grounded in the current checked-in wave 2 ledger and archived wave 1 baseline
- the known Phase 1 follow-up repos are called out explicitly above
- the current results do not show a new `Stable` precision regression
