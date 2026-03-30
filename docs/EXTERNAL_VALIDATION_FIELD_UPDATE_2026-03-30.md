# External Validation Field Update (2026-03-30)

> Manual field update after additional community and stratified validation waves.
> This document complements the ledger-bound checked-in reports and reflects the latest broad external scanning work across official, community, and stratified cohorts.

## Scope

- `1545` files scanned across all completed waves
- `82` total findings after precision hardening
- latest waves include official repos, community repos, and a stratified cohort split across:
  - offensive-security
  - MCP/tooling
  - marketing/general

## Current Product Readout

### Flagship rules

These are the rules that currently best represent `lintai` quality on real repos:

- `SEC352` — unscoped `Bash` grant in AI-native frontmatter
- `SEC347` — mutable MCP launcher in markdown setup docs
- `SEC340` — mutable package launcher in committed Claude hook settings
- `SEC329` — mutable package launcher in committed `mcp.json`

Why these four:

- they are easy to explain
- remediation is obvious
- they held up well under manual review
- they work on normal community repos, not only security-training corpora

### Domain-sensitive rules

These rules are still useful, but their match rate is more dependent on repo type:

- `SEC102`
- `SEC313`
- `SEC335`
- `SEC348`
- `SEC349`
- `SEC351`

These are better presented as cohort-aware security guidance than as homepage hero rules.

## Highest-Signal Findings

### `SEC352`

- latest field pass: `20` findings
- manual review: `20 TP`, `0 expected-but-benign`, `0 FP`
- strongest current skills-markdown rule by signal/noise
- promotion packet: [SEC352_STABLE_CANDIDATE_TRACK.md](SEC352_STABLE_CANDIDATE_TRACK.md)

### `SEC347 / SEC340 / SEC329`

- `SEC347`: `10` findings in current broad set, strong practical signal in setup docs
- `SEC340`: `1` high-confidence committed Claude settings hit
- `SEC329`: `1` high-confidence committed `mcp.json` hit

These remain the best operational MCP / Claude wiring rules.

## Wave Breakdown

### Official cohort

- `140` files
- `0` findings

### Community waves 1 + 2

- `458` files
- `28` findings

### Stratified wave 3

- `947` files
- `54` findings

Segment view for wave 3:

- offensive-security: `837` files, `33` findings
- MCP/tooling: `50` files, `1` finding
- marketing/general: `60` files, `20` findings

## Precision Notes

### `SEC352`

- precision story is strong enough to treat this as the leading promotion candidate
- remaining blocker is no longer "does this rule work?"
- remaining blocker is stable graduation process discipline

### `SEC102`

- still useful
- still exact enough to avoid false positives in the latest pass
- but often lands in expected dangerous examples on offensive-security corpora

### Recently hardened

- `SEC105` was tightened to ignore repo-local support paths like sibling `references/` and `assets/` targets
- `SEC312` now requires real PEM boundaries instead of matching bare search-string literals like `"BEGIN RSA PRIVATE KEY"`

## Recommended Next Step

Promote `SEC352` from "interesting preview rule" to an explicit stable-candidate track:

1. keep it featured on the site and in docs
2. preserve current corpus linkage and regression coverage
3. complete the stable checklist and one more broad precision pass

This is the clearest path to turning current external-validation evidence into a stronger public quality claim.
