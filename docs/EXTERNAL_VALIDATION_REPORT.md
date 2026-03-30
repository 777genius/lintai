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
- `110` total findings
- `46` stable findings
- `64` preview findings
- `0` runtime parser errors
- `3` diagnostics

## Hybrid Scope Expansion Results

Current wave inventory for the newly expanded JSON lanes:

- repos with root `mcp.json`: `5`
- repos with `.mcp.json`: `3`
- repos with `.cursor/mcp.json`: `0`
- repos with `.vscode/mcp.json`: `0`
- repos with `.roo/mcp.json`: `1`
- repos with `.kiro/settings/mcp.json`: `1`
- repos with `gemini-extension.json`: `0`
- repos with `gemini.settings.json`: `0`
- repos with `.gemini/settings.json`: `0`
- repos with `vscode.settings.json`: `0`
- repos with `.claude/mcp/*.json`: `1`
- repos with Docker-based MCP launch configs: `0`
- MCP findings from expanded client-config coverage (`SEC301`-`SEC331`, `SEC337`-`SEC339`, `SEC346`): `4`
- findings from `SEC336`: `0`
- findings from `SEC337`-`SEC339`, `SEC346`: `0`
- AI-native markdown preview findings:
  - `SEC313` fenced pipe-to-shell examples: `1`
  - `SEC335` metadata-service access examples: `1`
  - `SEC347` mutable MCP setup launcher examples: `3`
    - CLI-form repo hits: `2`
    - config-snippet-form repo hits: `3`
  - `SEC348` mutable Docker registry-image examples: `2`
  - `SEC349` Docker host-escape or privileged runtime examples: `0`
  - `SEC350` untrusted-input instruction-promotion examples: `0`
  - `SEC351` approval-bypass instruction examples: `0`
  - `SEC352` unscoped Bash tool grants in frontmatter: `0`
  - current `SEC347` usefulness is being driven mainly by MCP config snippets
- repos with `tool_descriptor_json`: `3`
- findings from `SEC314`-`SEC318`: `0`
- repos where new MCP client-config variants existed only under fixture-like paths: `1`
- repos where Docker-based MCP launch existed only under fixture-like client-config variants: `0`
- no external hits were produced yet from Docker-based MCP launch hardening on the canonical cohort
- no non-fixture external `Stable` hits were produced yet on committed tool-descriptor JSON
- `SEC348` repo-level preview hits on the canonical cohort:
  - `zebbern/claude-code-guide`: `1` preview finding(s) via `SEC348`
  - `zechenzhangAGI/AI-research-SKILLs`: `1` preview finding(s) via `SEC348`
- `SEC349` produced no repo-level preview hits yet on the canonical cohort
- `SEC350` produced no repo-level preview hits yet on the canonical cohort
- `SEC351` produced no repo-level preview hits yet on the canonical cohort
- `SEC352` produced no repo-level preview hits yet on the canonical cohort
- fixture/testdata/example suppression stayed active for the newly added MCP client-config variants and did not create a fake usefulness signal from fixture-like paths

## Delta From Previous Wave

- stable findings: `0` -> `46`
- preview findings: `1` -> `64`
- runtime parser errors: `2` -> `0`
- diagnostics: `0` -> `3`
- repo verdict changes:
  - `cursor/plugins`: `useful_but_noisy` -> `strong_fit`
  - `datadog-labs/cursor-plugin`: `useful_but_noisy` -> `strong_fit`
  - `Emmraan/agent-skills`: `useful_but_noisy` -> `strong_fit`

## Stable Precision Summary

Wave 2 surfaced `Stable` findings and requires another precision pass before beta.

## Preview Usefulness Summary

Wave 2 produced `64` preview finding(s).

- `datadog-labs/cursor-plugin`: `improved`
- `containers/kubernetes-mcp-server`: `3` preview finding(s) via `SEC328`
- `modelcontextprotocol/registry`: `10` preview finding(s) via `SEC328`
- `airmcp-com/mcp-standards`: `9` preview finding(s) via `SEC328`, `SEC347`
- `olostep/olostep-cursor-plugin`: `2` preview finding(s) via `SEC347`
- `agent-sh/agnix`: `27` preview finding(s) via `SEC325`, `SEC328`
- `zebbern/claude-code-guide`: `8` preview finding(s) via `SEC313`, `SEC335`, `SEC348`
- `zechenzhangAGI/AI-research-SKILLs`: `5` preview finding(s) via `SEC328`, `SEC347`, `SEC348`

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

`precision hardening`

Rationale:

- this report is grounded in the current checked-in wave 2 ledger and archived wave 1 baseline
- the known Phase 1 follow-up repos are called out explicitly above
- one or more wave 2 signals still require another precision pass before beta
