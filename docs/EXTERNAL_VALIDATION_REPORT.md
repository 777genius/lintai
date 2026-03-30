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
  - `SEC353` Copilot instruction files above 4000 chars: `0`
  - `SEC354` path-specific Copilot instructions missing `applyTo`: `0`
  - `SEC355` wildcard tool grants in frontmatter: `0`
  - `SEC356` plugin agent frontmatter `permissionMode`: `0`
  - `SEC357` plugin agent frontmatter `hooks`: `0`
  - `SEC358` plugin agent frontmatter `mcpServers`: `0`
  - `SEC359` Cursor rule non-boolean `alwaysApply`: `0`
  - `SEC360` Cursor rule non-sequence `globs`: `0`
  - `SEC361` Claude settings missing `$schema`: `0`
  - `SEC362` Claude settings wildcard `Bash(*)` permissions: `0`
  - `SEC363` Claude settings home-directory hook commands: `0`
  - `SEC364` Claude settings `bypassPermissions` default mode: `0`
  - `SEC365` Claude settings non-HTTPS `allowedHttpHookUrls`: `0`
  - `SEC366` Claude settings dangerous host literals in `allowedHttpHookUrls`: `0`
  - `SEC367` Claude settings wildcard `WebFetch(*)` permissions: `0`
  - `SEC368` Claude settings repo-external absolute hook paths: `0`
  - `SEC369` Claude settings wildcard `Write(*)` permissions: `0`
  - `SEC370` path-specific Copilot instructions using the wrong suffix: `0`
  - `SEC371` path-specific Copilot instructions with invalid `applyTo`: `0`
  - `SEC377` path-specific Copilot instructions with invalid `applyTo` globs: `0`
  - `SEC378` Cursor rules with redundant `globs` alongside `alwaysApply: true`: `0`
  - `SEC379` Cursor rules with unknown frontmatter keys: `0`
  - `SEC380` Cursor rules missing `description`: `0`
  - `SEC381` Claude settings command hooks missing `timeout`: `0`
  - `SEC382` Claude settings `matcher` on unsupported hook events: `0`
  - `SEC383` Claude settings missing `matcher` on matcher-capable hook events: `0`
  - `SEC384` Claude settings bare `WebSearch` permissions: `0`
  - `SEC385` Claude settings shared `git push` permissions: `0`
  - `SEC386` Claude settings shared `git checkout:*` permissions: `0`
  - `SEC387` Claude settings shared `git commit:*` permissions: `0`
  - `SEC388` Claude settings shared `git stash:*` permissions: `0`
  - `SEC394` MCP configs with wildcard `autoApprove`: `0`
  - `SEC395` MCP configs with `autoApproveTools: true`: `0`
  - `SEC396` MCP configs with `trustTools: true`: `0`
  - `SEC372` Claude settings wildcard `Read(*)` permissions: `0`
  - `SEC373` Claude settings wildcard `Edit(*)` permissions: `0`
  - `SEC374` Claude settings wildcard `WebSearch(*)` permissions: `0`
  - `SEC375` Claude settings wildcard `Glob(*)` permissions: `0`
  - `SEC376` Claude settings wildcard `Grep(*)` permissions: `0`
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
- `SEC353` produced no repo-level preview hits yet on the canonical cohort
- `SEC354` produced no repo-level preview hits yet on the canonical cohort
- `SEC355` produced no repo-level preview hits yet on the canonical cohort
- `SEC356` produced no repo-level preview hits yet on the canonical cohort
- `SEC357` produced no repo-level preview hits yet on the canonical cohort
- `SEC358` produced no repo-level preview hits yet on the canonical cohort
- `SEC359` produced no repo-level preview hits yet on the canonical cohort
- `SEC360` produced no repo-level preview hits yet on the canonical cohort
- `SEC361` produced no repo-level preview hits yet on the canonical cohort
- `SEC362` produced no repo-level preview hits yet on the canonical cohort
- `SEC363` produced no repo-level preview hits yet on the canonical cohort
- `SEC364` produced no repo-level preview hits yet on the canonical cohort
- `SEC365` produced no repo-level preview hits yet on the canonical cohort
- `SEC366` produced no repo-level preview hits yet on the canonical cohort
- `SEC367` produced no repo-level preview hits yet on the canonical cohort
- `SEC368` produced no repo-level preview hits yet on the canonical cohort
- `SEC369` produced no repo-level preview hits yet on the canonical cohort
- `SEC370` produced no repo-level preview hits yet on the canonical cohort
- `SEC371` produced no repo-level preview hits yet on the canonical cohort
- `SEC372` produced no repo-level preview hits yet on the canonical cohort
- `SEC373` produced no repo-level preview hits yet on the canonical cohort
- `SEC374` produced no repo-level preview hits yet on the canonical cohort
- `SEC375` produced no repo-level preview hits yet on the canonical cohort
- `SEC376` produced no repo-level preview hits yet on the canonical cohort
- `SEC377` produced no repo-level preview hits yet on the canonical cohort
- `SEC378` produced no repo-level preview hits yet on the canonical cohort
- `SEC379` produced no repo-level preview hits yet on the canonical cohort
- `SEC380` produced no repo-level preview hits yet on the canonical cohort
- `SEC381` produced no repo-level preview hits yet on the canonical cohort
- `SEC382` produced no repo-level preview hits yet on the canonical cohort
- `SEC383` produced no repo-level preview hits yet on the canonical cohort
- `SEC384` produced no repo-level preview hits yet on the canonical cohort
- `SEC385` produced no repo-level preview hits yet on the canonical cohort
- `SEC386` produced no repo-level preview hits yet on the canonical cohort
- `SEC387` produced no repo-level preview hits yet on the canonical cohort
- `SEC388` produced no repo-level preview hits yet on the canonical cohort
- `SEC394` produced no repo-level stable hits yet on the canonical cohort
- `SEC395` produced no repo-level stable hits yet on the canonical cohort
- `SEC396` produced no repo-level stable hits yet on the canonical cohort
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
