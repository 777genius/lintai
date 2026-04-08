# External Validation Report

> Third checked-in external validation summary for `lintai` after broader-mix precision evidence hardening.
> Cohort source of truth lives in [validation/external-repos/repo-shortlist.toml](../validation/external-repos/repo-shortlist.toml), current results in [validation/external-repos/ledger.toml](../validation/external-repos/ledger.toml), and wave 2 baseline in [validation/external-repos/archive/wave2-ledger.toml](../validation/external-repos/archive/wave2-ledger.toml).

## Cohort Composition

The current cohort still contains `48` public repositories:

- `20` `mcp`-focused repos
- `12` `cursor_plugin`-focused repos
- `16` `skills`-focused repos

## Overall Counts

Current checked-in wave 3 results:

- `48` repos evaluated
- `2199` total findings
- `1059` stable findings
- `1140` preview findings
- `2` runtime parser errors
- `40` diagnostics

## Recommended Counts By Tier

- stable findings: `17`
- preview findings: `27`

## Supply-Chain Counts By Tier

- stable findings: `132`
- preview findings: `94`

## Cohort Ownership Split

- total official repos: `20`
- total community repos: `28`

## Recommended Stable By Ownership

- official `recommended stable` hit count: `10`
- community `recommended stable` hit count: `7`

## Zero-Hit Coverage By Ownership

- official repos with `0` `recommended stable` hits: `17`
- community repos with `0` `recommended stable` hits: `21`

## Remaining Non-Default Lane Totals

- `base`: `23` stable, `0` preview
- `claude`: `19` stable, `27` preview
- `mcp`: `20` stable, `0` preview
- `preview`: `904` stable, `1046` preview
- `skills`: `888` stable, `1019` preview

## Hybrid Scope Expansion Results

Current wave inventory for the newly expanded JSON lanes:

- repos with root `mcp.json`: `6`
- repos with `.mcp.json`: `10`
- repos with `.cursor/mcp.json`: `0`
- repos with `.vscode/mcp.json`: `0`
- repos with `.roo/mcp.json`: `1`
- repos with `.kiro/settings/mcp.json`: `1`
- repos with `gemini-extension.json`: `2`
- repos with `gemini.settings.json`: `1`
- repos with `.gemini/settings.json`: `0`
- repos with `vscode.settings.json`: `0`
- repos with `.claude/mcp/*.json`: `1`
- repos with Docker-based MCP launch configs: `3`
- MCP findings from expanded client-config coverage (`SEC301`-`SEC331`, `SEC337`-`SEC339`, `SEC346`): `13`
- findings from `SEC336`: `0`
- findings from `SEC337`-`SEC339`, `SEC346`: `3`
- AI-native markdown preview findings:
  - `SEC313` fenced pipe-to-shell examples: `4`
  - `SEC335` metadata-service access examples: `1`
  - `SEC347` mutable MCP setup launcher examples: `9`
    - CLI-form repo hits: `1`
    - config-snippet-form repo hits: `9`
  - `SEC348` mutable Docker registry-image examples: `5`
  - `SEC349` Docker host-escape or privileged runtime examples: `2`
  - `SEC350` untrusted-input instruction-promotion examples: `0`
  - `SEC351` approval-bypass instruction examples: `4`
  - `SEC352` unscoped Bash tool grants in frontmatter: `7`
  - `SEC353` Copilot instruction files above 4000 chars: `0`
  - `SEC354` path-specific Copilot instructions missing `applyTo`: `0`
  - `SEC355` wildcard tool grants in frontmatter: `0`
  - `SEC356` plugin agent frontmatter `permissionMode`: `0`
  - `SEC357` plugin agent frontmatter `hooks`: `0`
  - `SEC358` plugin agent frontmatter `mcpServers`: `0`
  - `SEC359` Cursor rule non-boolean `alwaysApply`: `0`
  - `SEC360` Cursor rule non-sequence `globs`: `2`
  - `SEC361` Claude settings missing `$schema`: `6`
  - `SEC362` Claude settings wildcard `Bash(*)` permissions: `1`
  - `SEC363` Claude settings home-directory hook commands: `1`
  - `SEC364` Claude settings `bypassPermissions` default mode: `0`
  - `SEC365` Claude settings non-HTTPS `allowedHttpHookUrls`: `0`
  - `SEC366` Claude settings dangerous host literals in `allowedHttpHookUrls`: `0`
  - `SEC367` Claude settings wildcard `WebFetch(*)` permissions: `1`
  - `SEC368` Claude settings repo-external absolute hook paths: `0`
  - `SEC369` Claude settings wildcard `Write(*)` permissions: `1`
  - `SEC370` path-specific Copilot instructions using the wrong suffix: `0`
  - `SEC371` path-specific Copilot instructions with invalid `applyTo`: `0`
  - `SEC377` path-specific Copilot instructions with invalid `applyTo` globs: `0`
  - `SEC378` Cursor rules with redundant `globs` alongside `alwaysApply: true`: `2`
  - `SEC379` Cursor rules with unknown frontmatter keys: `0`
  - `SEC380` Cursor rules missing `description`: `2`
  - `SEC381` Claude settings command hooks missing `timeout`: `4`
  - `SEC382` Claude settings `matcher` on unsupported hook events: `4`
  - `SEC383` Claude settings missing `matcher` on matcher-capable hook events: `0`
  - `SEC384` Claude settings bare `WebSearch` permissions: `2`
  - `SEC385` Claude settings shared `git push` permissions: `1`
  - `SEC386` Claude settings shared `git checkout:*` permissions: `1`
  - `SEC387` Claude settings shared `git commit:*` permissions: `1`
  - `SEC388` Claude settings shared `git stash:*` permissions: `1`
  - `SEC394` MCP configs with wildcard `autoApprove`: `0`
  - `SEC395` MCP configs with `autoApproveTools: true`: `0`
  - `SEC396` MCP configs with `trustTools: true`: `0`
  - `SEC397` MCP configs with sandbox disabled: `0`
  - `SEC398` MCP configs with wildcard capabilities: `0`
  - `SEC399` Claude settings shared `Bash(npx ...)` permissions: `1`
  - `SEC400` Claude settings shared `enabledMcpjsonServers`: `2`
  - `SEC405` Claude settings shared package installation permissions: `0`
  - `SEC406` Claude settings shared `git add` permissions: `1`
  - `SEC407` Claude settings shared `git clone` permissions: `1`
  - `SEC408` Claude settings shared `gh pr` permissions: `0`
  - `SEC502` Claude settings shared `gh api --method POST` permissions: `0`
  - `SEC503` Claude settings shared `gh issue create` permissions: `0`
  - `SEC504` Claude settings shared `gh repo create` permissions: `0`
  - `SEC508` Claude settings shared `gh secret set` permissions: `0`
  - `SEC509` Claude settings shared `gh variable set` permissions: `0`
  - `SEC510` Claude settings shared `gh workflow run` permissions: `0`
  - `SEC514` Claude settings shared `gh secret delete` permissions: `0`
  - `SEC515` Claude settings shared `gh variable delete` permissions: `0`
  - `SEC516` Claude settings shared `gh workflow disable` permissions: `0`
  - `SEC409` Claude settings shared `git fetch` permissions: `1`
  - `SEC410` Claude settings shared `git ls-remote` permissions: `1`
  - `SEC411` Claude settings shared `curl` permissions: `1`
  - `SEC412` Claude settings shared `wget` permissions: `0`
  - `SEC413` Claude settings shared `git config` permissions: `1`
  - `SEC414` Claude settings shared `git tag` permissions: `1`
  - `SEC415` Claude settings shared `git branch` permissions: `1`
  - `SEC416` AI-native markdown bare `pip install` Claude transcripts: `0`
  - `SEC417` AI-native markdown unpinned `pip install git+https://...` examples: `2`
  - `SEC418` Claude settings raw GitHub content fetch permissions: `1`
  - `SEC474` AI-native markdown shared `gh pr` tool grants: `0`
  - `SEC475` Claude settings unsafe `Read(...)` path permissions: `0`
  - `SEC476` Claude settings unsafe `Write(...)` path permissions: `0`
  - `SEC477` Claude settings unsafe `Edit(...)` path permissions: `0`
  - `SEC478` Claude settings shared `git reset:*` permissions: `0`
  - `SEC479` Claude settings shared `git clean:*` permissions: `0`
  - `SEC480` Claude settings shared `git restore:*` permissions: `0`
  - `SEC481` Claude settings shared `git rebase:*` permissions: `0`
  - `SEC482` Claude settings shared `git merge:*` permissions: `0`
  - `SEC483` Claude settings shared `git cherry-pick:*` permissions: `1`
  - `SEC484` Claude settings shared `git apply:*` permissions: `0`
  - `SEC485` Claude settings shared `git am:*` permissions: `0`
  - `SEC486` Claude settings unsafe `Glob(...)` path permissions: `0`
  - `SEC487` Claude settings unsafe `Grep(...)` path permissions: `0`
  - `SEC488` Claude settings shared `Bash(uvx ...)` permissions: `0`
  - `SEC489` Claude settings shared `Bash(pnpm dlx ...)` permissions: `0`
  - `SEC490` Claude settings shared `Bash(yarn dlx ...)` permissions: `0`
  - `SEC491` Claude settings shared `Bash(pipx run ...)` permissions: `0`
  - `SEC492` Claude settings shared `Bash(npm exec ...)` permissions: `0`
  - `SEC493` Claude settings shared `Bash(bunx ...)` permissions: `0`
  - `SEC494` AI-native markdown shared `npm exec` tool grants: `0`
  - `SEC495` AI-native markdown shared `bunx` tool grants: `0`
  - `SEC496` AI-native markdown shared `uvx` tool grants: `0`
  - `SEC497` AI-native markdown shared `pnpm dlx` tool grants: `0`
  - `SEC498` AI-native markdown shared `yarn dlx` tool grants: `0`
  - `SEC499` AI-native markdown shared `pipx run` tool grants: `0`
  - `SEC500` AI-native markdown shared `npx` tool grants: `0`
  - `SEC501` AI-native markdown shared `git ls-remote` tool grants: `0`
  - `SEC505` AI-native markdown shared `gh api --method POST` tool grants: `0`
  - `SEC506` AI-native markdown shared `gh issue create` tool grants: `0`
  - `SEC507` AI-native markdown shared `gh repo create` tool grants: `0`
  - `SEC511` AI-native markdown shared `gh secret set` tool grants: `0`
  - `SEC512` AI-native markdown shared `gh variable set` tool grants: `0`
  - `SEC513` AI-native markdown shared `gh workflow run` tool grants: `0`
  - `SEC517` AI-native markdown shared `gh secret delete` tool grants: `0`
  - `SEC518` AI-native markdown shared `gh variable delete` tool grants: `0`
  - `SEC519` AI-native markdown shared `gh workflow disable` tool grants: `0`
  - `SEC372` Claude settings wildcard `Read(*)` permissions: `1`
  - `SEC373` Claude settings wildcard `Edit(*)` permissions: `1`
  - `SEC374` Claude settings wildcard `WebSearch(*)` permissions: `1`
  - `SEC375` Claude settings wildcard `Glob(*)` permissions: `1`
  - `SEC376` Claude settings wildcard `Grep(*)` permissions: `1`
  - current `SEC347` usefulness is being driven mainly by MCP config snippets
- repos with `tool_descriptor_json`: `10`
- findings from `SEC314`-`SEC318`: `0`
- repos where new MCP client-config variants existed only under fixture-like paths: `1`
- repos where Docker-based MCP launch existed only under fixture-like client-config variants: `0`
- no non-fixture external `Stable` hits were produced yet on committed tool-descriptor JSON
- `SEC348` repo-level preview hits on the canonical cohort:
  - `jeremylongshore/claude-code-plugins-plus-skills`: `1` preview finding(s) via `SEC348`
  - `giuseppe-trisciuoglio/developer-kit-claude-code`: `1` preview finding(s) via `SEC348`
  - `zebbern/claude-code-guide`: `1` preview finding(s) via `SEC348`
  - `zechenzhangAGI/AI-research-SKILLs`: `1` preview finding(s) via `SEC348`
  - `trailofbits/skills`: `1` preview finding(s) via `SEC348`
- `SEC349` repo-level preview hits on the canonical cohort:
  - `zechenzhangAGI/AI-research-SKILLs`: `1` preview finding(s) via `SEC349`
  - `trailofbits/skills`: `1` preview finding(s) via `SEC349`
- `SEC350` produced no repo-level preview hits yet on the canonical cohort
- `SEC351` repo-level preview hits on the canonical cohort:
  - `jeremylongshore/claude-code-plugins-plus-skills`: `1` preview finding(s) via `SEC351`
  - `agent-sh/agentsys`: `1` preview finding(s) via `SEC351`
  - `zechenzhangAGI/AI-research-SKILLs`: `1` preview finding(s) via `SEC351`
  - `buildingopen/claude-setup`: `1` preview finding(s) via `SEC351`
- `SEC352` produced no repo-level preview hits yet on the canonical cohort
- `SEC353` produced no repo-level preview hits yet on the canonical cohort
- `SEC354` produced no repo-level preview hits yet on the canonical cohort
- `SEC355` produced no repo-level preview hits yet on the canonical cohort
- `SEC356` produced no repo-level preview hits yet on the canonical cohort
- `SEC357` produced no repo-level preview hits yet on the canonical cohort
- `SEC358` produced no repo-level preview hits yet on the canonical cohort
- `SEC359` produced no repo-level preview hits yet on the canonical cohort
- `SEC360` repo-level preview hits on the canonical cohort:
  - `TencentCloudBase/CloudBase-MCP`: `1` preview finding(s) via `SEC360`
  - `blockscout/mcp-server`: `1` preview finding(s) via `SEC360`
- `SEC361` repo-level preview hits on the canonical cohort:
  - `airmcp-com/mcp-standards`: `1` preview finding(s) via `SEC361`
  - `centminmod/my-claude-code-setup`: `1` preview finding(s) via `SEC361`
  - `TencentCloudBase/CloudBase-MCP`: `1` preview finding(s) via `SEC361`
  - `blockscout/mcp-server`: `1` preview finding(s) via `SEC361`
  - `agent-sh/agentsys`: `1` preview finding(s) via `SEC361`
  - `buildingopen/claude-setup`: `1` preview finding(s) via `SEC361`
- `SEC362` produced no repo-level preview hits yet on the canonical cohort
- `SEC363` repo-level preview hits on the canonical cohort:
  - `buildingopen/claude-setup`: `1` preview finding(s) via `SEC363`
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
- `SEC378` repo-level preview hits on the canonical cohort:
  - `blockscout/mcp-server`: `1` preview finding(s) via `SEC378`
  - `get-convex/convex-agent-plugins`: `1` preview finding(s) via `SEC378`
- `SEC379` produced no repo-level preview hits yet on the canonical cohort
- `SEC380` repo-level preview hits on the canonical cohort:
  - `TencentCloudBase/CloudBase-MCP`: `1` preview finding(s) via `SEC380`
  - `blockscout/mcp-server`: `1` preview finding(s) via `SEC380`
- `SEC381` repo-level preview hits on the canonical cohort:
  - `airmcp-com/mcp-standards`: `1` preview finding(s) via `SEC381`
  - `centminmod/my-claude-code-setup`: `1` preview finding(s) via `SEC381`
  - `blockscout/mcp-server`: `1` preview finding(s) via `SEC381`
  - `buildingopen/claude-setup`: `1` preview finding(s) via `SEC381`
- `SEC382` repo-level preview hits on the canonical cohort:
  - `airmcp-com/mcp-standards`: `1` preview finding(s) via `SEC382`
  - `centminmod/my-claude-code-setup`: `1` preview finding(s) via `SEC382`
  - `blockscout/mcp-server`: `1` preview finding(s) via `SEC382`
  - `buildingopen/claude-setup`: `1` preview finding(s) via `SEC382`
- `SEC383` produced no repo-level preview hits yet on the canonical cohort
- `SEC384` produced no repo-level preview hits yet on the canonical cohort
- `SEC385` repo-level preview hits on the canonical cohort:
  - `airmcp-com/mcp-standards`: `1` preview finding(s) via `SEC385`
- `SEC386` repo-level preview hits on the canonical cohort:
  - `airmcp-com/mcp-standards`: `1` preview finding(s) via `SEC386`
- `SEC387` repo-level preview hits on the canonical cohort:
  - `airmcp-com/mcp-standards`: `1` preview finding(s) via `SEC387`
- `SEC388` repo-level preview hits on the canonical cohort:
  - `airmcp-com/mcp-standards`: `1` preview finding(s) via `SEC388`
- `SEC399` repo-level preview hits on the canonical cohort:
  - `airmcp-com/mcp-standards`: `1` preview finding(s) via `SEC399`
- `SEC400` produced no repo-level preview hits yet on the canonical cohort
- `SEC405` produced no repo-level preview hits yet on the canonical cohort
- `SEC406` repo-level preview hits on the canonical cohort:
  - `airmcp-com/mcp-standards`: `1` preview finding(s) via `SEC406`
- `SEC407` repo-level preview hits on the canonical cohort:
  - `blockscout/mcp-server`: `1` preview finding(s) via `SEC407`
- `SEC408` produced no repo-level preview hits yet on the canonical cohort
- `SEC502` produced no repo-level preview hits yet on the canonical cohort
- `SEC503` produced no repo-level preview hits yet on the canonical cohort
- `SEC504` produced no repo-level preview hits yet on the canonical cohort
- `SEC508` produced no repo-level preview hits yet on the canonical cohort
- `SEC509` produced no repo-level preview hits yet on the canonical cohort
- `SEC510` produced no repo-level preview hits yet on the canonical cohort
- `SEC514` produced no repo-level preview hits yet on the canonical cohort
- `SEC515` produced no repo-level preview hits yet on the canonical cohort
- `SEC516` produced no repo-level preview hits yet on the canonical cohort
- `SEC409` repo-level preview hits on the canonical cohort:
  - `blockscout/mcp-server`: `1` preview finding(s) via `SEC409`
- `SEC410` repo-level preview hits on the canonical cohort:
  - `blockscout/mcp-server`: `1` preview finding(s) via `SEC410`
- `SEC411` produced no repo-level preview hits yet on the canonical cohort
- `SEC412` produced no repo-level preview hits yet on the canonical cohort
- `SEC413` produced no repo-level preview hits yet on the canonical cohort
- `SEC414` produced no repo-level preview hits yet on the canonical cohort
- `SEC415` produced no repo-level preview hits yet on the canonical cohort
- `SEC416` produced no repo-level preview hits yet on the canonical cohort
- `SEC417` produced no repo-level preview hits yet on the canonical cohort
- `SEC418` produced no repo-level preview hits yet on the canonical cohort
- `SEC474` produced no repo-level preview hits yet on the canonical cohort
- `SEC475` produced no repo-level preview hits yet on the canonical cohort
- `SEC476` produced no repo-level preview hits yet on the canonical cohort
- `SEC477` produced no repo-level preview hits yet on the canonical cohort
- `SEC478` produced no repo-level preview hits yet on the canonical cohort
- `SEC479` produced no repo-level preview hits yet on the canonical cohort
- `SEC480` produced no repo-level preview hits yet on the canonical cohort
- `SEC481` produced no repo-level preview hits yet on the canonical cohort
- `SEC482` produced no repo-level preview hits yet on the canonical cohort
- `SEC483` repo-level preview hits on the canonical cohort:
  - `centminmod/my-claude-code-setup`: `1` preview finding(s) via `SEC483`
- `SEC484` produced no repo-level preview hits yet on the canonical cohort
- `SEC485` produced no repo-level preview hits yet on the canonical cohort
- `SEC486` produced no repo-level preview hits yet on the canonical cohort
- `SEC487` produced no repo-level preview hits yet on the canonical cohort
- `SEC488` produced no repo-level preview hits yet on the canonical cohort
- `SEC489` produced no repo-level preview hits yet on the canonical cohort
- `SEC490` produced no repo-level preview hits yet on the canonical cohort
- `SEC491` produced no repo-level preview hits yet on the canonical cohort
- `SEC492` produced no repo-level preview hits yet on the canonical cohort
- `SEC493` produced no repo-level preview hits yet on the canonical cohort
- `SEC494` produced no repo-level preview hits yet on the canonical cohort
- `SEC495` produced no repo-level preview hits yet on the canonical cohort
- `SEC496` produced no repo-level preview hits yet on the canonical cohort
- `SEC497` produced no repo-level preview hits yet on the canonical cohort
- `SEC498` produced no repo-level preview hits yet on the canonical cohort
- `SEC499` produced no repo-level preview hits yet on the canonical cohort
- `SEC500` produced no repo-level preview hits yet on the canonical cohort
- `SEC501` produced no repo-level preview hits yet on the canonical cohort
- `SEC505` produced no repo-level preview hits yet on the canonical cohort
- `SEC506` produced no repo-level preview hits yet on the canonical cohort
- `SEC507` produced no repo-level preview hits yet on the canonical cohort
- `SEC511` produced no repo-level preview hits yet on the canonical cohort
- `SEC512` produced no repo-level preview hits yet on the canonical cohort
- `SEC513` produced no repo-level preview hits yet on the canonical cohort
- `SEC517` produced no repo-level preview hits yet on the canonical cohort
- `SEC518` produced no repo-level preview hits yet on the canonical cohort
- `SEC519` produced no repo-level preview hits yet on the canonical cohort
- `SEC394` produced no repo-level stable hits yet on the canonical cohort
- `SEC395` produced no repo-level stable hits yet on the canonical cohort
- `SEC396` produced no repo-level stable hits yet on the canonical cohort
- `SEC397` produced no repo-level stable hits yet on the canonical cohort
- `SEC398` produced no repo-level stable hits yet on the canonical cohort
- fixture/testdata/example suppression stayed active for the newly added MCP client-config variants and did not create a fake usefulness signal from fixture-like paths

## Delta From Previous Wave

- stable findings: `75` -> `1059`
- preview findings: `86` -> `1140`
- runtime parser errors: `0` -> `2`
- diagnostics: `4` -> `40`
- repo verdict changes: none

## Adjudication Coverage For Recommended Stable

- recommended stable findings: `17`
- adjudicated hits: `17`
- unadjudicated hits: `0`
- adjudicated false positives: `0`

## Reviewed Recommended Stable Hits

- `TencentCloudBase/CloudBase-MCP`: `SEC329` at `.mcp.json` - `confirmed_issue` - committed MCP config launches through npx
  reason: `.mcp.json` uses `command: "npx"` with `@cloudbase/cloudbase-mcp@latest` in committed MCP server config.
  problem: mutable package launcher in committed MCP config
- `TencentCloudBase/CloudBase-MCP`: `SEC329` at `config/source/editor-config/files/gemini.settings.json` - `confirmed_issue` - committed MCP config launches through npx
  reason: `config/source/editor-config/files/gemini.settings.json` uses `command: "npx"` with mutable `npm-global-exec@latest` and `@cloudbase/cloudbase-mcp@latest`.
  problem: mutable package launcher in committed MCP config
- `TencentCloudBase/CloudBase-MCP`: `SEC329` at `gemini-extension.json` - `confirmed_issue` - committed MCP config launches through npx
  reason: `gemini-extension.json` uses `command: "npx"` with mutable `npm-global-exec@latest` and `@cloudbase/cloudbase-mcp@latest`.
  problem: mutable package launcher in committed MCP config
- `TencentCloudBase/CloudBase-MCP`: `SEC329` at `mcp/.mcp.json` - `confirmed_issue` - committed MCP config launches through npx
  reason: `mcp/.mcp.json` uses `command: "npx"` with mutable `npm-global-exec@latest` and `@cloudbase/cloudbase-mcp@latest`.
  problem: mutable package launcher in committed MCP config
- `TencentCloudBase/CloudBase-MCP`: `SEC329` at `mcp/mcp.json` - `confirmed_issue` - committed MCP config launches through npx
  reason: `mcp/mcp.json` uses `command: "npx"` with mutable `npm-global-exec@latest` and `@cloudbase/cloudbase-mcp@latest`.
  problem: mutable package launcher in committed MCP config
- `affaan-m/everything-claude-code`: `SEC329` at `.mcp.json` - `confirmed_issue` - committed MCP config launches through npx
  reason: `.mcp.json` uses committed `npx` launchers for multiple MCP servers including `@modelcontextprotocol/server-github`, `@upstash/context7-mcp`, and `@playwright/mcp`.
  problem: mutable package launcher in committed MCP config
- `airmcp-com/mcp-standards`: `SEC340` at `.claude/settings.json` - `confirmed_issue` - committed Claude hook executes through npx
  reason: `.claude/settings.json` contains committed command hooks invoking `npx claude-flow@alpha ...`.
  problem: mutable package launcher in committed Claude hook config
- `alirezarezvani/claude-skills`: `SEC329` at `engineering-team/playwright-pro/.mcp.json` - `confirmed_issue` - committed MCP config launches through npx
  reason: `engineering-team/playwright-pro/.mcp.json` uses `command: "npx"` to run committed `tsx`-based MCP integrations.
  problem: mutable package launcher in committed MCP config
- `anthropics/claude-plugins-official`: `SEC329` at `external_plugins/context7/.mcp.json` - `confirmed_issue` - committed MCP config launches through mutable package runner
  reason: `external_plugins/context7/.mcp.json` uses `command: "npx"` with `@upstash/context7-mcp` in committed plugin MCP config.
  problem: mutable package launcher in committed MCP config
- `anthropics/claude-plugins-official`: `SEC329` at `external_plugins/firebase/.mcp.json` - `confirmed_issue` - committed MCP config launches through mutable package runner
  reason: `external_plugins/firebase/.mcp.json` uses `command: "npx"` with mutable `firebase-tools@latest mcp`.
  problem: mutable package launcher in committed MCP config
- `anthropics/claude-plugins-official`: `SEC329` at `external_plugins/playwright/.mcp.json` - `confirmed_issue` - committed MCP config launches through mutable package runner
  reason: `external_plugins/playwright/.mcp.json` uses `command: "npx"` with `@playwright/mcp@latest` in committed plugin MCP config.
  problem: mutable package launcher in committed MCP config
- `anthropics/claude-plugins-official`: `SEC329` at `external_plugins/serena/.mcp.json` - `confirmed_issue` - committed MCP config launches through mutable package runner
  reason: `external_plugins/serena/.mcp.json` uses `command: "uvx"` with `git+https://github.com/oraios/serena` in committed plugin MCP config.
  problem: mutable package launcher in committed MCP config
- `buildingopen/claude-setup`: `SEC329` at `claude/.mcp.json` - `confirmed_issue` - committed MCP config launches through npx
  reason: `claude/.mcp.json` uses `command: "npx"` with `-y session-recall --mcp` in committed MCP server config.
  problem: mutable package launcher in committed MCP config
- `centminmod/my-claude-code-setup`: `SEC329` at `.claude/mcp/chrome-devtools.json` - `confirmed_issue` - committed MCP config launches through npx
  reason: `.claude/mcp/chrome-devtools.json` sets `command: "npx"` with `chrome-devtools-mcp@latest`.
  problem: mutable package launcher in committed MCP config
- `get-convex/convex-agent-plugins`: `SEC329` at `mcp.json` - `confirmed_issue` - committed MCP config launches through npx
  reason: `mcp.json` uses `command: "npx"` with `-y convex@latest mcp start` in committed plugin MCP config.
  problem: mutable package launcher in committed MCP config
- `olostep/olostep-cursor-plugin`: `SEC329` at `mcp.json` - `confirmed_issue` - committed MCP config launches through npx
  reason: `mcp.json` uses `command: "npx"` with `-y olostep-mcp` in committed MCP server config.
  problem: mutable package launcher in committed MCP config
- `van-reflect/cursor-plugin`: `SEC329` at `.mcp.json` - `confirmed_issue` - committed MCP config launches through npx
  reason: `.mcp.json` uses `command: "npx"` with `-y reflect-memory-mcp` in committed MCP server config.
  problem: mutable package launcher in committed MCP config

## Preview Usefulness Summary

Wave 2 produced `1140` preview finding(s).

- `datadog-labs/cursor-plugin`: `stayed unchanged`
- `containers/kubernetes-mcp-server`: `3` preview finding(s) via `SEC328`
- `modelcontextprotocol/registry`: `10` preview finding(s) via `SEC328`
- `airmcp-com/mcp-standards`: `18` preview finding(s) via `SEC328`, `SEC347`, `SEC361`, `SEC381`, `SEC382`, `SEC385`, `SEC386`, `SEC387`, `SEC388`, `SEC399`, `SEC406`
- `centminmod/my-claude-code-setup`: `5` preview finding(s) via `SEC361`, `SEC381`, `SEC382`, `SEC483`
- `olostep/olostep-cursor-plugin`: `2` preview finding(s) via `SEC347`
- `cloudflare/mcp-server-cloudflare`: `1` preview finding(s) via `SEC328`
- `googleworkspace/developer-tools`: `2` preview finding(s) via `SEC328`
- `hashicorp/terraform-mcp-server`: `1` preview finding(s) via `SEC328`
- `github/github-mcp-server`: `10` preview finding(s) via `SEC325`, `SEC328`
- `docker/hub-mcp`: `6` preview finding(s) via `SEC328`
- `TencentCloudBase/CloudBase-MCP`: `11` preview finding(s) via `SEC328`, `SEC347`, `SEC360`, `SEC361`, `SEC380`
- `gitkraken/MCP-Docs`: `1` preview finding(s) via `SEC328`
- `VictoriaMetrics-Community/mcp-victoriametrics`: `5` preview finding(s) via `SEC328`
- `OriShmila/alpha-vantage-mcp-server`: `1` preview finding(s) via `SEC347`
- `blockscout/mcp-server`: `40` preview finding(s) via `SEC328`, `SEC360`, `SEC361`, `SEC378`, `SEC380`, `SEC381`, `SEC382`, `SEC407`, `SEC409`, `SEC410`
- `anthropics/claude-plugins-official`: `1` preview finding(s) via `SEC347`
- `affaan-m/everything-claude-code`: `8` preview finding(s) via `SEC313`, `SEC328`, `SEC347`
- `jeremylongshore/claude-code-plugins-plus-skills`: `921` preview finding(s) via `SEC102`, `SEC105`, `SEC313`, `SEC328`, `SEC347`, `SEC348`, `SEC351`, `SEC389`, `SEC404`, `SEC419`
- `get-convex/convex-agent-plugins`: `17` preview finding(s) via `SEC378`
- `agent-sh/agentsys`: `6` preview finding(s) via `SEC102`, `SEC328`, `SEC351`, `SEC361`
- `giuseppe-trisciuoglio/developer-kit-claude-code`: `6` preview finding(s) via `SEC328`, `SEC348`, `SEC404`
- `agent-sh/agnix`: `27` preview finding(s) via `SEC325`, `SEC328`
- `zebbern/claude-code-guide`: `8` preview finding(s) via `SEC313`, `SEC335`, `SEC348`
- `zechenzhangAGI/AI-research-SKILLs`: `8` preview finding(s) via `SEC328`, `SEC348`, `SEC349`, `SEC351`
- `buildingopen/claude-setup`: `5` preview finding(s) via `SEC351`, `SEC361`, `SEC363`, `SEC381`, `SEC382`
- `alirezarezvani/claude-skills`: `5` preview finding(s) via `SEC105`, `SEC328`
- `trailofbits/skills`: `9` preview finding(s) via `SEC313`, `SEC348`, `SEC349`, `SEC389`, `SEC404`, `SEC419`
- `Jeffallan/claude-skills`: `2` preview finding(s) via `SEC328`, `SEC347`
- `coleam00/second-brain-skills`: `1` preview finding(s) via `SEC347`

## Runtime / Diagnostic Notes

- `cursor/plugins`: `stayed unchanged`
- `Emmraan/agent-skills`: `stayed unchanged`

## Top FP Clusters

1. No false-positive cluster observed in this wave.
2. No false-positive cluster observed in this wave.
3. No false-positive cluster observed in this wave.

## Top FN Clusters

1. No false-negative cluster observed in this wave.
2. No false-negative cluster observed in this wave.
3. No false-negative cluster observed in this wave.

## Recommended Next Step

`credible prod evidence for default precision`

Rationale:

- this report is grounded in the current checked-in wave 3 ledger and archived wave 2 baseline
- recommended stable precision is now evaluated from explicit preset-lane evidence and structured adjudications
- ownership split is now a checked-in part of the evidence model instead of an informal reading of repo owners
- cohort size reached the `48`-repo bar and official coverage reached the `12`-repo target
- every currently observed `recommended` stable hit has an adjudication and none of them is marked `false_positive`
