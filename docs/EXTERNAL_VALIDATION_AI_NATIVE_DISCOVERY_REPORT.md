# External Validation AI-Native Discovery Report

> Wave 1 discovery report for real AI-native execution surfaces that are only partially covered by the current shipped detector.
> Source of truth lives in [validation/external-repos-ai-native/repo-shortlist.toml](../validation/external-repos-ai-native/repo-shortlist.toml) and [validation/external-repos-ai-native/ledger.toml](../validation/external-repos-ai-native/ledger.toml).

## Cohort Composition

- `8` repos evaluated
- `2` `mcp_docker` repos
- `5` `claude_settings_command` repos
- `1` `plugin_execution_reference` repos

## Overall Counts

- `45` stable findings across whole-repo scans
- `31` preview findings across whole-repo scans
- `0` runtime parser errors
- `1` diagnostics

## Admission Results

- `hashicorp/terraform-mcp-server` via `gemini-extension.json`. Committed Gemini extension config launches the MCP server via docker run from a repo-local JSON file.
- `SonarSource/sonarqube-mcp-server` via `gemini-extension.json`. Committed Gemini extension config launches the MCP server via docker run and represents a real repo-local client execution surface.
- `airmcp-com/mcp-standards` via `.claude/settings.json`. Repository-local Claude settings file contains multiple command-type hook definitions under hooks.
- `blockscout/mcp-server` via `.claude/settings.json`. Committed .claude/settings.json contains command hook execution entries under hooks.
- `centminmod/my-claude-code-setup` via `.claude/settings.json`. Committed .claude/settings.json exposes command-type hooks in a real user-facing Claude setup repo.
- `buildingopen/claude-setup` via `claude/settings.json`. Committed claude/settings.json contains multiple command hook entries and represents a real repo-local Claude execution surface.
- `cursor/plugins` via `agent-compatibility/agents/compatibility-scan-review.md`, `agent-compatibility/agents/startup-review.md`, `agent-compatibility/agents/validation-review.md`, `continual-learning/agents/agents-memory-updater.md`, `continual-learning/hooks/hooks.json`, `create-plugin/agents/plugin-architect.md`, `cursor-team-kit/agents/ci-watcher.md`, `ralph-loop/hooks/hooks.json`. Plugin manifests in the marketplace repo point to real repo-root hook registries and agent markdown files outside the currently shipped .cursor-plugin-only detector paths.
- `tldraw/tldraw` via `.claude/settings.json`. Large real-world repo with a committed .claude/settings.json containing command hook execution entries.

## Coverage Status

- `15` total admitted paths
- `15` admitted paths are currently covered by shipped detector kinds
- `0` admitted paths are discovery-only and not directly scanned by current detector kinds
- `8` repos have at least one currently covered admission path
- `0` repos are discovery-only under current detector coverage

- `2` plugin-root hook admission paths are now covered
- `6` plugin-root agent markdown admission paths are now covered

- `0` plugin-root command markdown admission paths are now covered

- `2` Gemini-style MCP client admission paths are now covered

Currently covered admission paths:

- `hashicorp/terraform-mcp-server`: `gemini-extension.json`
- `SonarSource/sonarqube-mcp-server`: `gemini-extension.json`
- `airmcp-com/mcp-standards`: `.claude/settings.json`
- `blockscout/mcp-server`: `.claude/settings.json`
- `centminmod/my-claude-code-setup`: `.claude/settings.json`
- `buildingopen/claude-setup`: `claude/settings.json`
- `cursor/plugins`: `agent-compatibility/agents/compatibility-scan-review.md`, `agent-compatibility/agents/startup-review.md`, `agent-compatibility/agents/validation-review.md`, `continual-learning/agents/agents-memory-updater.md`, `continual-learning/hooks/hooks.json`, `create-plugin/agents/plugin-architect.md`, `cursor-team-kit/agents/ci-watcher.md`, `ralph-loop/hooks/hooks.json`
- `tldraw/tldraw`: `.claude/settings.json`

- `hashicorp/terraform-mcp-server` is now `covered` under shipped AI-native detector coverage
- `SonarSource/sonarqube-mcp-server` is now `covered` under shipped AI-native detector coverage

## Stable Hits

- current AI-native MCP rule families produced `7` repo-level rule-code hits in this discovery wave
- repo-level AI-native rule hits were observed after the latest detector expansion. Treat these as repo-scope evidence first, then inspect path attribution before claiming they all came from newly covered admission paths.

- `SonarSource/sonarqube-mcp-server`: `1` repo-level stable finding(s) via `SEC346`

## Preview Hits

- `31` preview hit(s) were observed at repo scope; these should not yet be interpreted as proof on discovery-only admission paths

- `SEC361` Claude settings files missing `$schema`: `0`
- `SEC362` Claude settings files allowing `Bash(*)`: `0`
- `SEC363` Claude settings files with home-directory hook commands: `0`
- `SEC364` Claude settings files with `permissions.defaultMode = bypassPermissions`: `0`
- `SEC365` Claude settings files with non-HTTPS `allowedHttpHookUrls`: `0`
- `SEC366` Claude settings files with dangerous host literals in `allowedHttpHookUrls`: `0`
- `SEC367` Claude settings files allowing `WebFetch(*)`: `0`
- `SEC368` Claude settings files with repo-external absolute hook paths: `0`
- `SEC369` Claude settings files allowing `Write(*)`: `0`
- `SEC370` path-specific Copilot instructions using the wrong suffix: `0`
- `SEC371` path-specific Copilot instructions with invalid `applyTo`: `0`
- `SEC372` Claude settings files allowing `Read(*)`: `0`
- `SEC373` Claude settings files allowing `Edit(*)`: `0`
- `SEC374` Claude settings files allowing `WebSearch(*)`: `0`
- `SEC375` Claude settings files allowing `Glob(*)`: `0`
- `SEC376` Claude settings files allowing `Grep(*)`: `0`
- `SEC381` Claude settings command hooks missing `timeout`: `0`
- `SEC382` Claude settings `matcher` on unsupported hook events: `0`
- `SEC383` Claude settings missing `matcher` on matcher-capable hook events: `0`
- `SEC384` Claude settings bare `WebSearch` permissions: `0`
- AI-native markdown preview hits by rule code: `SEC313`=`0`, `SEC335`=`0`, `SEC347`=`1`, `SEC348`=`0`, `SEC349`=`0`, `SEC350`=`0`, `SEC351`=`0`, `SEC352`=`0`, `SEC353`=`0`, `SEC354`=`0`, `SEC355`=`0`, `SEC356`=`0`, `SEC357`=`0`, `SEC358`=`0`, `SEC359`=`0`, `SEC360`=`0`, `SEC370`=`0`, `SEC371`=`0`, `SEC377`=`0`, `SEC378`=`0`, `SEC379`=`0`, `SEC380`=`0`
- `SEC347` subtype repo hits: CLI-form=`1`, config-snippet-form=`1`
- current markdown usefulness is still mainly skills / `CLAUDE.md`; plugin-root command docs remain a non-driving surface with `0` admitted covered paths

- current `SEC347` usefulness is being driven mainly by a split mix of command-line onboarding examples and MCP config snippets

- `SEC313` produced no repo-level external preview hits in this wave
- `SEC335` produced no repo-level external preview hits in this wave
- `airmcp-com/mcp-standards`: `1` repo-level preview finding(s) via `SEC347`
- `SEC348` produced no repo-level external preview hits in this wave
- `SEC349` produced no repo-level external preview hits in this wave
- `SEC350` produced no repo-level external preview hits in this wave
- `SEC351` produced no repo-level external preview hits in this wave
- `SEC352` produced no repo-level external preview hits in this wave
- `SEC353` produced no repo-level external preview hits in this wave
- `SEC354` produced no repo-level external preview hits in this wave
- `SEC355` produced no repo-level external preview hits in this wave
- `SEC356` produced no repo-level external preview hits in this wave
- `SEC357` produced no repo-level external preview hits in this wave
- `SEC358` produced no repo-level external preview hits in this wave
- `SEC359` produced no repo-level external preview hits in this wave
- `SEC360` produced no repo-level external preview hits in this wave
- `SEC361` produced no repo-level external preview hits in this wave
- `SEC362` produced no repo-level external preview hits in this wave
- `SEC363` produced no repo-level external preview hits in this wave
- `SEC364` produced no repo-level external preview hits in this wave
- `SEC365` produced no repo-level external preview hits in this wave
- `SEC366` produced no repo-level external preview hits in this wave
- `SEC367` produced no repo-level external preview hits in this wave
- `SEC368` produced no repo-level external preview hits in this wave
- `SEC369` produced no repo-level external preview hits in this wave
- `SEC370` produced no repo-level external preview hits in this wave
- `SEC371` produced no repo-level external preview hits in this wave
- `SEC372` produced no repo-level external preview hits in this wave
- `SEC373` produced no repo-level external preview hits in this wave
- `SEC374` produced no repo-level external preview hits in this wave
- `SEC375` produced no repo-level external preview hits in this wave
- `SEC376` produced no repo-level external preview hits in this wave
- `SEC377` produced no repo-level external preview hits in this wave
- `SEC378` produced no repo-level external preview hits in this wave
- `SEC379` produced no repo-level external preview hits in this wave
- `SEC380` produced no repo-level external preview hits in this wave
- `SEC381` produced no repo-level external preview hits in this wave
- `SEC382` produced no repo-level external preview hits in this wave
- `SEC383` produced no repo-level external preview hits in this wave
- `SEC384` produced no repo-level external preview hits in this wave

## Runtime / Diagnostic Notes

- `cursor/plugins`: `0` runtime parser errors, `1` diagnostics (non-admission-path issue)

- `cursor/plugins` currently reports `0` stable and `0` preview findings at repo scope after plugin-root target coverage expansion

## Recommended Next Step

Use this package as discovery evidence for the next detector expansion. There are no remaining discovery-only admission paths in the current checked-in AI-native cohort, and markdown usefulness is still being driven mainly by skills / `CLAUDE.md` rather than plugin-root command docs.
