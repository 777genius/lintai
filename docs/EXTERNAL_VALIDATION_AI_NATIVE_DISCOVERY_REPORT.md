# External Validation AI-Native Discovery Report

> Wave 1 discovery report for real AI-native execution surfaces that are only partially covered by the current shipped detector.
> Source of truth lives in [validation/external-repos-ai-native/repo-shortlist.toml](../validation/external-repos-ai-native/repo-shortlist.toml) and [validation/external-repos-ai-native/ledger.toml](../validation/external-repos-ai-native/ledger.toml).

## Cohort Composition

- `8` repos evaluated
- `2` `mcp_docker` repos
- `5` `claude_settings_command` repos
- `1` `plugin_execution_reference` repos

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
- `0` admitted paths are currently covered by shipped detector kinds
- `15` admitted paths are discovery-only and not directly scanned by current detector kinds
- `0` repos have at least one currently covered admission path
- `8` repos are discovery-only under current detector coverage

Discovery-only admission paths:

- `hashicorp/terraform-mcp-server`: `gemini-extension.json`
- `SonarSource/sonarqube-mcp-server`: `gemini-extension.json`
- `airmcp-com/mcp-standards`: `.claude/settings.json`
- `blockscout/mcp-server`: `.claude/settings.json`
- `centminmod/my-claude-code-setup`: `.claude/settings.json`
- `buildingopen/claude-setup`: `claude/settings.json`
- `cursor/plugins`: `agent-compatibility/agents/compatibility-scan-review.md`, `agent-compatibility/agents/startup-review.md`, `agent-compatibility/agents/validation-review.md`, `continual-learning/agents/agents-memory-updater.md`, `continual-learning/hooks/hooks.json`, `create-plugin/agents/plugin-architect.md`, `cursor-team-kit/agents/ci-watcher.md`, `ralph-loop/hooks/hooks.json`
- `tldraw/tldraw`: `.claude/settings.json`

## Overall Counts

- `39` stable findings across whole-repo scans
- `24` preview findings across whole-repo scans
- `0` runtime parser errors
- `1` diagnostics

## Stable Hits

- current AI-native MCP rule families produced `3` repo-level rule-code hits in this discovery wave
- some repo-level hits were observed, but current scan output still needs path-attribution work before claiming they came from discovery-only admission paths rather than sibling scanned surfaces

## Preview Hits

- `24` preview hit(s) were observed at repo scope; these should not yet be interpreted as proof on discovery-only admission paths

## Runtime / Diagnostic Notes

- `cursor/plugins`: `0` runtime parser errors, `1` diagnostics (non-admission-path issue)

## Recommended Next Step

Use this package as discovery evidence for the next detector expansion. The immediate product work should target currently uncovered `.claude/settings.json`, plugin-root `hooks.json` / `agents/*.md`, and committed Docker-oriented client config files before widening non-AI-native surfaces.
