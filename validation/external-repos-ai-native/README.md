# AI-Native Discovery Package

This package tracks a focused external discovery wave for repository-local AI execution surfaces that are important to `lintai` but are only partially covered by the current shipped detector.

The cohort is intentionally small and conservative:

- committed Docker-oriented MCP client configs such as `gemini-extension.json`
- committed `.claude/settings.json` or `claude/settings.json` files with command hooks
- plugin manifests that reference real repo-root `hooks.json`, `agents/*.md`, or `.mcp.json` execution targets

The goal of this package is not to inflate usefulness counts. It is to answer two narrower questions:

1. how common are these AI-native execution surfaces in real public repos
2. which of them are still discovery-only under the current detector coverage

Current source-of-truth files:

- `repo-shortlist.toml`
- `ledger.toml`
- `../../docs/EXTERNAL_VALIDATION_AI_NATIVE_DISCOVERY_REPORT.md`
