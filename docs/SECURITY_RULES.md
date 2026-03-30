# Security Rules Catalog

> Generated file. Do not edit by hand.
> Source: `lintai-cli` shipped rule inventory aggregated from provider catalogs.

Canonical catalog for the shipped security rules currently exposed by:
- `lintai-ai-security`
- `lintai-policy-mismatch`

## Summary

| Code | Summary | Tier | Lifecycle | Severity | Scope | Surface | Detection | Remediation | Presets |
|---|---|---|---|---|---|---|---|---|---|
| `SEC101 / MD-HIDDEN-INSTRUCTIONS` | Hidden HTML comment contains dangerous agent instructions | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `safe_fix` | `preview`, `skills` |
| `SEC102 / MD-DOWNLOAD-EXEC` | Markdown contains remote download-and-execute instruction outside code blocks | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `suggestion` | `preview`, `skills` |
| `SEC103 / MD-HIDDEN-DOWNLOAD-EXEC` | Hidden HTML comment contains remote download-and-execute instruction | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `safe_fix` | `preview`, `skills` |
| `SEC104 / MD-BASE64-EXEC` | Markdown contains a base64-decoded executable payload outside code blocks | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` | `preview`, `skills` |
| `SEC105 / MD-PATH-TRAVERSAL` | Markdown instructions reference parent-directory traversal for file access | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` | `preview`, `skills` |
| `SEC201 / HOOK-DOWNLOAD-EXEC` | Hook script downloads remote code and executes it | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `suggestion` | `base` |
| `SEC202 / HOOK-SECRET-EXFIL` | Hook script appears to exfiltrate secrets through a network call | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `suggestion` | `base` |
| `SEC203 / HOOK-PLAIN-HTTP-SECRET-EXFIL` | Hook script sends secret material to an insecure http:// endpoint | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `suggestion` | `base` |
| `SEC204 / HOOK-TLS-BYPASS` | Hook script disables TLS or certificate verification for a network call | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `base` |
| `SEC205 / HOOK-STATIC-AUTH` | Hook script embeds static authentication material in a network call | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `base` |
| `SEC206 / HOOK-BASE64-EXEC` | Hook script decodes a base64 payload and executes it | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `suggestion` | `base` |
| `SEC301 / MCP-SHELL-WRAPPER` | MCP configuration shells out through sh -c or bash -c | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC302 / MCP-PLAIN-HTTP-ENDPOINT` | Configuration contains an insecure http:// endpoint | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `suggestion` | `base`, `mcp` |
| `SEC303 / MCP-CREDENTIAL-ENV-PASSTHROUGH` | MCP configuration passes through credential environment variables | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC304 / MCP-TLS-BYPASS` | Configuration disables TLS or certificate verification | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC305 / MCP-STATIC-AUTH` | Configuration embeds static authentication material in a connection or auth value | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC306 / MCP-HIDDEN-INSTRUCTIONS` | JSON configuration description contains override-style hidden instructions | Preview | `preview_blocked` | Warn | `per_file` | `json` | `heuristic` | `message_only` | `preview`, `mcp` |
| `SEC307 / MCP-SENSITIVE-ENV-REFERENCE` | Configuration forwards sensitive environment variable references | Preview | `preview_blocked` | Warn | `per_file` | `json` | `heuristic` | `message_only` | `preview`, `mcp` |
| `SEC308 / MCP-SUSPICIOUS-ENDPOINT` | Configuration points at a suspicious remote endpoint | Preview | `preview_blocked` | Warn | `per_file` | `json` | `heuristic` | `message_only` | `preview`, `mcp` |
| `SEC309 / MCP-LITERAL-SECRET` | Configuration commits literal secret material in env, auth, or header values | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC310 / MCP-METADATA-HOST-LITERAL` | Configuration endpoint targets a metadata or private-network host literal | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC311 / PLUGIN-UNSAFE-PATH` | Cursor plugin manifest contains an unsafe absolute or parent-traversing path | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC312 / MD-PRIVATE-KEY` | Markdown contains committed private key material | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `base`, `skills` |
| `SEC313 / MD-PIPE-SHELL` | Fenced shell example pipes remote content directly into a shell | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC314 / TOOL-MISSING-MACHINE-FIELDS` | MCP-style tool descriptor is missing required machine fields | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC315 / TOOL-DUPLICATE-NAMES` | MCP-style tool descriptor collection contains duplicate tool names | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC316 / OPENAI-STRICT-ADDITIONAL-PROPERTIES` | OpenAI strict tool schema omits recursive additionalProperties: false | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC317 / OPENAI-STRICT-REQUIRED-COVERAGE` | OpenAI strict tool schema does not require every declared property | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC318 / ANTHROPIC-STRICT-ADDITIONAL-PROPERTIES` | Anthropic strict tool input schema omits additionalProperties: false | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC319 / SERVER-REMOTE-URL` | server.json remotes entry uses an insecure or non-public remote URL | Stable | `stable_gated` | Warn | `per_file` | `server_json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC320 / SERVER-UNDEFINED-URL-VAR` | server.json remotes URL references an undefined template variable | Stable | `stable_gated` | Warn | `per_file` | `server_json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC321 / SERVER-LITERAL-AUTH-HEADER` | server.json remotes header commits literal authentication material | Stable | `stable_gated` | Warn | `per_file` | `server_json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC322 / SERVER-UNDEFINED-HEADER-VAR` | server.json remotes header value references an undefined template variable | Stable | `stable_gated` | Warn | `per_file` | `server_json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC323 / SERVER-AUTH-SECRET-FLAG` | server.json auth header carries material without an explicit secret flag | Preview | `preview_blocked` | Warn | `per_file` | `server_json` | `structural` | `message_only` | `preview`, `mcp` |
| `SEC324 / GHA-UNPINNED-ACTION` | GitHub Actions workflow uses a third-party action that is not pinned to a full commit SHA | Stable | `stable_gated` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` | `supply-chain` |
| `SEC325 / GHA-UNTRUSTED-RUN-INTERPOLATION` | GitHub Actions workflow interpolates untrusted expression data directly inside a run command | Preview | `preview_blocked` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` | `supply-chain` |
| `SEC326 / GHA-PR-TARGET-HEAD-CHECKOUT` | GitHub Actions pull_request_target workflow checks out untrusted pull request head content | Stable | `stable_gated` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` | `supply-chain` |
| `SEC327 / GHA-WRITE-ALL-PERMISSIONS` | GitHub Actions workflow grants GITHUB_TOKEN write-all permissions | Stable | `stable_gated` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` | `supply-chain` |
| `SEC328 / GHA-WRITE-CAPABLE-THIRD-PARTY-ACTION` | GitHub Actions workflow combines explicit write-capable permissions with a third-party action | Preview | `preview_blocked` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` | `supply-chain` |
| `SEC329 / MCP-MUTABLE-LAUNCHER` | MCP configuration launches tooling through a mutable package runner | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC330 / MCP-DOWNLOAD-EXEC` | MCP configuration command downloads remote content and pipes it into a shell | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC331 / MCP-TLS-BYPASS` | MCP configuration command disables TLS verification in a network-capable execution path | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC335 / MD-METADATA-SERVICE-ACCESS` | AI-native markdown contains a direct cloud metadata-service access example | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC336 / MCP-BROAD-ENVFILE` | Repo-local MCP client config loads a broad dotenv-style envFile | Preview | `preview_blocked` | Warn | `per_file` | `json` | `structural` | `message_only` | `preview`, `mcp` |
| `SEC337 / MCP-DOCKER-UNPINNED-IMAGE` | MCP configuration launches Docker with an image reference that is not digest-pinned | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC338 / MCP-DOCKER-SENSITIVE-MOUNT` | MCP configuration launches Docker with a bind mount of sensitive host material | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC339 / MCP-DOCKER-HOST-ESCAPE` | MCP configuration launches Docker with a host-escape or privileged runtime flag | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC340 / CLAUDE-HOOK-MUTABLE-LAUNCHER` | Claude settings command hook uses a mutable package launcher | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `base`, `claude` |
| `SEC341 / CLAUDE-HOOK-DOWNLOAD-EXEC` | Claude settings command hook downloads remote content and pipes it into a shell | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `base`, `claude` |
| `SEC342 / CLAUDE-HOOK-TLS-BYPASS` | Claude settings command hook disables TLS verification in a network-capable execution path | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `base`, `claude` |
| `SEC343 / PLUGIN-HOOK-MUTABLE-LAUNCHER` | Plugin hook command uses a mutable package launcher | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC344 / PLUGIN-HOOK-DOWNLOAD-EXEC` | Plugin hook command downloads remote content and pipes it into a shell | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC345 / PLUGIN-HOOK-TLS-BYPASS` | Plugin hook command disables TLS verification in a network-capable execution path | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC346 / MCP-DOCKER-PULL-ALWAYS` | MCP configuration forces Docker to refresh from a mutable registry source | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC347 / MD-MCP-MUTABLE-LAUNCHER` | AI-native markdown example launches MCP through a mutable package runner | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC348 / MD-DOCKER-MUTABLE-IMAGE` | AI-native markdown Docker example uses a mutable registry image | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC349 / MD-DOCKER-HOST-ESCAPE` | AI-native markdown Docker example uses a host-escape or privileged runtime pattern | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC350 / MD-UNTRUSTED-INSTRUCTION-PROMOTION` | Instruction markdown promotes untrusted external content to developer/system-level instructions | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` | `preview`, `skills` |
| `SEC351 / MD-APPROVAL-BYPASS` | AI-native instruction explicitly disables user approval or confirmation | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` | `preview`, `skills` |
| `SEC352 / MD-UNSCOPED-BASH` | AI-native markdown frontmatter grants unscoped Bash tool access | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC353 / COPILOT-4K` | GitHub Copilot instruction markdown exceeds the 4000-character guidance limit | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC354 / COPILOT-PATH-APPLYTO` | Path-specific GitHub Copilot instruction markdown is missing `applyTo` frontmatter | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC355 / MD-WILDCARD-TOOLS` | AI-native markdown frontmatter grants wildcard tool access | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC356 / PLUGIN-AGENT-PERMISSIONMODE` | Plugin agent frontmatter sets `permissionMode` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC357 / PLUGIN-AGENT-HOOKS` | Plugin agent frontmatter sets `hooks` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC358 / PLUGIN-AGENT-MCPSERVERS` | Plugin agent frontmatter sets `mcpServers` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC359 / CURSOR-RULE-ALWAYSAPPLY` | Cursor rule frontmatter `alwaysApply` must be boolean | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC360 / CURSOR-RULE-GLOBS` | Cursor rule frontmatter `globs` must be a sequence of patterns | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC361 / CLAUDE-SETTINGS-SCHEMA` | Claude settings file is missing a top-level `$schema` reference | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC362 / CLAUDE-BASH-WILDCARD` | Claude settings permissions allow `Bash(*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC363 / CLAUDE-HOME-HOOK-PATH` | Claude settings hook command uses a home-directory path in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC364 / CLAUDE-BYPASS-PERMISSIONS` | Claude settings set `permissions.defaultMode` to `bypassPermissions` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC365 / CLAUDE-HTTP-HOOK-URL` | Claude settings allow non-HTTPS HTTP hook URLs in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC366 / CLAUDE-HTTP-HOOK-HOST` | Claude settings allow dangerous host literals in `allowedHttpHookUrls` | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC367 / CLAUDE-WEBFETCH-WILDCARD` | Claude settings permissions allow `WebFetch(*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC368 / CLAUDE-ABS-HOOK-PATH` | Claude settings hook command uses a repo-external absolute path in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC369 / CLAUDE-WRITE-WILDCARD` | Claude settings permissions allow `Write(*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC370 / COPILOT-PATH-SUFFIX` | Path-specific GitHub Copilot instruction markdown under `.github/instructions/` uses the wrong file suffix | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC371 / COPILOT-APPLYTO-TYPE` | Path-specific GitHub Copilot instruction markdown has an invalid `applyTo` shape | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC372 / CLAUDE-READ-WILDCARD` | Claude settings permissions allow `Read(*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC373 / CLAUDE-EDIT-WILDCARD` | Claude settings permissions allow `Edit(*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC374 / CLAUDE-WEBSEARCH-WILDCARD` | Claude settings permissions allow `WebSearch(*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC375 / CLAUDE-GLOB-WILDCARD` | Claude settings permissions allow `Glob(*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC376 / CLAUDE-GREP-WILDCARD` | Claude settings permissions allow `Grep(*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC377 / COPILOT-APPLYTO-GLOB` | Path-specific GitHub Copilot instruction markdown has an invalid `applyTo` glob pattern | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC378 / CURSOR-ALWAYSAPPLY-GLOBS` | Cursor rule frontmatter should not set `globs` when `alwaysApply` is `true` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC379 / CURSOR-UNKNOWN-FRONTMATTER` | Cursor rule frontmatter contains an unknown key | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC380 / CURSOR-DESCRIPTION` | Cursor rule frontmatter should include `description` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC381 / CLAUDE-HOOK-TIMEOUT` | Claude settings command hook should set `timeout` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC382 / CLAUDE-HOOK-MATCHER-EVENT` | Claude settings should not use `matcher` on unsupported hook events | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC383 / CLAUDE-HOOK-MISSING-MATCHER` | Claude settings should set `matcher` on matcher-capable hook events | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC384 / CLAUDE-WEBSEARCH-UNSCOPED` | Claude settings permissions allow bare `WebSearch` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC401 / POLICY-EXEC-MISMATCH` | Project policy forbids execution, but repository contains executable behavior | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` | `compat` |
| `SEC402 / POLICY-NETWORK-MISMATCH` | Project policy forbids network access, but repository contains network behavior | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` | `compat` |
| `SEC403 / POLICY-SKILL-CAPABILITIES-MISMATCH` | Skill frontmatter capabilities conflict with project policy | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` | `compat` |

## Builtin preset activation model

All shipped rules now participate in the preset model through a deterministic surface-and-tier mapping:

- `base`: the core shipped stable rule set for repo-local agent artifacts
- `preview`: core preview rules that expand the main artifact-security lane without enabling separate sidecar lanes
- `compat`: workspace policy mismatch rules (`SEC401`-`SEC403`) kept as a separate policy lane
- `skills`: markdown-surface rules for the core instruction/skills lane
- `mcp`: all `json`, `tool_json`, and `server_json` surface rules, including preview MCP/config rules
- `claude`: all `claude_settings` surface rules
- `guidance`: advice-oriented guidance checks such as Copilot instruction layout and length guidance
- `supply-chain`: sidecar supply-chain hardening checks such as GitHub Actions workflow rules

Important behavior:

- `strict` is a severity overlay, not a membership preset: when enabled, active security rules are raised through preset policy instead of silently activating new rules by itself.
- Dedicated sidecar lanes such as `compat`, `guidance`, and `supply-chain` stay opt-in and are not implied by `base` or `preview`.
- Category overrides do not activate rules outside the resolved preset set.
- Explicit `[rules] SECxxx = "..."` remains the escape hatch for intentional per-rule opt-in outside the default preset set.

## Provider: `lintai-ai-security`

### `SEC101 / MD-HIDDEN-INSTRUCTIONS` — Hidden HTML comment contains dangerous agent instructions

- Provider: `lintai-ai-security`
- Alias: `MD-HIDDEN-INSTRUCTIONS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `safe_fix`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on suspicious phrase heuristics inside hidden HTML comments.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC102 / MD-DOWNLOAD-EXEC` — Markdown contains remote download-and-execute instruction outside code blocks

- Provider: `lintai-ai-security`
- Alias: `MD-DOWNLOAD-EXEC`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `suggestion`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on prose command heuristics outside code blocks.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC103 / MD-HIDDEN-DOWNLOAD-EXEC` — Hidden HTML comment contains remote download-and-execute instruction

- Provider: `lintai-ai-security`
- Alias: `MD-HIDDEN-DOWNLOAD-EXEC`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `safe_fix`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on hidden-comment command heuristics rather than a structural execution model.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC104 / MD-BASE64-EXEC` — Markdown contains a base64-decoded executable payload outside code blocks

- Provider: `lintai-ai-security`
- Alias: `MD-BASE64-EXEC`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on prose base64-and-exec text heuristics.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC105 / MD-PATH-TRAVERSAL` — Markdown instructions reference parent-directory traversal for file access

- Provider: `lintai-ai-security`
- Alias: `MD-PATH-TRAVERSAL`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on prose path-traversal and access-verb heuristics.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC201 / HOOK-DOWNLOAD-EXEC` — Hook script downloads remote code and executes it

- Provider: `lintai-ai-security`
- Alias: `HOOK-DOWNLOAD-EXEC`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit remote download-and-execute behavior in hook shell lines, not prose text.
- Deterministic Signal Basis: HookSignals download-and-execute observation over non-comment hook lines.
- Malicious Corpus: `hook-download-exec`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC202 / HOOK-SECRET-EXFIL` — Hook script appears to exfiltrate secrets through a network call

- Provider: `lintai-ai-security`
- Alias: `HOOK-SECRET-EXFIL`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches secret-bearing network exfil behavior in executable hook lines.
- Deterministic Signal Basis: HookSignals secret exfil observation from network markers plus secret markers on non-comment lines.
- Malicious Corpus: `hook-secret-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC203 / HOOK-PLAIN-HTTP-SECRET-EXFIL` — Hook script sends secret material to an insecure http:// endpoint

- Provider: `lintai-ai-security`
- Alias: `HOOK-PLAIN-HTTP-SECRET-EXFIL`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches insecure HTTP transport on a secret-bearing hook exfil path.
- Deterministic Signal Basis: HookSignals precise http:// span observation gated by concurrent secret exfil markers.
- Malicious Corpus: `hook-plain-http-secret-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC204 / HOOK-TLS-BYPASS` — Hook script disables TLS or certificate verification for a network call

- Provider: `lintai-ai-security`
- Alias: `HOOK-TLS-BYPASS`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit TLS verification bypass tokens in executable hook network context.
- Deterministic Signal Basis: HookSignals TLS-bypass token observation over parsed hook line tokens and network context.
- Malicious Corpus: `hook-tls-bypass`
- Benign Corpus: `cursor-plugin-tls-verified-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC205 / HOOK-STATIC-AUTH` — Hook script embeds static authentication material in a network call

- Provider: `lintai-ai-security`
- Alias: `HOOK-STATIC-AUTH`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches literal static auth material in hook URLs or authorization headers.
- Deterministic Signal Basis: HookSignals userinfo/header literal extraction excluding dynamic references.
- Malicious Corpus: `hook-static-auth-userinfo`
- Benign Corpus: `hook-auth-dynamic-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC206 / HOOK-BASE64-EXEC` — Hook script decodes a base64 payload and executes it

- Provider: `lintai-ai-security`
- Alias: `HOOK-BASE64-EXEC`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit base64 decode-and-execute behavior in executable hook lines.
- Deterministic Signal Basis: HookSignals base64-decode plus exec observation over non-comment hook lines.
- Malicious Corpus: `hook-base64-exec`
- Benign Corpus: `hook-base64-decode-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC301 / MCP-SHELL-WRAPPER` — MCP configuration shells out through sh -c or bash -c

- Provider: `lintai-ai-security`
- Alias: `MCP-SHELL-WRAPPER`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit shell-wrapper command structure in JSON config.
- Deterministic Signal Basis: JsonSignals command and args structure observation for sh -c or bash -c wrappers.
- Malicious Corpus: `mcp-shell-wrapper`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC302 / MCP-PLAIN-HTTP-ENDPOINT` — Configuration contains an insecure http:// endpoint

- Provider: `lintai-ai-security`
- Alias: `MCP-PLAIN-HTTP-ENDPOINT`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit insecure http:// endpoints in configuration values.
- Deterministic Signal Basis: JsonSignals precise http:// endpoint span resolution from parsed JSON location map.
- Malicious Corpus: `mcp-plain-http`
- Benign Corpus: `mcp-trusted-endpoint-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC303 / MCP-CREDENTIAL-ENV-PASSTHROUGH` — MCP configuration passes through credential environment variables

- Provider: `lintai-ai-security`
- Alias: `MCP-CREDENTIAL-ENV-PASSTHROUGH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit credential env passthrough by key inside configuration env maps.
- Deterministic Signal Basis: JsonSignals env-map key observation for credential passthrough keys.
- Malicious Corpus: `mcp-credential-env-passthrough`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC304 / MCP-TLS-BYPASS` — Configuration disables TLS or certificate verification

- Provider: `lintai-ai-security`
- Alias: `MCP-TLS-BYPASS`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit TLS or certificate verification disable flags in configuration.
- Deterministic Signal Basis: JsonSignals boolean and key observation for trust-verification disable settings.
- Malicious Corpus: `mcp-trust-verification-disabled`
- Benign Corpus: `mcp-trust-verified-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC305 / MCP-STATIC-AUTH` — Configuration embeds static authentication material in a connection or auth value

- Provider: `lintai-ai-security`
- Alias: `MCP-STATIC-AUTH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches literal static auth material embedded directly in configuration values.
- Deterministic Signal Basis: JsonSignals literal authorization or userinfo span extraction excluding dynamic placeholders.
- Malicious Corpus: `mcp-static-authorization`
- Benign Corpus: `mcp-authorization-placeholder-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC306 / MCP-HIDDEN-INSTRUCTIONS` — JSON configuration description contains override-style hidden instructions

- Provider: `lintai-ai-security`
- Alias: `MCP-HIDDEN-INSTRUCTIONS`
- Scope: `per_file`
- Surface: `json`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `mcp`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on descriptive-field phrase heuristics in JSON text.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC307 / MCP-SENSITIVE-ENV-REFERENCE` — Configuration forwards sensitive environment variable references

- Provider: `lintai-ai-security`
- Alias: `MCP-SENSITIVE-ENV-REFERENCE`
- Scope: `per_file`
- Surface: `json`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `mcp`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on sensitive env-name heuristics in forwarded references.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC308 / MCP-SUSPICIOUS-ENDPOINT` — Configuration points at a suspicious remote endpoint

- Provider: `lintai-ai-security`
- Alias: `MCP-SUSPICIOUS-ENDPOINT`
- Scope: `per_file`
- Surface: `json`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `mcp`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on suspicious host-marker heuristics for remote endpoints.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC309 / MCP-LITERAL-SECRET` — Configuration commits literal secret material in env, auth, or header values

- Provider: `lintai-ai-security`
- Alias: `MCP-LITERAL-SECRET`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches literal secret material committed into env, header, or auth-like JSON fields.
- Deterministic Signal Basis: JsonSignals literal secret observation over env, header, and auth-like keys excluding dynamic placeholders.
- Malicious Corpus: `mcp-literal-secret-config`
- Benign Corpus: `mcp-secret-placeholder-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC310 / MCP-METADATA-HOST-LITERAL` — Configuration endpoint targets a metadata or private-network host literal

- Provider: `lintai-ai-security`
- Alias: `MCP-METADATA-HOST-LITERAL`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit metadata-service or private-network host literals in endpoint-like configuration values.
- Deterministic Signal Basis: JsonSignals endpoint-host extraction over URL-like endpoint fields with metadata/private-host classification.
- Malicious Corpus: `mcp-metadata-host-literal`
- Benign Corpus: `mcp-public-endpoint-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC311 / PLUGIN-UNSAFE-PATH` — Cursor plugin manifest contains an unsafe absolute or parent-traversing path

- Provider: `lintai-ai-security`
- Alias: `PLUGIN-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches absolute or parent-traversing paths in committed Cursor plugin manifest path fields.
- Deterministic Signal Basis: JsonSignals plugin-manifest path observation limited to known plugin path fields.
- Malicious Corpus: `cursor-plugin-unsafe-path`
- Benign Corpus: `cursor-plugin-safe-paths`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC312 / MD-PRIVATE-KEY` — Markdown contains committed private key material

- Provider: `lintai-ai-security`
- Alias: `MD-PRIVATE-KEY`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit committed private-key PEM markers inside agent markdown surfaces.
- Deterministic Signal Basis: MarkdownSignals private-key marker observation across parsed markdown regions excluding placeholder examples.
- Malicious Corpus: `skill-private-key-pem`
- Benign Corpus: `skill-public-key-pem-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC313 / MD-PIPE-SHELL` — Fenced shell example pipes remote content directly into a shell

- Provider: `lintai-ai-security`
- Alias: `MD-PIPE-SHELL`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on fenced shell-example command heuristics and still needs broader external precision review.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC314 / TOOL-MISSING-MACHINE-FIELDS` — MCP-style tool descriptor is missing required machine fields

- Provider: `lintai-ai-security`
- Alias: `TOOL-MISSING-MACHINE-FIELDS`
- Scope: `per_file`
- Surface: `tool_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks unambiguous MCP-style tool descriptors for missing machine fields instead of relying on prose heuristics.
- Deterministic Signal Basis: ToolJsonSignals MCP collection analysis over parsed tool descriptor JSON.
- Malicious Corpus: `tool-json-mcp-missing-machine-fields`
- Benign Corpus: `tool-json-mcp-valid-tool`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC315 / TOOL-DUPLICATE-NAMES` — MCP-style tool descriptor collection contains duplicate tool names

- Provider: `lintai-ai-security`
- Alias: `TOOL-DUPLICATE-NAMES`
- Scope: `per_file`
- Surface: `tool_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks structured MCP-style tool collections for duplicate names that can shadow one another.
- Deterministic Signal Basis: ToolJsonSignals duplicate-name detection over MCP-style tool collections.
- Malicious Corpus: `tool-json-duplicate-tool-names`
- Benign Corpus: `tool-json-unique-tool-names`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC316 / OPENAI-STRICT-ADDITIONAL-PROPERTIES` — OpenAI strict tool schema omits recursive additionalProperties: false

- Provider: `lintai-ai-security`
- Alias: `OPENAI-STRICT-ADDITIONAL-PROPERTIES`
- Scope: `per_file`
- Surface: `tool_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks OpenAI strict tool schemas for recursive object locking with additionalProperties: false.
- Deterministic Signal Basis: ToolJsonSignals recursive schema walk over OpenAI function.parameters when strict mode is enabled.
- Malicious Corpus: `tool-json-openai-strict-additional-properties`
- Benign Corpus: `tool-json-openai-strict-locked`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC317 / OPENAI-STRICT-REQUIRED-COVERAGE` — OpenAI strict tool schema does not require every declared property

- Provider: `lintai-ai-security`
- Alias: `OPENAI-STRICT-REQUIRED-COVERAGE`
- Scope: `per_file`
- Surface: `tool_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks OpenAI strict tool schemas for full required coverage of declared properties.
- Deterministic Signal Basis: ToolJsonSignals recursive required-versus-properties comparison over strict OpenAI schemas.
- Malicious Corpus: `tool-json-openai-strict-required-coverage`
- Benign Corpus: `tool-json-openai-strict-required-complete`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC318 / ANTHROPIC-STRICT-ADDITIONAL-PROPERTIES` — Anthropic strict tool input schema omits additionalProperties: false

- Provider: `lintai-ai-security`
- Alias: `ANTHROPIC-STRICT-ADDITIONAL-PROPERTIES`
- Scope: `per_file`
- Surface: `tool_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks Anthropic strict tool input_schema objects for explicit additionalProperties: false.
- Deterministic Signal Basis: ToolJsonSignals recursive schema walk over Anthropic input_schema when strict mode is enabled.
- Malicious Corpus: `tool-json-anthropic-strict-open-schema`
- Benign Corpus: `tool-json-anthropic-strict-locked`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC319 / SERVER-REMOTE-URL` — server.json remotes entry uses an insecure or non-public remote URL

- Provider: `lintai-ai-security`
- Alias: `SERVER-REMOTE-URL`
- Scope: `per_file`
- Surface: `server_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks MCP registry remotes[] URLs for insecure HTTP and non-public host literals without inspecting local package transport URLs.
- Deterministic Signal Basis: ServerJsonSignals remotes[] URL analysis limited to streamable-http and sse entries.
- Malicious Corpus: `server-json-insecure-remote-url`
- Benign Corpus: `server-json-loopback-package-transport-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC320 / SERVER-UNDEFINED-URL-VAR` — server.json remotes URL references an undefined template variable

- Provider: `lintai-ai-security`
- Alias: `SERVER-UNDEFINED-URL-VAR`
- Scope: `per_file`
- Surface: `server_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks server.json remotes[] URL templates against variables defined on the same remote entry.
- Deterministic Signal Basis: ServerJsonSignals placeholder extraction over remotes[] URLs compared with remotes[].variables keys.
- Malicious Corpus: `server-json-unresolved-remote-variable`
- Benign Corpus: `server-json-remote-variable-defined`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC321 / SERVER-LITERAL-AUTH-HEADER` — server.json remotes header commits literal authentication material

- Provider: `lintai-ai-security`
- Alias: `SERVER-LITERAL-AUTH-HEADER`
- Scope: `per_file`
- Surface: `server_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks remotes[].headers[] auth-like values for literal bearer/basic material or literal API key style values.
- Deterministic Signal Basis: ServerJsonSignals inspects remotes[].headers[] auth-like names and value literals without looking at packages[].transport.
- Malicious Corpus: `server-json-literal-auth-header`
- Benign Corpus: `server-json-auth-header-placeholder-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC322 / SERVER-UNDEFINED-HEADER-VAR` — server.json remotes header value references an undefined template variable

- Provider: `lintai-ai-security`
- Alias: `SERVER-UNDEFINED-HEADER-VAR`
- Scope: `per_file`
- Surface: `server_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks auth-like remotes[].headers[].value placeholders against variables defined on the same header object.
- Deterministic Signal Basis: ServerJsonSignals placeholder extraction over remotes[].headers[].value compared with headers[].variables keys.
- Malicious Corpus: `server-json-unresolved-header-variable`
- Benign Corpus: `server-json-header-variable-defined`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC323 / SERVER-AUTH-SECRET-FLAG` — server.json auth header carries material without an explicit secret flag

- Provider: `lintai-ai-security`
- Alias: `SERVER-AUTH-SECRET-FLAG`
- Scope: `per_file`
- Surface: `server_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `mcp`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Secret policy expectations can vary across registry producers, so the first release keeps this as guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC324 / GHA-UNPINNED-ACTION` — GitHub Actions workflow uses a third-party action that is not pinned to a full commit SHA

- Provider: `lintai-ai-security`
- Alias: `GHA-UNPINNED-ACTION`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks workflow uses: entries for third-party actions that rely on mutable refs instead of immutable commit SHAs; positioned as a supply-chain hardening control rather than a direct exploit claim.
- Deterministic Signal Basis: GithubWorkflowSignals line-level uses: extraction gated by semantically confirmed workflow YAML.
- Malicious Corpus: `github-workflow-third-party-unpinned-action`
- Benign Corpus: `github-workflow-pinned-third-party-action`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC325 / GHA-UNTRUSTED-RUN-INTERPOLATION` — GitHub Actions workflow interpolates untrusted expression data directly inside a run command

- Provider: `lintai-ai-security`
- Alias: `GHA-UNTRUSTED-RUN-INTERPOLATION`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shell safety depends on how the interpolated expression is consumed inside the run command.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC326 / GHA-PR-TARGET-HEAD-CHECKOUT` — GitHub Actions pull_request_target workflow checks out untrusted pull request head content

- Provider: `lintai-ai-security`
- Alias: `GHA-PR-TARGET-HEAD-CHECKOUT`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks pull_request_target workflows for actions/checkout steps that explicitly pull untrusted pull request head refs instead of the safer default merge context.
- Deterministic Signal Basis: GithubWorkflowSignals event gating plus line-level checkout ref extraction for pull_request_target workflows.
- Malicious Corpus: `github-workflow-pull-request-target-head-checkout`
- Benign Corpus: `github-workflow-pull-request-target-safe-checkout`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC327 / GHA-WRITE-ALL-PERMISSIONS` — GitHub Actions workflow grants GITHUB_TOKEN write-all permissions

- Provider: `lintai-ai-security`
- Alias: `GHA-WRITE-ALL-PERMISSIONS`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks workflow permissions for the explicit write-all shortcut, which exceeds least-privilege guidance for GITHUB_TOKEN.
- Deterministic Signal Basis: GithubWorkflowSignals line-level permissions extraction for semantically confirmed workflow YAML.
- Malicious Corpus: `github-workflow-write-all-permissions`
- Benign Corpus: `github-workflow-read-only-permissions`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC328 / GHA-WRITE-CAPABLE-THIRD-PARTY-ACTION` — GitHub Actions workflow combines explicit write-capable permissions with a third-party action

- Provider: `lintai-ai-security`
- Alias: `GHA-WRITE-CAPABLE-THIRD-PARTY-ACTION`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Write-capable token scopes and third-party action usage are compositional and need more corpus-backed precision review before a stable launch.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC329 / MCP-MUTABLE-LAUNCHER` — MCP configuration launches tooling through a mutable package runner

- Provider: `lintai-ai-security`
- Alias: `MCP-MUTABLE-LAUNCHER`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config command launchers for mutable package-runner forms such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.
- Deterministic Signal Basis: JsonSignals command/args analysis over ArtifactKind::McpConfig objects with launcher-specific argument gating.
- Malicious Corpus: `mcp-mutable-launcher`
- Benign Corpus: `mcp-pinned-launcher-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC330 / MCP-DOWNLOAD-EXEC` — MCP configuration command downloads remote content and pipes it into a shell

- Provider: `lintai-ai-security`
- Alias: `MCP-DOWNLOAD-EXEC`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config command and args values for explicit curl|shell or wget|shell execution chains.
- Deterministic Signal Basis: JsonSignals command/args string analysis over ArtifactKind::McpConfig objects, limited to explicit download-pipe-shell patterns.
- Malicious Corpus: `mcp-inline-download-exec`
- Benign Corpus: `mcp-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC331 / MCP-TLS-BYPASS` — MCP configuration command disables TLS verification in a network-capable execution path

- Provider: `lintai-ai-security`
- Alias: `MCP-TLS-BYPASS`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config command and args values for explicit TLS-bypass tokens in a network-capable execution context.
- Deterministic Signal Basis: JsonSignals command/args string analysis over ArtifactKind::McpConfig objects gated by network markers plus TLS-bypass tokens.
- Malicious Corpus: `mcp-command-tls-bypass`
- Benign Corpus: `mcp-network-tls-verified-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC335 / MD-METADATA-SERVICE-ACCESS` — AI-native markdown contains a direct cloud metadata-service access example

- Provider: `lintai-ai-security`
- Alias: `MD-METADATA-SERVICE-ACCESS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Metadata-service examples can appear in legitimate security training content, so the first release stays guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC336 / MCP-BROAD-ENVFILE` — Repo-local MCP client config loads a broad dotenv-style envFile

- Provider: `lintai-ai-security`
- Alias: `MCP-BROAD-ENVFILE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `mcp`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Broad envFile loading is useful review signal, but whether it is materially risky still depends on repo-local review policy and env contents.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC337 / MCP-DOCKER-UNPINNED-IMAGE` — MCP configuration launches Docker with an image reference that is not digest-pinned

- Provider: `lintai-ai-security`
- Alias: `MCP-DOCKER-UNPINNED-IMAGE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config Docker launch paths for image references that are not pinned by digest, including tag-only refs such as :latest or :1.2.3.
- Deterministic Signal Basis: JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to command == docker plus args beginning with run.
- Malicious Corpus: `mcp-docker-unpinned-image`
- Benign Corpus: `mcp-docker-digest-pinned-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC338 / MCP-DOCKER-SENSITIVE-MOUNT` — MCP configuration launches Docker with a bind mount of sensitive host material

- Provider: `lintai-ai-security`
- Alias: `MCP-DOCKER-SENSITIVE-MOUNT`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config Docker launch paths for bind mounts of sensitive host sources such as docker.sock, SSH material, cloud credentials, and kubeconfig directories.
- Deterministic Signal Basis: JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to -v/--volume and --mount bind forms with sensitive host-path markers.
- Malicious Corpus: `mcp-docker-sensitive-mount`
- Benign Corpus: `mcp-docker-named-volume-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC339 / MCP-DOCKER-HOST-ESCAPE` — MCP configuration launches Docker with a host-escape or privileged runtime flag

- Provider: `lintai-ai-security`
- Alias: `MCP-DOCKER-HOST-ESCAPE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config Docker launch paths for privileged or host-escape runtime flags such as --privileged, --network host, --pid host, and --ipc host.
- Deterministic Signal Basis: JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to explicit privileged and host namespace flags.
- Malicious Corpus: `mcp-docker-host-escape`
- Benign Corpus: `mcp-docker-safe-run`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC340 / CLAUDE-HOOK-MUTABLE-LAUNCHER` — Claude settings command hook uses a mutable package launcher

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HOOK-MUTABLE-LAUNCHER`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for mutable package launcher forms such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook analysis over committed .claude/settings.json or claude/settings.json objects with type == command under hooks.
- Malicious Corpus: `claude-settings-mutable-launcher`
- Benign Corpus: `claude-settings-pinned-launcher-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC341 / CLAUDE-HOOK-DOWNLOAD-EXEC` — Claude settings command hook downloads remote content and pipes it into a shell

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HOOK-DOWNLOAD-EXEC`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit curl|shell or wget|shell execution chains.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command, limited to explicit download-pipe-shell patterns.
- Malicious Corpus: `claude-settings-inline-download-exec`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC342 / CLAUDE-HOOK-TLS-BYPASS` — Claude settings command hook disables TLS verification in a network-capable execution path

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HOOK-TLS-BYPASS`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit TLS-bypass tokens in a network-capable execution context.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command, gated by network markers plus TLS-bypass tokens.
- Malicious Corpus: `claude-settings-command-tls-bypass`
- Benign Corpus: `claude-settings-network-tls-verified-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC343 / PLUGIN-HOOK-MUTABLE-LAUNCHER` — Plugin hook command uses a mutable package launcher

- Provider: `lintai-ai-security`
- Alias: `PLUGIN-HOOK-MUTABLE-LAUNCHER`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for mutable package launchers such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects limited to actual hook command values.
- Malicious Corpus: `plugin-hook-command-mutable-launcher`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC344 / PLUGIN-HOOK-DOWNLOAD-EXEC` — Plugin hook command downloads remote content and pipes it into a shell

- Provider: `lintai-ai-security`
- Alias: `PLUGIN-HOOK-DOWNLOAD-EXEC`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit curl|shell or wget|shell execution chains.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects, limited to explicit download-pipe-shell patterns.
- Malicious Corpus: `plugin-hook-command-inline-download-exec`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC345 / PLUGIN-HOOK-TLS-BYPASS` — Plugin hook command disables TLS verification in a network-capable execution path

- Provider: `lintai-ai-security`
- Alias: `PLUGIN-HOOK-TLS-BYPASS`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit TLS-bypass tokens in a network-capable execution context.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects gated by network markers plus TLS-bypass tokens.
- Malicious Corpus: `plugin-hook-command-tls-bypass`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC346 / MCP-DOCKER-PULL-ALWAYS` — MCP configuration forces Docker to refresh from a mutable registry source

- Provider: `lintai-ai-security`
- Alias: `MCP-DOCKER-PULL-ALWAYS`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config Docker launch paths for explicit --pull always refresh policies that force a mutable registry fetch at runtime.
- Deterministic Signal Basis: JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to explicit --pull=always or --pull always forms.
- Malicious Corpus: `gemini-mcp-docker-pull-always`
- Benign Corpus: `gemini-mcp-docker-digest-pinned-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC347 / MD-MCP-MUTABLE-LAUNCHER` — AI-native markdown example launches MCP through a mutable package runner

- Provider: `lintai-ai-security`
- Alias: `MD-MCP-MUTABLE-LAUNCHER`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Mutable MCP launcher examples in markdown can be legitimate setup guidance, so the first release stays guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC348 / MD-DOCKER-MUTABLE-IMAGE` — AI-native markdown Docker example uses a mutable registry image

- Provider: `lintai-ai-security`
- Alias: `MD-DOCKER-MUTABLE-IMAGE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Mutable Docker image examples in markdown can be legitimate setup guidance, so the first release stays guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC349 / MD-DOCKER-HOST-ESCAPE` — AI-native markdown Docker example uses a host-escape or privileged runtime pattern

- Provider: `lintai-ai-security`
- Alias: `MD-DOCKER-HOST-ESCAPE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Docker host-escape examples in markdown can be legitimate ops guidance, so the first release stays guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC350 / MD-UNTRUSTED-INSTRUCTION-PROMOTION` — Instruction markdown promotes untrusted external content to developer/system-level instructions

- Provider: `lintai-ai-security`
- Alias: `MD-UNTRUSTED-INSTRUCTION-PROMOTION`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Instruction-boundary promotion in markdown is prose-aware and needs external usefulness review before any stronger posture.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC351 / MD-APPROVAL-BYPASS` — AI-native instruction explicitly disables user approval or confirmation

- Provider: `lintai-ai-security`
- Alias: `MD-APPROVAL-BYPASS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Approval-bypass guidance in markdown is prose-aware and needs external usefulness review before any stronger posture.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC352 / MD-UNSCOPED-BASH` — AI-native markdown frontmatter grants unscoped Bash tool access

- Provider: `lintai-ai-security`
- Alias: `MD-UNSCOPED-BASH`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Broad Bash grants in AI-native frontmatter can be intentional, so the first release stays least-privilege guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC353 / COPILOT-4K` — GitHub Copilot instruction markdown exceeds the 4000-character guidance limit

- Provider: `lintai-ai-security`
- Alias: `COPILOT-4K`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Long Copilot instruction files can still be intentional, so the first release stays guidance-only while usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC354 / COPILOT-PATH-APPLYTO` — Path-specific GitHub Copilot instruction markdown is missing `applyTo` frontmatter

- Provider: `lintai-ai-security`
- Alias: `COPILOT-PATH-APPLYTO`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Missing `applyTo` on path-specific Copilot instruction files is deterministic, but the first release stays guidance-only while external usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC355 / MD-WILDCARD-TOOLS` — AI-native markdown frontmatter grants wildcard tool access

- Provider: `lintai-ai-security`
- Alias: `MD-WILDCARD-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Wildcard tool grants in AI-native frontmatter can still appear in convenience-oriented docs, so the first release stays least-privilege guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC356 / PLUGIN-AGENT-PERMISSIONMODE` — Plugin agent frontmatter sets `permissionMode`

- Provider: `lintai-ai-security`
- Alias: `PLUGIN-AGENT-PERMISSIONMODE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Plugin agent frontmatter can still include unsupported permission policy experiments, so the first release stays spec-guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC357 / PLUGIN-AGENT-HOOKS` — Plugin agent frontmatter sets `hooks`

- Provider: `lintai-ai-security`
- Alias: `PLUGIN-AGENT-HOOKS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Plugin agent frontmatter can still include unsupported hook experiments, so the first release stays spec-guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC358 / PLUGIN-AGENT-MCPSERVERS` — Plugin agent frontmatter sets `mcpServers`

- Provider: `lintai-ai-security`
- Alias: `PLUGIN-AGENT-MCPSERVERS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Plugin agent frontmatter can still include unsupported MCP server experiments, so the first release stays spec-guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC359 / CURSOR-RULE-ALWAYSAPPLY` — Cursor rule frontmatter `alwaysApply` must be boolean

- Provider: `lintai-ai-security`
- Alias: `CURSOR-RULE-ALWAYSAPPLY`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Cursor rule frontmatter shape mismatches are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC360 / CURSOR-RULE-GLOBS` — Cursor rule frontmatter `globs` must be a sequence of patterns

- Provider: `lintai-ai-security`
- Alias: `CURSOR-RULE-GLOBS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Cursor rule path-matching shape mismatches are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC361 / CLAUDE-SETTINGS-SCHEMA` — Claude settings file is missing a top-level `$schema` reference

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-SETTINGS-SCHEMA`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Schema references in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC362 / CLAUDE-BASH-WILDCARD` — Claude settings permissions allow `Bash(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-BASH-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Wildcard Bash grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC363 / CLAUDE-HOME-HOOK-PATH` — Claude settings hook command uses a home-directory path in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HOME-HOOK-PATH`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Home-directory hook paths in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC364 / CLAUDE-BYPASS-PERMISSIONS` — Claude settings set `permissions.defaultMode` to `bypassPermissions` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-BYPASS-PERMISSIONS`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Committed Claude settings with `permissions.defaultMode = bypassPermissions` are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC365 / CLAUDE-HTTP-HOOK-URL` — Claude settings allow non-HTTPS HTTP hook URLs in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HTTP-HOOK-URL`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Committed Claude settings with non-HTTPS `allowedHttpHookUrls` entries are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC366 / CLAUDE-HTTP-HOOK-HOST` — Claude settings allow dangerous host literals in `allowedHttpHookUrls`

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HTTP-HOOK-HOST`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Committed Claude settings with dangerous host literals in `allowedHttpHookUrls` are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC367 / CLAUDE-WEBFETCH-WILDCARD` — Claude settings permissions allow `WebFetch(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WEBFETCH-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Wildcard WebFetch grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC368 / CLAUDE-ABS-HOOK-PATH` — Claude settings hook command uses a repo-external absolute path in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-ABS-HOOK-PATH`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Repo-external absolute hook paths in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC369 / CLAUDE-WRITE-WILDCARD` — Claude settings permissions allow `Write(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WRITE-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Wildcard Write grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC370 / COPILOT-PATH-SUFFIX` — Path-specific GitHub Copilot instruction markdown under `.github/instructions/` uses the wrong file suffix

- Provider: `lintai-ai-security`
- Alias: `COPILOT-PATH-SUFFIX`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Wrong suffix on path-specific Copilot instruction files is deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC371 / COPILOT-APPLYTO-TYPE` — Path-specific GitHub Copilot instruction markdown has an invalid `applyTo` shape

- Provider: `lintai-ai-security`
- Alias: `COPILOT-APPLYTO-TYPE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Invalid `applyTo` shape on path-specific Copilot instruction files is deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC372 / CLAUDE-READ-WILDCARD` — Claude settings permissions allow `Read(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-READ-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Wildcard Read grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC373 / CLAUDE-EDIT-WILDCARD` — Claude settings permissions allow `Edit(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-EDIT-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Wildcard Edit grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC374 / CLAUDE-WEBSEARCH-WILDCARD` — Claude settings permissions allow `WebSearch(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WEBSEARCH-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Wildcard WebSearch grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC375 / CLAUDE-GLOB-WILDCARD` — Claude settings permissions allow `Glob(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GLOB-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Wildcard Glob grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC376 / CLAUDE-GREP-WILDCARD` — Claude settings permissions allow `Grep(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GREP-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Wildcard Grep grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC377 / COPILOT-APPLYTO-GLOB` — Path-specific GitHub Copilot instruction markdown has an invalid `applyTo` glob pattern

- Provider: `lintai-ai-security`
- Alias: `COPILOT-APPLYTO-GLOB`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Invalid `applyTo` glob patterns on path-specific Copilot instruction files are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC378 / CURSOR-ALWAYSAPPLY-GLOBS` — Cursor rule frontmatter should not set `globs` when `alwaysApply` is `true`

- Provider: `lintai-ai-security`
- Alias: `CURSOR-ALWAYSAPPLY-GLOBS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Redundant `globs` alongside `alwaysApply: true` is deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC379 / CURSOR-UNKNOWN-FRONTMATTER` — Cursor rule frontmatter contains an unknown key

- Provider: `lintai-ai-security`
- Alias: `CURSOR-UNKNOWN-FRONTMATTER`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Unknown Cursor rule frontmatter keys are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC380 / CURSOR-DESCRIPTION` — Cursor rule frontmatter should include `description`

- Provider: `lintai-ai-security`
- Alias: `CURSOR-DESCRIPTION`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Missing `description` on Cursor rules is deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC381 / CLAUDE-HOOK-TIMEOUT` — Claude settings command hook should set `timeout` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HOOK-TIMEOUT`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Missing command-hook timeouts in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC382 / CLAUDE-HOOK-MATCHER-EVENT` — Claude settings should not use `matcher` on unsupported hook events

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HOOK-MATCHER-EVENT`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Unsupported hook-event matchers in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC383 / CLAUDE-HOOK-MISSING-MATCHER` — Claude settings should set `matcher` on matcher-capable hook events

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HOOK-MISSING-MATCHER`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Missing matchers on matcher-capable Claude hook events are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC384 / CLAUDE-WEBSEARCH-UNSCOPED` — Claude settings permissions allow bare `WebSearch` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WEBSEARCH-UNSCOPED`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Bare WebSearch grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

## Provider: `lintai-policy-mismatch`

### `SEC401 / POLICY-EXEC-MISMATCH` — Project policy forbids execution, but repository contains executable behavior

- Provider: `lintai-policy-mismatch`
- Alias: `POLICY-EXEC-MISMATCH`
- Scope: `workspace`
- Surface: `workspace`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `compat`
- Remediation: `none`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Needs workspace-level precision review and linked graduation corpus before promotion to Stable.
- Promotion Requirements: Needs workspace precision review, linked benign/malicious corpus proof, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC402 / POLICY-NETWORK-MISMATCH` — Project policy forbids network access, but repository contains network behavior

- Provider: `lintai-policy-mismatch`
- Alias: `POLICY-NETWORK-MISMATCH`
- Scope: `workspace`
- Surface: `workspace`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `compat`
- Remediation: `none`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Needs workspace-level network precision review and linked graduation corpus before promotion to Stable.
- Promotion Requirements: Needs workspace precision review, linked benign/malicious corpus proof, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC403 / POLICY-SKILL-CAPABILITIES-MISMATCH` — Skill frontmatter capabilities conflict with project policy

- Provider: `lintai-policy-mismatch`
- Alias: `POLICY-SKILL-CAPABILITIES-MISMATCH`
- Scope: `workspace`
- Surface: `workspace`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `compat`
- Remediation: `none`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Needs workspace-level capability-conflict precision review and linked graduation corpus before promotion to Stable.
- Promotion Requirements: Needs workspace precision review, linked benign/malicious corpus proof, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.
