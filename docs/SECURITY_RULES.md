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
| `SEC385 / CLAUDE-GIT-PUSH-PERMISSION` | Claude settings permissions allow `Bash(git push)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC386 / CLAUDE-GIT-CHECKOUT-PERMISSION` | Claude settings permissions allow `Bash(git checkout:*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC387 / CLAUDE-GIT-COMMIT-PERMISSION` | Claude settings permissions allow `Bash(git commit:*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC388 / CLAUDE-GIT-STASH-PERMISSION` | Claude settings permissions allow `Bash(git stash:*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC389 / MD-WEBSEARCH-UNSCOPED` | AI-native markdown frontmatter grants bare `WebSearch` tool access | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC390 / MD-GIT-PUSH-PERMISSION` | AI-native markdown frontmatter grants `Bash(git push)` tool access | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC391 / MD-GIT-CHECKOUT-PERMISSION` | AI-native markdown frontmatter grants `Bash(git checkout:*)` tool access | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC392 / MD-GIT-COMMIT-PERMISSION` | AI-native markdown frontmatter grants `Bash(git commit:*)` tool access | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC393 / MD-GIT-STASH-PERMISSION` | AI-native markdown frontmatter grants `Bash(git stash:*)` tool access | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC394 / MCP-AUTOAPPROVE-WILDCARD` | MCP configuration auto-approves all tools with `autoApprove: ["*"]` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC395 / MCP-AUTOAPPROVE-TOOLS` | MCP configuration auto-approves all tools with `autoApproveTools: true` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC396 / MCP-TRUST-TOOLS` | MCP configuration fully trusts tools with `trustTools: true` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC397 / MCP-SANDBOX-DISABLED` | MCP configuration disables sandboxing with `sandbox: false` or `disableSandbox: true` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC398 / MCP-CAPABILITIES-WILDCARD` | MCP configuration grants all capabilities with `capabilities: ["*"]` or `capabilities: "*"` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC399 / CLAUDE-NPX-PERMISSION` | Claude settings permissions allow `Bash(npx ...)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC400 / CLAUDE-ENABLED-MCPJSON-SERVERS` | Claude settings enable `enabledMcpjsonServers` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC401 / POLICY-EXEC-MISMATCH` | Project policy forbids execution, but repository contains executable behavior | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` | `compat` |
| `SEC402 / POLICY-NETWORK-MISMATCH` | Project policy forbids network access, but repository contains network behavior | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` | `compat` |
| `SEC403 / POLICY-SKILL-CAPABILITIES-MISMATCH` | Skill frontmatter capabilities conflict with project policy | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` | `compat` |
| `SEC404 / MD-WEBFETCH-UNSCOPED` | AI-native markdown frontmatter grants bare `WebFetch` tool access | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC405 / CLAUDE-PACKAGE-INSTALL-PERMISSION` | Claude settings permissions allow package installation commands in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC406 / CLAUDE-GIT-ADD-PERMISSION` | Claude settings permissions allow `Bash(git add:*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC407 / CLAUDE-GIT-CLONE-PERMISSION` | Claude settings permissions allow `Bash(git clone:*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC408 / CLAUDE-GH-PR-PERMISSION` | Claude settings permissions allow `Bash(gh pr:*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC409 / CLAUDE-GIT-FETCH-PERMISSION` | Claude settings permissions allow `Bash(git fetch:*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC410 / CLAUDE-GIT-LS-REMOTE-PERMISSION` | Claude settings permissions allow `Bash(git ls-remote:*)` in a shared committed config | Preview | `preview_blocked` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC411 / CLAUDE-CURL-PERMISSION` | Claude settings permissions allow `Bash(curl:*)` in a shared committed config | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC412 / CLAUDE-WGET-PERMISSION` | Claude settings permissions allow `Bash(wget:*)` in a shared committed config | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC413 / CLAUDE-GIT-CONFIG-PERMISSION` | Claude settings permissions allow `Bash(git config:*)` in a shared committed config | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC414 / CLAUDE-GIT-TAG-PERMISSION` | Claude settings permissions allow `Bash(git tag:*)` in a shared committed config | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC415 / CLAUDE-GIT-BRANCH-PERMISSION` | Claude settings permissions allow `Bash(git branch:*)` in a shared committed config | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC416 / MD-CLAUDE-PIP-INSTALL` | AI-native markdown models Claude package installation with bare `pip install` despite explicit `uv` preference guidance | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` | `preview`, `skills` |
| `SEC417 / MD-PIP-GIT-UNPINNED` | AI-native markdown installs Python packages from an unpinned `git+https://` source | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC418 / CLAUDE-WEBFETCH-RAW-GITHUB` | Claude settings permissions allow `WebFetch(domain:raw.githubusercontent.com)` in a shared committed config | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `preview`, `claude` |
| `SEC419 / MD-CURL-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(curl:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC420 / MD-WGET-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(wget:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC421 / MD-GIT-CLONE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git clone:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC422 / MCP-COMMAND-SUDO` | MCP configuration launches the server through `sudo` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC423 / MD-READ-UNSCOPED` | AI-native markdown frontmatter grants bare `Read` tool access | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC424 / MD-WRITE-UNSCOPED` | AI-native markdown frontmatter grants bare `Write` tool access | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC425 / MD-EDIT-UNSCOPED` | AI-native markdown frontmatter grants bare `Edit` tool access | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC426 / MD-GLOB-UNSCOPED` | AI-native markdown frontmatter grants bare `Glob` tool access | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC427 / MD-GREP-UNSCOPED` | AI-native markdown frontmatter grants bare `Grep` tool access | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC428 / MD-READ-UNSAFE-PATH` | AI-native markdown frontmatter grants `Read(...)` over an unsafe repo-external path | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC429 / MD-WRITE-UNSAFE-PATH` | AI-native markdown frontmatter grants `Write(...)` over an unsafe repo-external path | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC430 / MD-EDIT-UNSAFE-PATH` | AI-native markdown frontmatter grants `Edit(...)` over an unsafe repo-external path | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC431 / MD-GLOB-UNSAFE-PATH` | AI-native markdown frontmatter grants `Glob(...)` over an unsafe repo-external path | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC432 / MD-GIT-ADD-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git add:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC433 / MD-GIT-FETCH-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git fetch:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC434 / MD-WEBFETCH-RAW-GITHUB` | AI-native markdown frontmatter grants `WebFetch(domain:raw.githubusercontent.com)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC435 / MD-GIT-CONFIG-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git config:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC436 / MD-GIT-TAG-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git tag:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC437 / MD-GIT-BRANCH-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git branch:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC438 / MD-GIT-RESET-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git reset:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC439 / MD-GIT-CLEAN-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git clean:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC440 / MD-GIT-RESTORE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git restore:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC441 / MD-GIT-REBASE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git rebase:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC442 / MD-GIT-MERGE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git merge:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC443 / MD-GIT-CHERRY-PICK-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git cherry-pick:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC444 / MD-GIT-APPLY-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git apply:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC445 / MD-GIT-AM-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git am:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC446 / MCP-ARGS-SUDO` | MCP configuration passes `sudo` as the first launch argument | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `base`, `mcp` |
| `SEC447 / MD-PACKAGE-INSTALL-ALLOWED-TOOLS` | AI-native markdown frontmatter grants package installation authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC448 / MD-PIP-TRUSTED-HOST` | AI-native markdown installs Python packages with `--trusted-host` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC449 / MD-PIP-HTTP-INDEX` | AI-native markdown installs Python packages from an insecure `http://` package index | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC450 / MD-NPM-HTTP-REGISTRY` | AI-native markdown installs JavaScript packages from an insecure `http://` registry | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC451 / MD-CARGO-HTTP-GIT-INSTALL` | AI-native markdown installs Rust packages from an insecure `http://` git source | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC452 / MD-CARGO-HTTP-INDEX` | AI-native markdown installs Rust packages from an insecure `http://` index | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC453 / MD-PIP-HTTP-SOURCE` | AI-native markdown installs Python packages from an insecure direct `http://` source | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC454 / MD-NPM-HTTP-SOURCE` | AI-native markdown installs JavaScript packages from an insecure direct `http://` source | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC455 / MD-PIP-HTTP-GIT-INSTALL` | AI-native markdown installs Python packages from an insecure `git+http://` source | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC456 / MD-PIP-HTTP-FIND-LINKS` | AI-native markdown installs Python packages with insecure `http://` find-links | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC457 / MD-JS-PACKAGE-STRICT-SSL-FALSE` | AI-native markdown disables strict SSL verification for JavaScript package manager config | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC458 / MD-PIP-CONFIG-HTTP-INDEX` | AI-native markdown configures Python package resolution with an insecure `http://` package index | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC459 / MD-JS-PACKAGE-CONFIG-HTTP-REGISTRY` | AI-native markdown configures a JavaScript package manager with an insecure `http://` registry | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC460 / MD-PIP-CONFIG-HTTP-FIND-LINKS` | AI-native markdown configures Python package discovery with insecure `http://` find-links | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC461 / MD-PIP-CONFIG-TRUSTED-HOST` | AI-native markdown configures Python package resolution with `trusted-host` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC462 / MD-NETWORK-TLS-BYPASS` | AI-native markdown disables TLS verification for a network-capable command | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC463 / MD-SUDO-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(sudo:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC464 / MD-GIT-HTTP-CLONE` | AI-native markdown clones a Git repository from an insecure `http://` source | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC465 / MD-GIT-HTTP-REMOTE` | AI-native markdown configures a Git remote with an insecure `http://` source | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC466 / MD-RM-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(rm:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC467 / MD-CHMOD-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(chmod:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC468 / MD-CHOWN-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(chown:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC469 / MD-CHGRP-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(chgrp:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC470 / MD-SU-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(su:*)` authority | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC471 / MD-GIT-SSLVERIFY-FALSE` | AI-native markdown disables Git TLS verification with `http.sslVerify false` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |
| `SEC472 / MD-GIT-SSL-NO-VERIFY` | AI-native markdown disables Git TLS verification with `GIT_SSL_NO_VERIFY` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `preview`, `skills` |

## Builtin preset activation model

All shipped rules now participate in the preset model through a deterministic surface-and-tier mapping:

- `base`: the core shipped stable rule set for repo-local agent artifacts
- `preview`: core preview rules that expand the main artifact-security lane without enabling separate sidecar lanes
- `compat`: workspace policy mismatch rules (`SEC401`-`SEC403`) kept as a separate policy lane
- `skills`: markdown-surface rules for the core instruction/skills lane
- `mcp`: all `json`, `tool_json`, and `server_json` surface rules, including preview MCP/config rules
- `claude`: all `claude_settings` surface rules
- `guidance`: advice-oriented guidance checks such as Copilot instruction layout and length guidance
- `governance`: opt-in review rules for shared mutation authority and similar workflow-policy decisions that should stay separate from the main security lane
- `supply-chain`: sidecar supply-chain hardening checks such as GitHub Actions workflow rules

Important behavior:

- `strict` is a severity overlay, not a membership preset: when enabled, active security rules are raised through preset policy instead of silently activating new rules by itself.
- Dedicated sidecar lanes such as `compat`, `guidance`, `governance`, and `supply-chain` stay opt-in and are not implied by `base` or `preview`.
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
- Graduation Rationale: Matches explicit shell-wrapper command structure in JSON config, whether the shell is the command itself or the first launch argument.
- Deterministic Signal Basis: JsonSignals command and args structure observation for sh -c or bash -c wrappers, either through `command` or `args[0]`.
- Malicious Corpus: `mcp-shell-wrapper`, `mcp-shell-wrapper-args0`
- Benign Corpus: `mcp-safe-basic`, `mcp-shell-wrapper-args-safe`
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
- Promotion Blocker: External validation now shows strong usefulness, but promotion still requires the completed stable checklist and one broader cross-cohort precision pass.
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

### `SEC385 / CLAUDE-GIT-PUSH-PERMISSION` — Claude settings permissions allow `Bash(git push)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-PUSH-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared git push permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC386 / CLAUDE-GIT-CHECKOUT-PERMISSION` — Claude settings permissions allow `Bash(git checkout:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-CHECKOUT-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared git checkout permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC387 / CLAUDE-GIT-COMMIT-PERMISSION` — Claude settings permissions allow `Bash(git commit:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-COMMIT-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared git commit permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC388 / CLAUDE-GIT-STASH-PERMISSION` — Claude settings permissions allow `Bash(git stash:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-STASH-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared git stash permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC389 / MD-WEBSEARCH-UNSCOPED` — AI-native markdown frontmatter grants bare `WebSearch` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-WEBSEARCH-UNSCOPED`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Bare WebSearch grants in AI-native frontmatter are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC390 / MD-GIT-PUSH-PERMISSION` — AI-native markdown frontmatter grants `Bash(git push)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-PUSH-PERMISSION`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared git push grants in AI-native frontmatter can be legitimate workflow policy, so the first release stays in the opt-in governance lane while usefulness and default posture are measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC391 / MD-GIT-CHECKOUT-PERMISSION` — AI-native markdown frontmatter grants `Bash(git checkout:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-CHECKOUT-PERMISSION`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared git checkout grants in AI-native frontmatter can be legitimate workflow policy, so the first release stays in the opt-in governance lane while usefulness and default posture are measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC392 / MD-GIT-COMMIT-PERMISSION` — AI-native markdown frontmatter grants `Bash(git commit:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-COMMIT-PERMISSION`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared git commit grants in AI-native frontmatter can be legitimate workflow policy, so the first release stays in the opt-in governance lane while usefulness and default posture are measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC393 / MD-GIT-STASH-PERMISSION` — AI-native markdown frontmatter grants `Bash(git stash:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-STASH-PERMISSION`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared git stash grants in AI-native frontmatter can be legitimate workflow policy, so the first release stays in the opt-in governance lane while usefulness and default posture are measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC394 / MCP-AUTOAPPROVE-WILDCARD` — MCP configuration auto-approves all tools with `autoApprove: ["*"]`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-WILDCARD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit wildcard auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["*"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-wildcard`
- Benign Corpus: `mcp-autoapprove-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC395 / MCP-AUTOAPPROVE-TOOLS` — MCP configuration auto-approves all tools with `autoApproveTools: true`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-TOOLS`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit blanket auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact boolean detection for `autoApproveTools: true` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-tools-true`
- Benign Corpus: `mcp-autoapprove-tools-false-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC396 / MCP-TRUST-TOOLS` — MCP configuration fully trusts tools with `trustTools: true`

- Provider: `lintai-ai-security`
- Alias: `MCP-TRUST-TOOLS`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit blanket tool trust in MCP client config.
- Deterministic Signal Basis: JsonSignals exact boolean detection for `trustTools: true` on parsed MCP configuration.
- Malicious Corpus: `mcp-trust-tools-true`
- Benign Corpus: `mcp-trust-tools-false-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC397 / MCP-SANDBOX-DISABLED` — MCP configuration disables sandboxing with `sandbox: false` or `disableSandbox: true`

- Provider: `lintai-ai-security`
- Alias: `MCP-SANDBOX-DISABLED`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit MCP config booleans that disable sandbox isolation.
- Deterministic Signal Basis: JsonSignals exact boolean detection for `sandbox: false` or `disableSandbox: true` on parsed MCP configuration.
- Malicious Corpus: `mcp-sandbox-disabled`
- Benign Corpus: `mcp-sandbox-enabled-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC398 / MCP-CAPABILITIES-WILDCARD` — MCP configuration grants all capabilities with `capabilities: ["*"]` or `capabilities: "*"`

- Provider: `lintai-ai-security`
- Alias: `MCP-CAPABILITIES-WILDCARD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit wildcard capability grants in MCP config.
- Deterministic Signal Basis: JsonSignals exact wildcard detection for `capabilities` scalar or array values on parsed MCP configuration.
- Malicious Corpus: `mcp-capabilities-wildcard`
- Benign Corpus: `mcp-capabilities-scoped-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC399 / CLAUDE-NPX-PERMISSION` — Claude settings permissions allow `Bash(npx ...)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-NPX-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared `Bash(npx ...)` permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC400 / CLAUDE-ENABLED-MCPJSON-SERVERS` — Claude settings enable `enabledMcpjsonServers` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-ENABLED-MCPJSON-SERVERS`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared `enabledMcpjsonServers` in committed Claude settings is deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC404 / MD-WEBFETCH-UNSCOPED` — AI-native markdown frontmatter grants bare `WebFetch` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-WEBFETCH-UNSCOPED`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Bare WebFetch grants in AI-native frontmatter are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC405 / CLAUDE-PACKAGE-INSTALL-PERMISSION` — Claude settings permissions allow package installation commands in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-PACKAGE-INSTALL-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared package installation permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC406 / CLAUDE-GIT-ADD-PERMISSION` — Claude settings permissions allow `Bash(git add:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-ADD-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared `git add` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC407 / CLAUDE-GIT-CLONE-PERMISSION` — Claude settings permissions allow `Bash(git clone:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-CLONE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared `git clone` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC408 / CLAUDE-GH-PR-PERMISSION` — Claude settings permissions allow `Bash(gh pr:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-PR-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared `gh pr` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC409 / CLAUDE-GIT-FETCH-PERMISSION` — Claude settings permissions allow `Bash(git fetch:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-FETCH-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared `git fetch` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC410 / CLAUDE-GIT-LS-REMOTE-PERMISSION` — Claude settings permissions allow `Bash(git ls-remote:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-LS-REMOTE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shared `git ls-remote` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC411 / CLAUDE-CURL-PERMISSION` — Claude settings permissions allow `Bash(curl:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-CURL-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for explicit wildcard curl execution grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(curl:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-curl-permission`
- Benign Corpus: `claude-settings-curl-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC412 / CLAUDE-WGET-PERMISSION` — Claude settings permissions allow `Bash(wget:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WGET-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for explicit wildcard wget execution grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(wget:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-wget-permission`
- Benign Corpus: `claude-settings-wget-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC413 / CLAUDE-GIT-CONFIG-PERMISSION` — Claude settings permissions allow `Bash(git config:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-CONFIG-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for wildcard git config mutation grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(git config:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-git-config-permission`
- Benign Corpus: `claude-settings-git-config-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC414 / CLAUDE-GIT-TAG-PERMISSION` — Claude settings permissions allow `Bash(git tag:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-TAG-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for wildcard git tag mutation grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(git tag:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-git-tag-permission`
- Benign Corpus: `claude-settings-git-tag-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC415 / CLAUDE-GIT-BRANCH-PERMISSION` — Claude settings permissions allow `Bash(git branch:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-BRANCH-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for wildcard git branch mutation grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(git branch:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-git-branch-permission`
- Benign Corpus: `claude-settings-git-branch-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC416 / MD-CLAUDE-PIP-INSTALL` — AI-native markdown models Claude package installation with bare `pip install` despite explicit `uv` preference guidance

- Provider: `lintai-ai-security`
- Alias: `MD-CLAUDE-PIP-INSTALL`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: This rule depends on transcript-shaped markdown plus explicit `uv` preference context in the same AI-native document, so the first release stays guidance-only while broader ecosystem usefulness is measured.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC417 / MD-PIP-GIT-UNPINNED` — AI-native markdown installs Python packages from an unpinned `git+https://` source

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-GIT-UNPINNED`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip install` examples that pull directly from mutable git+https sources without commit pinning.
- Deterministic Signal Basis: MarkdownSignals exact `pip install` plus `git+https://` token analysis with commit-pin detection inside parsed markdown regions.
- Malicious Corpus: `claude-unpinned-pip-git-install`
- Benign Corpus: `claude-unpinned-pip-git-install-commit-pinned-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC418 / CLAUDE-WEBFETCH-RAW-GITHUB` — Claude settings permissions allow `WebFetch(domain:raw.githubusercontent.com)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WEBFETCH-RAW-GITHUB`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for explicit raw GitHub content fetch grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `WebFetch(domain:raw.githubusercontent.com)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-webfetch-raw-github-permission`
- Benign Corpus: `claude-settings-webfetch-raw-github-fixture-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC419 / MD-CURL-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(curl:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-CURL-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for explicit wildcard curl grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(curl:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-curl-allowed-tools`
- Benign Corpus: `skill-curl-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC420 / MD-WGET-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(wget:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-WGET-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for explicit wildcard wget grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(wget:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-wget-allowed-tools`
- Benign Corpus: `skill-wget-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC421 / MD-GIT-CLONE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git clone:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-CLONE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git clone grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git clone:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-clone-allowed-tools`
- Benign Corpus: `skill-git-clone-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC422 / MCP-COMMAND-SUDO` — MCP configuration launches the server through `sudo`

- Provider: `lintai-ai-security`
- Alias: `MCP-COMMAND-SUDO`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact MCP server launch paths that run under `sudo`.
- Deterministic Signal Basis: JsonSignals exact string detection for `command: "sudo"` on parsed MCP configuration objects.
- Malicious Corpus: `mcp-command-sudo`
- Benign Corpus: `mcp-command-non-sudo-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC423 / MD-READ-UNSCOPED` — AI-native markdown frontmatter grants bare `Read` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-READ-UNSCOPED`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for bare Read grants that omit a reviewed repo-local scope.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for bare `Read` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-unscoped-read-allowed-tools`
- Benign Corpus: `skill-unscoped-read-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC424 / MD-WRITE-UNSCOPED` — AI-native markdown frontmatter grants bare `Write` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-WRITE-UNSCOPED`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for bare Write grants that omit a reviewed repo-local scope.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for bare `Write` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-unscoped-write-allowed-tools`
- Benign Corpus: `skill-unscoped-write-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC425 / MD-EDIT-UNSCOPED` — AI-native markdown frontmatter grants bare `Edit` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-EDIT-UNSCOPED`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for bare Edit grants that omit a reviewed repo-local scope.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for bare `Edit` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-unscoped-edit-allowed-tools`
- Benign Corpus: `skill-unscoped-edit-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC426 / MD-GLOB-UNSCOPED` — AI-native markdown frontmatter grants bare `Glob` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GLOB-UNSCOPED`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for bare Glob grants that omit a reviewed repo-local discovery scope.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for bare `Glob` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-unscoped-glob-allowed-tools`
- Benign Corpus: `skill-unscoped-glob-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC427 / MD-GREP-UNSCOPED` — AI-native markdown frontmatter grants bare `Grep` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GREP-UNSCOPED`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for bare Grep grants that omit a reviewed search scope.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for bare `Grep` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-unscoped-grep-allowed-tools`
- Benign Corpus: `skill-unscoped-grep-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC428 / MD-READ-UNSAFE-PATH` — AI-native markdown frontmatter grants `Read(...)` over an unsafe repo-external path

- Provider: `lintai-ai-security`
- Alias: `MD-READ-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for `Read(...)` grants scoped to absolute, home-relative, drive-letter, or parent-traversing paths outside the repository boundary.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token analysis for `Read(...)` scopes with absolute, home-relative, drive-letter, or parent-traversing path markers.
- Malicious Corpus: `skill-read-unsafe-path-allowed-tools`
- Benign Corpus: `skill-read-unsafe-path-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC429 / MD-WRITE-UNSAFE-PATH` — AI-native markdown frontmatter grants `Write(...)` over an unsafe repo-external path

- Provider: `lintai-ai-security`
- Alias: `MD-WRITE-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for `Write(...)` grants scoped to absolute, home-relative, drive-letter, or parent-traversing paths outside the repository boundary.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token analysis for `Write(...)` scopes with absolute, home-relative, drive-letter, or parent-traversing path markers.
- Malicious Corpus: `skill-write-unsafe-path-allowed-tools`
- Benign Corpus: `skill-write-unsafe-path-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC430 / MD-EDIT-UNSAFE-PATH` — AI-native markdown frontmatter grants `Edit(...)` over an unsafe repo-external path

- Provider: `lintai-ai-security`
- Alias: `MD-EDIT-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for `Edit(...)` grants scoped to absolute, home-relative, drive-letter, or parent-traversing paths outside the repository boundary.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token analysis for `Edit(...)` scopes with absolute, home-relative, drive-letter, or parent-traversing path markers.
- Malicious Corpus: `skill-edit-unsafe-path-allowed-tools`
- Benign Corpus: `skill-edit-unsafe-path-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC431 / MD-GLOB-UNSAFE-PATH` — AI-native markdown frontmatter grants `Glob(...)` over an unsafe repo-external path

- Provider: `lintai-ai-security`
- Alias: `MD-GLOB-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for `Glob(...)` grants scoped to absolute, home-relative, drive-letter, or parent-traversing paths outside the repository boundary.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token analysis for `Glob(...)` scopes with absolute, home-relative, drive-letter, or parent-traversing path markers.
- Malicious Corpus: `skill-glob-unsafe-path-allowed-tools`
- Benign Corpus: `skill-glob-unsafe-path-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC432 / MD-GIT-ADD-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git add:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-ADD-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git add grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git add:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-add-allowed-tools`
- Benign Corpus: `skill-git-add-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC433 / MD-GIT-FETCH-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git fetch:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-FETCH-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git fetch grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git fetch:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-fetch-allowed-tools`
- Benign Corpus: `skill-git-fetch-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC434 / MD-WEBFETCH-RAW-GITHUB` — AI-native markdown frontmatter grants `WebFetch(domain:raw.githubusercontent.com)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-WEBFETCH-RAW-GITHUB`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for explicit raw GitHub content fetch grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `WebFetch(domain:raw.githubusercontent.com)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-webfetch-raw-github-allowed-tools`
- Benign Corpus: `skill-webfetch-raw-github-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC435 / MD-GIT-CONFIG-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git config:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-CONFIG-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git config grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git config:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-config-allowed-tools`
- Benign Corpus: `skill-git-config-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC436 / MD-GIT-TAG-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git tag:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-TAG-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git tag grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git tag:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-tag-allowed-tools`
- Benign Corpus: `skill-git-tag-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC437 / MD-GIT-BRANCH-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git branch:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-BRANCH-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git branch grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git branch:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-branch-allowed-tools`
- Benign Corpus: `skill-git-branch-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC438 / MD-GIT-RESET-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git reset:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-RESET-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git reset grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git reset:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-reset-allowed-tools`
- Benign Corpus: `skill-git-reset-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC439 / MD-GIT-CLEAN-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git clean:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-CLEAN-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git clean grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git clean:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-clean-allowed-tools`
- Benign Corpus: `skill-git-clean-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC440 / MD-GIT-RESTORE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git restore:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-RESTORE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git restore grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git restore:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-restore-allowed-tools`
- Benign Corpus: `skill-git-restore-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC441 / MD-GIT-REBASE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git rebase:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-REBASE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git rebase grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git rebase:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-rebase-allowed-tools`
- Benign Corpus: `skill-git-rebase-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC442 / MD-GIT-MERGE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git merge:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-MERGE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git merge grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git merge:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-merge-allowed-tools`
- Benign Corpus: `skill-git-merge-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC443 / MD-GIT-CHERRY-PICK-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git cherry-pick:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-CHERRY-PICK-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git cherry-pick grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git cherry-pick:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-cherry-pick-allowed-tools`
- Benign Corpus: `skill-git-cherry-pick-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC444 / MD-GIT-APPLY-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git apply:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-APPLY-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git apply grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git apply:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-apply-allowed-tools`
- Benign Corpus: `skill-git-apply-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC445 / MD-GIT-AM-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git am:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-AM-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git am grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git am:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-am-allowed-tools`
- Benign Corpus: `skill-git-am-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC446 / MCP-ARGS-SUDO` — MCP configuration passes `sudo` as the first launch argument

- Provider: `lintai-ai-security`
- Alias: `MCP-ARGS-SUDO`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `base`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact MCP server launch paths that pass `sudo` as the first argv element.
- Deterministic Signal Basis: JsonSignals exact string detection for `args[0] == "sudo"` on parsed MCP configuration objects.
- Malicious Corpus: `mcp-args-sudo`
- Benign Corpus: `mcp-args-non-sudo-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC447 / MD-PACKAGE-INSTALL-ALLOWED-TOOLS` — AI-native markdown frontmatter grants package installation authority

- Provider: `lintai-ai-security`
- Alias: `MD-PACKAGE-INSTALL-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for shared package-install grants in allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for package-install permissions such as `Bash(pip install)` and `Bash(npm install)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-package-install-allowed-tools`
- Benign Corpus: `skill-package-command-allowed-tools-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC448 / MD-PIP-TRUSTED-HOST` — AI-native markdown installs Python packages with `--trusted-host`

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-TRUSTED-HOST`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip install` examples that disable host trust checks with `--trusted-host`.
- Deterministic Signal Basis: MarkdownSignals exact `pip install` token analysis with `--trusted-host` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-trusted-host`
- Benign Corpus: `skill-pip-index-url-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC449 / MD-PIP-HTTP-INDEX` — AI-native markdown installs Python packages from an insecure `http://` package index

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-HTTP-INDEX`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip install` examples that point package index resolution at `http://` sources.
- Deterministic Signal Basis: MarkdownSignals exact `pip install` token analysis with `--index-url http://` or `--extra-index-url http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-http-index`
- Benign Corpus: `skill-pip-https-index-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC450 / MD-NPM-HTTP-REGISTRY` — AI-native markdown installs JavaScript packages from an insecure `http://` registry

- Provider: `lintai-ai-security`
- Alias: `MD-NPM-HTTP-REGISTRY`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `npm`, `pnpm`, `yarn`, and `bun` install examples that point dependency resolution at `http://` registries.
- Deterministic Signal Basis: MarkdownSignals exact `npm install`, `npm i`, `pnpm add/install`, `yarn add`, or `bun add` token analysis with `--registry http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-npm-http-registry`
- Benign Corpus: `skill-npm-https-registry-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC451 / MD-CARGO-HTTP-GIT-INSTALL` — AI-native markdown installs Rust packages from an insecure `http://` git source

- Provider: `lintai-ai-security`
- Alias: `MD-CARGO-HTTP-GIT-INSTALL`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `cargo install` examples that fetch a crate directly from an `http://` git source.
- Deterministic Signal Basis: MarkdownSignals exact `cargo install` token analysis with `--git http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-cargo-http-git-install`
- Benign Corpus: `skill-cargo-https-git-install-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC452 / MD-CARGO-HTTP-INDEX` — AI-native markdown installs Rust packages from an insecure `http://` index

- Provider: `lintai-ai-security`
- Alias: `MD-CARGO-HTTP-INDEX`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `cargo install` examples that resolve crates through an `http://` index.
- Deterministic Signal Basis: MarkdownSignals exact `cargo install` token analysis with `--index http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-cargo-http-index`
- Benign Corpus: `skill-cargo-https-index-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC453 / MD-PIP-HTTP-SOURCE` — AI-native markdown installs Python packages from an insecure direct `http://` source

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-HTTP-SOURCE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip install` examples that fetch a direct package source over `http://`.
- Deterministic Signal Basis: MarkdownSignals exact `pip install` token analysis with direct `http://` source detection inside parsed markdown regions, excluding `--index-url` and `--extra-index-url` forms already covered by SEC449.
- Malicious Corpus: `skill-pip-http-source`
- Benign Corpus: `skill-pip-https-source-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC454 / MD-NPM-HTTP-SOURCE` — AI-native markdown installs JavaScript packages from an insecure direct `http://` source

- Provider: `lintai-ai-security`
- Alias: `MD-NPM-HTTP-SOURCE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `npm`, `pnpm`, `yarn`, and `bun` install examples that fetch a direct package source over `http://`.
- Deterministic Signal Basis: MarkdownSignals exact `npm install`, `npm i`, `pnpm add/install`, `yarn add`, or `bun add` token analysis with direct `http://` source detection inside parsed markdown regions, excluding `--registry http://` forms already covered by SEC450.
- Malicious Corpus: `skill-npm-http-source`
- Benign Corpus: `skill-npm-https-source-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC455 / MD-PIP-HTTP-GIT-INSTALL` — AI-native markdown installs Python packages from an insecure `git+http://` source

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-HTTP-GIT-INSTALL`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip install` examples that fetch Python packages from an insecure `git+http://` source.
- Deterministic Signal Basis: MarkdownSignals exact `pip install` token analysis with `git+http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-http-git-install`
- Benign Corpus: `skill-pip-https-git-install-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC456 / MD-PIP-HTTP-FIND-LINKS` — AI-native markdown installs Python packages with insecure `http://` find-links

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-HTTP-FIND-LINKS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip install` examples that point package discovery at `http://` find-links sources.
- Deterministic Signal Basis: MarkdownSignals exact `pip install` token analysis with `--find-links http://`, `--find-links=http://`, or `-f http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-http-find-links`
- Benign Corpus: `skill-pip-https-find-links-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC457 / MD-JS-PACKAGE-STRICT-SSL-FALSE` — AI-native markdown disables strict SSL verification for JavaScript package manager config

- Provider: `lintai-ai-security`
- Alias: `MD-JS-PACKAGE-STRICT-SSL-FALSE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for JavaScript package-manager config commands that explicitly disable strict SSL verification.
- Deterministic Signal Basis: MarkdownSignals exact `npm config set`, `pnpm config set`, or `yarn config set` token analysis with `strict-ssl false` or `strict-ssl=false` detection inside parsed markdown regions.
- Malicious Corpus: `skill-js-package-strict-ssl-false`
- Benign Corpus: `skill-js-package-strict-ssl-true-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC458 / MD-PIP-CONFIG-HTTP-INDEX` — AI-native markdown configures Python package resolution with an insecure `http://` package index

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-CONFIG-HTTP-INDEX`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip config set` commands that point package index configuration at `http://` sources.
- Deterministic Signal Basis: MarkdownSignals exact `pip config set`, `pip3 config set`, or `python -m pip config set` token analysis with `global.index-url http://` or `global.extra-index-url http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-config-http-index`
- Benign Corpus: `skill-pip-config-https-index-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC459 / MD-JS-PACKAGE-CONFIG-HTTP-REGISTRY` — AI-native markdown configures a JavaScript package manager with an insecure `http://` registry

- Provider: `lintai-ai-security`
- Alias: `MD-JS-PACKAGE-CONFIG-HTTP-REGISTRY`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for JavaScript package-manager config commands that point registry configuration at `http://` sources.
- Deterministic Signal Basis: MarkdownSignals exact `npm config set`, `pnpm config set`, or `yarn config set` token analysis with `registry http://` or `registry=http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-js-package-config-http-registry`
- Benign Corpus: `skill-js-package-config-https-registry-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC460 / MD-PIP-CONFIG-HTTP-FIND-LINKS` — AI-native markdown configures Python package discovery with insecure `http://` find-links

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-CONFIG-HTTP-FIND-LINKS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip config set` commands that point package discovery configuration at `http://` find-links sources.
- Deterministic Signal Basis: MarkdownSignals exact `pip config set`, `pip3 config set`, or `python -m pip config set` token analysis with `global.find-links http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-config-http-find-links`
- Benign Corpus: `skill-pip-config-https-find-links-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC461 / MD-PIP-CONFIG-TRUSTED-HOST` — AI-native markdown configures Python package resolution with `trusted-host`

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-CONFIG-TRUSTED-HOST`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip config set` commands that configure trusted-host bypass behavior.
- Deterministic Signal Basis: MarkdownSignals exact `pip config set`, `pip3 config set`, or `python -m pip config set` token analysis with `global.trusted-host` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-config-trusted-host`
- Benign Corpus: `skill-pip-config-unrelated-key-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC462 / MD-NETWORK-TLS-BYPASS` — AI-native markdown disables TLS verification for a network-capable command

- Provider: `lintai-ai-security`
- Alias: `MD-NETWORK-TLS-BYPASS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for exact network-command examples that disable TLS verification, including PowerShell certificate-bypass forms.
- Deterministic Signal Basis: MarkdownSignals exact command-token analysis with `--insecure`, `-k`, `--no-check-certificate`, `-SkipCertificateCheck`, or `NODE_TLS_REJECT_UNAUTHORIZED=0` detection inside parsed markdown regions, with safety-guidance suppression.
- Malicious Corpus: `skill-markdown-network-tls-bypass`, `skill-markdown-network-tls-bypass-powershell`
- Benign Corpus: `skill-markdown-network-tls-bypass-warning-safe`, `skill-markdown-network-tls-bypass-powershell-warning-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC463 / MD-SUDO-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(sudo:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-SUDO-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for explicit wildcard sudo grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(sudo:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-sudo-allowed-tools`
- Benign Corpus: `skill-sudo-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC464 / MD-GIT-HTTP-CLONE` — AI-native markdown clones a Git repository from an insecure `http://` source

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-HTTP-CLONE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `git clone` examples that fetch repositories directly from an insecure `http://` source.
- Deterministic Signal Basis: MarkdownSignals exact `git clone` token analysis with direct `http://` source detection inside parsed markdown regions.
- Malicious Corpus: `skill-git-http-clone`
- Benign Corpus: `skill-git-https-clone-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC465 / MD-GIT-HTTP-REMOTE` — AI-native markdown configures a Git remote with an insecure `http://` source

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-HTTP-REMOTE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `git remote add` examples that configure a repository remote through an insecure `http://` source.
- Deterministic Signal Basis: MarkdownSignals exact `git remote add` token analysis with direct `http://` source detection inside parsed markdown regions.
- Malicious Corpus: `skill-git-http-remote`
- Benign Corpus: `skill-git-https-remote-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC466 / MD-RM-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(rm:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-RM-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for explicit wildcard rm grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(rm:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-rm-allowed-tools`
- Benign Corpus: `skill-rm-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC467 / MD-CHMOD-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(chmod:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-CHMOD-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for explicit wildcard chmod grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(chmod:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-chmod-allowed-tools`
- Benign Corpus: `skill-chmod-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC468 / MD-CHOWN-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(chown:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-CHOWN-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for explicit wildcard chown grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(chown:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-chown-allowed-tools`
- Benign Corpus: `skill-chown-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC469 / MD-CHGRP-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(chgrp:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-CHGRP-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for explicit wildcard chgrp grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(chgrp:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-chgrp-allowed-tools`
- Benign Corpus: `skill-chgrp-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC470 / MD-SU-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(su:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-SU-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for explicit wildcard su grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(su:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-su-allowed-tools`
- Benign Corpus: `skill-su-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC471 / MD-GIT-SSLVERIFY-FALSE` — AI-native markdown disables Git TLS verification with `http.sslVerify false`

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-SSLVERIFY-FALSE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for exact `git config` examples that disable Git TLS verification through `http.sslVerify false`.
- Deterministic Signal Basis: MarkdownSignals exact `git config` token analysis with `http.sslVerify false` or `http.sslVerify=false` detection inside parsed markdown regions, excluding safety-warning phrasing.
- Malicious Corpus: `skill-git-sslverify-false`
- Benign Corpus: `skill-git-sslverify-true-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC472 / MD-GIT-SSL-NO-VERIFY` — AI-native markdown disables Git TLS verification with `GIT_SSL_NO_VERIFY`

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-SSL-NO-VERIFY`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `preview`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for exact Git command examples that disable TLS verification through `GIT_SSL_NO_VERIFY`.
- Deterministic Signal Basis: MarkdownSignals exact `GIT_SSL_NO_VERIFY=1` or `GIT_SSL_NO_VERIFY=true` token analysis when a Git command appears in the same parsed markdown region, excluding safety-warning phrasing.
- Malicious Corpus: `skill-git-ssl-no-verify`
- Benign Corpus: `skill-git-ssl-no-verify-disabled-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

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
