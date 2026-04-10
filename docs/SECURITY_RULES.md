# Security Rules Catalog

> Generated file. Do not edit by hand.
> Source: `lintai-cli` shipped rule inventory aggregated from provider catalogs.

Canonical catalog for the shipped security rules currently exposed by:
- `lintai-ai-security`
- `lintai-policy-mismatch`
- `lintai-dep-vulns`

## Summary

| Code | Summary | Public Lane | Tier | Lifecycle | Severity | Scope | Surface | Detection | Remediation | Presets |
|---|---|---|---|---|---|---|---|---|---|---|
| `SEC101 / MD-HIDDEN-INSTRUCTIONS` | Hidden HTML comment contains dangerous agent instructions | `threat-review` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `safe_fix` | `threat-review`, `skills` |
| `SEC102 / MD-DOWNLOAD-EXEC` | Markdown contains remote download-and-execute instruction outside code blocks | `threat-review` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `suggestion` | `threat-review`, `skills` |
| `SEC103 / MD-HIDDEN-DOWNLOAD-EXEC` | Hidden HTML comment contains remote download-and-execute instruction | `threat-review` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `safe_fix` | `threat-review`, `skills` |
| `SEC104 / MD-BASE64-EXEC` | Markdown contains a base64-decoded executable payload outside code blocks | `threat-review` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` | `threat-review`, `skills` |
| `SEC105 / MD-PATH-TRAVERSAL` | Markdown instructions reference parent-directory traversal for file access | `threat-review` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` | `threat-review`, `skills` |
| `SEC201 / HOOK-DOWNLOAD-EXEC` | Hook script downloads remote code and executes it | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `suggestion` | `threat-review` |
| `SEC202 / HOOK-SECRET-EXFIL` | Hook script appears to exfiltrate secrets through a network call | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `suggestion` | `threat-review` |
| `SEC203 / HOOK-PLAIN-HTTP-SECRET-EXFIL` | Hook script sends secret material to an insecure http:// endpoint | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `suggestion` | `threat-review` |
| `SEC204 / HOOK-TLS-BYPASS` | Hook script disables TLS or certificate verification for a network call | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC205 / HOOK-STATIC-AUTH` | Hook script embeds static authentication material in a network call | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC206 / HOOK-BASE64-EXEC` | Hook script decodes a base64 payload and executes it | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `suggestion` | `threat-review` |
| `SEC301 / MCP-SHELL-WRAPPER` | MCP configuration shells out through sh -c or bash -c | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC302 / MCP-PLAIN-HTTP-ENDPOINT` | Configuration contains an insecure http:// endpoint | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `suggestion` | `supply-chain` |
| `SEC303 / MCP-CREDENTIAL-ENV-PASSTHROUGH` | MCP configuration passes through credential environment variables | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC304 / MCP-TLS-BYPASS` | Configuration disables TLS or certificate verification | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `supply-chain` |
| `SEC305 / MCP-STATIC-AUTH` | Configuration embeds static authentication material in a connection or auth value | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC306 / MCP-HIDDEN-INSTRUCTIONS` | JSON configuration description contains override-style hidden instructions | `threat-review` | Preview | `preview_blocked` | Warn | `per_file` | `json` | `heuristic` | `message_only` | `threat-review`, `mcp` |
| `SEC307 / MCP-SENSITIVE-ENV-REFERENCE` | Configuration forwards sensitive environment variable references | `governance` | Preview | `preview_blocked` | Warn | `per_file` | `json` | `heuristic` | `message_only` | `governance`, `mcp` |
| `SEC308 / MCP-SUSPICIOUS-ENDPOINT` | Configuration points at a suspicious remote endpoint | `preview` | Preview | `preview_blocked` | Warn | `per_file` | `json` | `heuristic` | `message_only` | `preview`, `mcp` |
| `SEC309 / MCP-LITERAL-SECRET` | Configuration commits literal secret material in env, auth, or header values | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC310 / MCP-METADATA-HOST-LITERAL` | Configuration endpoint targets a metadata or private-network host literal | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC311 / PLUGIN-UNSAFE-PATH` | Cursor plugin manifest contains an unsafe absolute or parent-traversing path | `compat` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `compat`, `mcp` |
| `SEC312 / MD-PRIVATE-KEY` | Markdown contains committed private key material | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `threat-review`, `skills` |
| `SEC313 / MD-PIPE-SHELL` | Fenced shell example pipes remote content directly into a shell | `threat-review` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `threat-review`, `skills` |
| `SEC314 / TOOL-MISSING-MACHINE-FIELDS` | MCP-style tool descriptor is missing required machine fields | `compat` | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` | `compat`, `mcp` |
| `SEC315 / TOOL-DUPLICATE-NAMES` | MCP-style tool descriptor collection contains duplicate tool names | `compat` | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` | `compat`, `mcp` |
| `SEC316 / OPENAI-STRICT-ADDITIONAL-PROPERTIES` | OpenAI strict tool schema omits recursive additionalProperties: false | `compat` | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` | `compat`, `mcp` |
| `SEC317 / OPENAI-STRICT-REQUIRED-COVERAGE` | OpenAI strict tool schema does not require every declared property | `compat` | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` | `compat`, `mcp` |
| `SEC318 / ANTHROPIC-STRICT-ADDITIONAL-PROPERTIES` | Anthropic strict tool input schema omits additionalProperties: false | `compat` | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` | `compat`, `mcp` |
| `SEC319 / SERVER-REMOTE-URL` | server.json remotes entry uses an insecure or non-public remote URL | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `server_json` | `structural` | `message_only` | `supply-chain`, `mcp` |
| `SEC320 / SERVER-UNDEFINED-URL-VAR` | server.json remotes URL references an undefined template variable | `compat` | Stable | `stable_gated` | Warn | `per_file` | `server_json` | `structural` | `message_only` | `compat`, `mcp` |
| `SEC321 / SERVER-LITERAL-AUTH-HEADER` | server.json remotes header commits literal authentication material | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `server_json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC322 / SERVER-UNDEFINED-HEADER-VAR` | server.json remotes header value references an undefined template variable | `compat` | Stable | `stable_gated` | Warn | `per_file` | `server_json` | `structural` | `message_only` | `compat`, `mcp` |
| `SEC323 / SERVER-AUTH-SECRET-FLAG` | server.json auth header carries material without an explicit secret flag | `compat` | Preview | `preview_blocked` | Warn | `per_file` | `server_json` | `structural` | `message_only` | `compat`, `mcp` |
| `SEC324 / GHA-UNPINNED-ACTION` | GitHub Actions workflow uses a third-party action that is not pinned to a full commit SHA | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` | `supply-chain` |
| `SEC325 / GHA-UNTRUSTED-RUN-INTERPOLATION` | GitHub Actions workflow interpolates untrusted expression data directly inside a run command | `supply-chain` | Preview | `preview_blocked` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` | `supply-chain` |
| `SEC326 / GHA-PR-TARGET-HEAD-CHECKOUT` | GitHub Actions pull_request_target workflow checks out untrusted pull request head content | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` | `supply-chain` |
| `SEC327 / GHA-WRITE-ALL-PERMISSIONS` | GitHub Actions workflow grants GITHUB_TOKEN write-all permissions | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` | `supply-chain` |
| `SEC328 / GHA-WRITE-CAPABLE-THIRD-PARTY-ACTION` | GitHub Actions workflow combines explicit write-capable permissions with a third-party action | `supply-chain` | Preview | `preview_blocked` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` | `supply-chain` |
| `SEC329 / MCP-MUTABLE-LAUNCHER` | MCP configuration launches tooling through a mutable package runner | `recommended` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `recommended`, `base`, `mcp` |
| `SEC330 / MCP-DOWNLOAD-EXEC` | MCP configuration command downloads remote content and pipes it into a shell | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `supply-chain`, `mcp` |
| `SEC331 / MCP-TLS-BYPASS` | MCP configuration command disables TLS verification in a network-capable execution path | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `supply-chain` |
| `SEC335 / MD-METADATA-SERVICE-ACCESS` | AI-native markdown contains a direct cloud metadata-service access example | `threat-review` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `threat-review`, `skills` |
| `SEC336 / MCP-BROAD-ENVFILE` | Repo-local MCP client config loads a broad dotenv-style envFile | `governance` | Preview | `preview_blocked` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC337 / MCP-DOCKER-UNPINNED-IMAGE` | MCP configuration launches Docker with an image reference that is not digest-pinned | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `supply-chain` |
| `SEC338 / MCP-DOCKER-SENSITIVE-MOUNT` | MCP configuration launches Docker with a bind mount of sensitive host material | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC339 / MCP-DOCKER-HOST-ESCAPE` | MCP configuration launches Docker with a host-escape or privileged runtime flag | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC340 / CLAUDE-HOOK-MUTABLE-LAUNCHER` | Claude settings command hook uses a mutable package launcher | `recommended` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `recommended`, `base`, `claude` |
| `SEC341 / CLAUDE-HOOK-DOWNLOAD-EXEC` | Claude settings command hook downloads remote content and pipes it into a shell | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `supply-chain`, `claude` |
| `SEC342 / CLAUDE-HOOK-TLS-BYPASS` | Claude settings command hook disables TLS verification in a network-capable execution path | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `supply-chain`, `claude` |
| `SEC343 / PLUGIN-HOOK-MUTABLE-LAUNCHER` | Plugin hook command uses a mutable package launcher | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `supply-chain` |
| `SEC344 / PLUGIN-HOOK-DOWNLOAD-EXEC` | Plugin hook command downloads remote content and pipes it into a shell | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `supply-chain`, `mcp` |
| `SEC345 / PLUGIN-HOOK-TLS-BYPASS` | Plugin hook command disables TLS verification in a network-capable execution path | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `supply-chain` |
| `SEC346 / MCP-DOCKER-PULL-ALWAYS` | MCP configuration forces Docker to refresh from a mutable registry source | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `supply-chain` |
| `SEC347 / MD-MCP-MUTABLE-LAUNCHER` | AI-native markdown example launches MCP through a mutable package runner | `supply-chain` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC348 / MD-DOCKER-MUTABLE-IMAGE` | AI-native markdown Docker example uses a mutable registry image | `supply-chain` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC349 / MD-DOCKER-HOST-ESCAPE` | AI-native markdown Docker example uses a host-escape or privileged runtime pattern | `threat-review` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `threat-review`, `skills` |
| `SEC350 / MD-UNTRUSTED-INSTRUCTION-PROMOTION` | Instruction markdown promotes untrusted external content to developer/system-level instructions | `threat-review` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` | `threat-review`, `skills` |
| `SEC351 / MD-APPROVAL-BYPASS` | AI-native instruction explicitly disables user approval or confirmation | `threat-review` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` | `threat-review`, `skills` |
| `SEC352 / MD-UNSCOPED-BASH` | AI-native markdown frontmatter grants unscoped Bash tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC353 / COPILOT-4K` | GitHub Copilot instruction markdown exceeds the 4000-character guidance limit | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC354 / COPILOT-PATH-APPLYTO` | Path-specific GitHub Copilot instruction markdown is missing `applyTo` frontmatter | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC355 / MD-WILDCARD-TOOLS` | AI-native markdown frontmatter grants wildcard tool access | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC356 / PLUGIN-AGENT-PERMISSIONMODE` | Plugin agent frontmatter sets `permissionMode` | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC357 / PLUGIN-AGENT-HOOKS` | Plugin agent frontmatter sets `hooks` | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC358 / PLUGIN-AGENT-MCPSERVERS` | Plugin agent frontmatter sets `mcpServers` | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC359 / CURSOR-RULE-ALWAYSAPPLY` | Cursor rule frontmatter `alwaysApply` must be boolean | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC360 / CURSOR-RULE-GLOBS` | Cursor rule frontmatter `globs` must be a sequence of patterns | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC361 / CLAUDE-SETTINGS-SCHEMA` | Claude settings file is missing a top-level `$schema` reference | `compat` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `compat`, `claude` |
| `SEC362 / CLAUDE-BASH-WILDCARD` | Claude settings permissions allow `Bash(*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC363 / CLAUDE-HOME-HOOK-PATH` | Claude settings hook command uses a home-directory path in a shared committed config | `compat` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `compat`, `claude` |
| `SEC364 / CLAUDE-BYPASS-PERMISSIONS` | Claude settings set `permissions.defaultMode` to `bypassPermissions` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC365 / CLAUDE-HTTP-HOOK-URL` | Claude settings allow non-HTTPS HTTP hook URLs in a shared committed config | `supply-chain` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `supply-chain`, `claude` |
| `SEC366 / CLAUDE-HTTP-HOOK-HOST` | Claude settings allow dangerous host literals in `allowedHttpHookUrls` | `supply-chain` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `supply-chain`, `claude` |
| `SEC367 / CLAUDE-WEBFETCH-WILDCARD` | Claude settings permissions allow `WebFetch(*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC368 / CLAUDE-ABS-HOOK-PATH` | Claude settings hook command uses a repo-external absolute path in a shared committed config | `compat` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `compat`, `claude` |
| `SEC369 / CLAUDE-WRITE-WILDCARD` | Claude settings permissions allow `Write(*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC370 / COPILOT-PATH-SUFFIX` | Path-specific GitHub Copilot instruction markdown under `.github/instructions/` uses the wrong file suffix | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC371 / COPILOT-APPLYTO-TYPE` | Path-specific GitHub Copilot instruction markdown has an invalid `applyTo` shape | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC372 / CLAUDE-READ-WILDCARD` | Claude settings permissions allow `Read(*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC373 / CLAUDE-EDIT-WILDCARD` | Claude settings permissions allow `Edit(*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC374 / CLAUDE-WEBSEARCH-WILDCARD` | Claude settings permissions allow `WebSearch(*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC375 / CLAUDE-GLOB-WILDCARD` | Claude settings permissions allow `Glob(*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC376 / CLAUDE-GREP-WILDCARD` | Claude settings permissions allow `Grep(*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC377 / COPILOT-APPLYTO-GLOB` | Path-specific GitHub Copilot instruction markdown has an invalid `applyTo` glob pattern | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC378 / CURSOR-ALWAYSAPPLY-GLOBS` | Cursor rule frontmatter should not set `globs` when `alwaysApply` is `true` | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC379 / CURSOR-UNKNOWN-FRONTMATTER` | Cursor rule frontmatter contains an unknown key | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC380 / CURSOR-DESCRIPTION` | Cursor rule frontmatter should include `description` | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `guidance` |
| `SEC381 / CLAUDE-HOOK-TIMEOUT` | Claude settings command hook should set `timeout` in a shared committed config | `compat` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `compat`, `claude` |
| `SEC382 / CLAUDE-HOOK-MATCHER-EVENT` | Claude settings should not use `matcher` on unsupported hook events | `compat` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `compat`, `claude` |
| `SEC383 / CLAUDE-HOOK-MISSING-MATCHER` | Claude settings should set `matcher` on matcher-capable hook events | `compat` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `compat`, `claude` |
| `SEC384 / CLAUDE-WEBSEARCH-UNSCOPED` | Claude settings permissions allow bare `WebSearch` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC385 / CLAUDE-GIT-PUSH-PERMISSION` | Claude settings permissions allow `Bash(git push)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC386 / CLAUDE-GIT-CHECKOUT-PERMISSION` | Claude settings permissions allow `Bash(git checkout:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC387 / CLAUDE-GIT-COMMIT-PERMISSION` | Claude settings permissions allow `Bash(git commit:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC388 / CLAUDE-GIT-STASH-PERMISSION` | Claude settings permissions allow `Bash(git stash:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC389 / MD-WEBSEARCH-UNSCOPED` | AI-native markdown frontmatter grants bare `WebSearch` tool access | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC390 / MD-GIT-PUSH-PERMISSION` | AI-native markdown frontmatter grants `Bash(git push)` tool access | `governance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC391 / MD-GIT-CHECKOUT-PERMISSION` | AI-native markdown frontmatter grants `Bash(git checkout:*)` tool access | `governance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC392 / MD-GIT-COMMIT-PERMISSION` | AI-native markdown frontmatter grants `Bash(git commit:*)` tool access | `governance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC393 / MD-GIT-STASH-PERMISSION` | AI-native markdown frontmatter grants `Bash(git stash:*)` tool access | `governance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC394 / MCP-AUTOAPPROVE-WILDCARD` | MCP configuration auto-approves all tools with `autoApprove: ["*"]` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC395 / MCP-AUTOAPPROVE-TOOLS` | MCP configuration auto-approves all tools with `autoApproveTools: true` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC396 / MCP-TRUST-TOOLS` | MCP configuration fully trusts tools with `trustTools: true` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC397 / MCP-SANDBOX-DISABLED` | MCP configuration disables sandboxing with `sandbox: false` or `disableSandbox: true` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC398 / MCP-CAPABILITIES-WILDCARD` | MCP configuration grants all capabilities with `capabilities: ["*"]` or `capabilities: "*"` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC399 / CLAUDE-NPX-PERMISSION` | Claude settings permissions allow `Bash(npx ...)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC400 / CLAUDE-ENABLED-MCPJSON-SERVERS` | Claude settings enable `enabledMcpjsonServers` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC401 / POLICY-EXEC-MISMATCH` | Project policy forbids execution, but repository contains executable behavior | `compat` | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` | `compat` |
| `SEC402 / POLICY-NETWORK-MISMATCH` | Project policy forbids network access, but repository contains network behavior | `compat` | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` | `compat` |
| `SEC403 / POLICY-SKILL-CAPABILITIES-MISMATCH` | Skill frontmatter capabilities conflict with project policy | `compat` | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` | `compat` |
| `SEC404 / MD-WEBFETCH-UNSCOPED` | AI-native markdown frontmatter grants bare `WebFetch` tool access | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC405 / CLAUDE-PACKAGE-INSTALL-PERMISSION` | Claude settings permissions allow package installation commands in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC406 / CLAUDE-GIT-ADD-PERMISSION` | Claude settings permissions allow `Bash(git add:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC407 / CLAUDE-GIT-CLONE-PERMISSION` | Claude settings permissions allow `Bash(git clone:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC408 / CLAUDE-GH-PR-PERMISSION` | Claude settings permissions allow `Bash(gh pr:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC409 / CLAUDE-GIT-FETCH-PERMISSION` | Claude settings permissions allow `Bash(git fetch:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC410 / CLAUDE-GIT-LS-REMOTE-PERMISSION` | Claude settings permissions allow `Bash(git ls-remote:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC411 / CLAUDE-CURL-PERMISSION` | Claude settings permissions allow `Bash(curl:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC412 / CLAUDE-WGET-PERMISSION` | Claude settings permissions allow `Bash(wget:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC413 / CLAUDE-GIT-CONFIG-PERMISSION` | Claude settings permissions allow `Bash(git config:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC414 / CLAUDE-GIT-TAG-PERMISSION` | Claude settings permissions allow `Bash(git tag:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC415 / CLAUDE-GIT-BRANCH-PERMISSION` | Claude settings permissions allow `Bash(git branch:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC416 / MD-CLAUDE-PIP-INSTALL` | AI-native markdown models Claude package installation with bare `pip install` despite explicit `uv` preference guidance | `guidance` | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` | `guidance` |
| `SEC417 / MD-PIP-GIT-UNPINNED` | AI-native markdown installs Python packages from an unpinned `git+https://` source | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC418 / CLAUDE-WEBFETCH-RAW-GITHUB` | Claude settings permissions allow `WebFetch(domain:raw.githubusercontent.com)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC419 / MD-CURL-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(curl:*)` authority | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC420 / MD-WGET-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(wget:*)` authority | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC421 / MD-GIT-CLONE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git clone:*)` authority | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC422 / MCP-COMMAND-SUDO` | MCP configuration launches the server through `sudo` | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC423 / MD-READ-UNSCOPED` | AI-native markdown frontmatter grants bare `Read` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC424 / MD-WRITE-UNSCOPED` | AI-native markdown frontmatter grants bare `Write` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC425 / MD-EDIT-UNSCOPED` | AI-native markdown frontmatter grants bare `Edit` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC426 / MD-GLOB-UNSCOPED` | AI-native markdown frontmatter grants bare `Glob` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC427 / MD-GREP-UNSCOPED` | AI-native markdown frontmatter grants bare `Grep` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC428 / MD-READ-UNSAFE-PATH` | AI-native markdown frontmatter grants `Read(...)` over an unsafe repo-external path | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC429 / MD-WRITE-UNSAFE-PATH` | AI-native markdown frontmatter grants `Write(...)` over an unsafe repo-external path | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC430 / MD-EDIT-UNSAFE-PATH` | AI-native markdown frontmatter grants `Edit(...)` over an unsafe repo-external path | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC431 / MD-GLOB-UNSAFE-PATH` | AI-native markdown frontmatter grants `Glob(...)` over an unsafe repo-external path | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC432 / MD-GIT-ADD-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git add:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC433 / MD-GIT-FETCH-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git fetch:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC434 / MD-WEBFETCH-RAW-GITHUB` | AI-native markdown frontmatter grants `WebFetch(domain:raw.githubusercontent.com)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC435 / MD-GIT-CONFIG-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git config:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC436 / MD-GIT-TAG-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git tag:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC437 / MD-GIT-BRANCH-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git branch:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC438 / MD-GIT-RESET-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git reset:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC439 / MD-GIT-CLEAN-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git clean:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC440 / MD-GIT-RESTORE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git restore:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC441 / MD-GIT-REBASE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git rebase:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC442 / MD-GIT-MERGE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git merge:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC443 / MD-GIT-CHERRY-PICK-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git cherry-pick:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC444 / MD-GIT-APPLY-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git apply:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC445 / MD-GIT-AM-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git am:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC446 / MCP-ARGS-SUDO` | MCP configuration passes `sudo` as the first launch argument | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC447 / MD-PACKAGE-INSTALL-ALLOWED-TOOLS` | AI-native markdown frontmatter grants package installation authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC448 / MD-PIP-TRUSTED-HOST` | AI-native markdown installs Python packages with `--trusted-host` | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC449 / MD-PIP-HTTP-INDEX` | AI-native markdown installs Python packages from an insecure `http://` package index | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC450 / MD-NPM-HTTP-REGISTRY` | AI-native markdown installs JavaScript packages from an insecure `http://` registry | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC451 / MD-CARGO-HTTP-GIT-INSTALL` | AI-native markdown installs Rust packages from an insecure `http://` git source | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC452 / MD-CARGO-HTTP-INDEX` | AI-native markdown installs Rust packages from an insecure `http://` index | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC453 / MD-PIP-HTTP-SOURCE` | AI-native markdown installs Python packages from an insecure direct `http://` source | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC454 / MD-NPM-HTTP-SOURCE` | AI-native markdown installs JavaScript packages from an insecure direct `http://` source | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC455 / MD-PIP-HTTP-GIT-INSTALL` | AI-native markdown installs Python packages from an insecure `git+http://` source | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC456 / MD-PIP-HTTP-FIND-LINKS` | AI-native markdown installs Python packages with insecure `http://` find-links | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC457 / MD-JS-PACKAGE-STRICT-SSL-FALSE` | AI-native markdown disables strict SSL verification for JavaScript package manager config | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC458 / MD-PIP-CONFIG-HTTP-INDEX` | AI-native markdown configures Python package resolution with an insecure `http://` package index | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC459 / MD-JS-PACKAGE-CONFIG-HTTP-REGISTRY` | AI-native markdown configures a JavaScript package manager with an insecure `http://` registry | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC460 / MD-PIP-CONFIG-HTTP-FIND-LINKS` | AI-native markdown configures Python package discovery with insecure `http://` find-links | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC461 / MD-PIP-CONFIG-TRUSTED-HOST` | AI-native markdown configures Python package resolution with `trusted-host` | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC462 / MD-NETWORK-TLS-BYPASS` | AI-native markdown disables TLS verification for a network-capable command | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC463 / MD-SUDO-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(sudo:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC464 / MD-GIT-HTTP-CLONE` | AI-native markdown clones a Git repository from an insecure `http://` source | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC465 / MD-GIT-HTTP-REMOTE` | AI-native markdown configures a Git remote with an insecure `http://` source | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC466 / MD-RM-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(rm:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC467 / MD-CHMOD-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(chmod:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC468 / MD-CHOWN-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(chown:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC469 / MD-CHGRP-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(chgrp:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC470 / MD-SU-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(su:*)` authority | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC471 / MD-GIT-SSLVERIFY-FALSE` | AI-native markdown disables Git TLS verification with `http.sslVerify false` | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC472 / MD-GIT-SSL-NO-VERIFY` | AI-native markdown disables Git TLS verification with `GIT_SSL_NO_VERIFY` | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC473 / MD-GIT-INLINE-SSLVERIFY-FALSE` | AI-native markdown disables Git TLS verification with `git -c http.sslVerify=false` | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `supply-chain` |
| `SEC474 / MD-GH-PR-PERMISSION` | AI-native markdown frontmatter grants `Bash(gh pr:*)` tool access | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC475 / CLAUDE-READ-UNSAFE-PATH` | Claude settings permissions allow `Read(...)` over an unsafe path in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC476 / CLAUDE-WRITE-UNSAFE-PATH` | Claude settings permissions allow `Write(...)` over an unsafe path in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC477 / CLAUDE-EDIT-UNSAFE-PATH` | Claude settings permissions allow `Edit(...)` over an unsafe path in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC478 / CLAUDE-GIT-RESET-PERMISSION` | Claude settings permissions allow `Bash(git reset:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC479 / CLAUDE-GIT-CLEAN-PERMISSION` | Claude settings permissions allow `Bash(git clean:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC480 / CLAUDE-GIT-RESTORE-PERMISSION` | Claude settings permissions allow `Bash(git restore:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC481 / CLAUDE-GIT-REBASE-PERMISSION` | Claude settings permissions allow `Bash(git rebase:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC482 / CLAUDE-GIT-MERGE-PERMISSION` | Claude settings permissions allow `Bash(git merge:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC483 / CLAUDE-GIT-CHERRY-PICK-PERMISSION` | Claude settings permissions allow `Bash(git cherry-pick:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC484 / CLAUDE-GIT-APPLY-PERMISSION` | Claude settings permissions allow `Bash(git apply:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC485 / CLAUDE-GIT-AM-PERMISSION` | Claude settings permissions allow `Bash(git am:*)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC486 / CLAUDE-GLOB-UNSAFE-PATH` | Claude settings permissions allow `Glob(...)` over an unsafe path in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC487 / CLAUDE-GREP-UNSAFE-PATH` | Claude settings permissions allow `Grep(...)` over an unsafe path in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC488 / CLAUDE-UVX-PERMISSION` | Claude settings permissions allow `Bash(uvx ...)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC489 / CLAUDE-PNPM-DLX-PERMISSION` | Claude settings permissions allow `Bash(pnpm dlx ...)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC490 / CLAUDE-YARN-DLX-PERMISSION` | Claude settings permissions allow `Bash(yarn dlx ...)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC491 / CLAUDE-PIPX-RUN-PERMISSION` | Claude settings permissions allow `Bash(pipx run ...)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC492 / CLAUDE-NPM-EXEC-PERMISSION` | Claude settings permissions allow `Bash(npm exec ...)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC493 / CLAUDE-BUNX-PERMISSION` | Claude settings permissions allow `Bash(bunx ...)` in a shared committed config | `governance` | Preview | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC494 / MD-NPM-EXEC-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(npm exec:*)` tool access | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC495 / MD-BUNX-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(bunx:*)` tool access | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC496 / MD-UVX-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(uvx:*)` tool access | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC497 / MD-PNPM-DLX-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(pnpm dlx:*)` tool access | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC498 / MD-YARN-DLX-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(yarn dlx:*)` tool access | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC499 / MD-PIPX-RUN-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(pipx run:*)` tool access | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC500 / MD-NPX-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(npx:*)` tool access | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC501 / MD-GIT-LS-REMOTE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(git ls-remote:*)` tool access | `governance` | Preview | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC502 / CLAUDE-GH-API-POST-PERMISSION` | Claude settings permissions allow `Bash(gh api --method POST:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC503 / CLAUDE-GH-ISSUE-CREATE-PERMISSION` | Claude settings permissions allow `Bash(gh issue create:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC504 / CLAUDE-GH-REPO-CREATE-PERMISSION` | Claude settings permissions allow `Bash(gh repo create:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC505 / MD-GH-API-POST-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh api --method POST:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC506 / MD-GH-ISSUE-CREATE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh issue create:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC507 / MD-GH-REPO-CREATE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh repo create:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC508 / CLAUDE-GH-SECRET-SET-PERMISSION` | Claude settings permissions allow `Bash(gh secret set:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC509 / CLAUDE-GH-VARIABLE-SET-PERMISSION` | Claude settings permissions allow `Bash(gh variable set:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC510 / CLAUDE-GH-WORKFLOW-RUN-PERMISSION` | Claude settings permissions allow `Bash(gh workflow run:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC511 / MD-GH-SECRET-SET-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh secret set:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC512 / MD-GH-VARIABLE-SET-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh variable set:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC513 / MD-GH-WORKFLOW-RUN-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh workflow run:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC514 / CLAUDE-GH-SECRET-DELETE-PERMISSION` | Claude settings permissions allow `Bash(gh secret delete:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC515 / CLAUDE-GH-VARIABLE-DELETE-PERMISSION` | Claude settings permissions allow `Bash(gh variable delete:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC516 / CLAUDE-GH-WORKFLOW-DISABLE-PERMISSION` | Claude settings permissions allow `Bash(gh workflow disable:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC517 / MD-GH-SECRET-DELETE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh secret delete:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC518 / MD-GH-VARIABLE-DELETE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh variable delete:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC519 / MD-GH-WORKFLOW-DISABLE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh workflow disable:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC520 / MD-READ-WILDCARD` | AI-native markdown frontmatter grants `Read(*)` wildcard access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC521 / MD-WRITE-WILDCARD` | AI-native markdown frontmatter grants `Write(*)` wildcard access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC522 / MD-EDIT-WILDCARD` | AI-native markdown frontmatter grants `Edit(*)` wildcard access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC523 / MD-GLOB-WILDCARD` | AI-native markdown frontmatter grants `Glob(*)` wildcard access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC524 / MD-GREP-WILDCARD` | AI-native markdown frontmatter grants `Grep(*)` wildcard access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC525 / MD-WEBFETCH-WILDCARD` | AI-native markdown frontmatter grants `WebFetch(*)` wildcard access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC526 / MD-WEBSEARCH-WILDCARD` | AI-native markdown frontmatter grants `WebSearch(*)` wildcard access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC527 / MD-BASH-WILDCARD` | AI-native markdown frontmatter grants `Bash(*)` wildcard access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC528 / CLAUDE-GH-API-DELETE-PERMISSION` | Claude settings permissions allow `Bash(gh api --method DELETE:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC529 / MD-GH-API-DELETE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh api --method DELETE:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC530 / CLAUDE-GH-API-PATCH-PERMISSION` | Claude settings permissions allow `Bash(gh api --method PATCH:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC531 / CLAUDE-GH-API-PUT-PERMISSION` | Claude settings permissions allow `Bash(gh api --method PUT:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC532 / MD-GH-API-PATCH-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh api --method PATCH:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC533 / MD-GH-API-PUT-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh api --method PUT:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC534 / CLAUDE-GH-REPO-DELETE-PERMISSION` | Claude settings permissions allow `Bash(gh repo delete:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC535 / MD-GH-REPO-DELETE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh repo delete:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC536 / CLAUDE-GH-RELEASE-DELETE-PERMISSION` | Claude settings permissions allow `Bash(gh release delete:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC537 / MD-GH-RELEASE-DELETE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh release delete:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC538 / CLAUDE-GH-REPO-EDIT-PERMISSION` | Claude settings permissions allow `Bash(gh repo edit:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC539 / MD-GH-REPO-EDIT-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh repo edit:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC540 / CLAUDE-GH-RELEASE-CREATE-PERMISSION` | Claude settings permissions allow `Bash(gh release create:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC541 / MD-GH-RELEASE-CREATE-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh release create:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC542 / CLAUDE-GH-REPO-TRANSFER-PERMISSION` | Claude settings permissions allow `Bash(gh repo transfer:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC543 / MD-GH-REPO-TRANSFER-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh repo transfer:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC544 / CLAUDE-GH-RELEASE-UPLOAD-PERMISSION` | Claude settings permissions allow `Bash(gh release upload:*)` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC545 / MD-GH-RELEASE-UPLOAD-ALLOWED-TOOLS` | AI-native markdown frontmatter grants `Bash(gh release upload:*)` tool access | `governance` | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` | `governance` |
| `SEC546 / MCP-AUTOAPPROVE-BASH-WILDCARD` | MCP configuration auto-approves blanket shell execution with `autoApprove: ["Bash(*)"]` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC547 / MCP-AUTOAPPROVE-CURL` | MCP configuration auto-approves `Bash(curl:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC548 / MCP-AUTOAPPROVE-WGET` | MCP configuration auto-approves `Bash(wget:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC549 / MCP-AUTOAPPROVE-SUDO` | MCP configuration auto-approves `Bash(sudo:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC550 / MCP-AUTOAPPROVE-RM` | MCP configuration auto-approves `Bash(rm:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC551 / MCP-AUTOAPPROVE-GIT-PUSH` | MCP configuration auto-approves `Bash(git push)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC552 / MCP-AUTOAPPROVE-GH-API-POST` | MCP configuration auto-approves `Bash(gh api --method POST:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC553 / MCP-AUTOAPPROVE-GIT-CHECKOUT` | MCP configuration auto-approves `Bash(git checkout:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC554 / MCP-AUTOAPPROVE-GIT-COMMIT` | MCP configuration auto-approves `Bash(git commit:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC555 / MCP-AUTOAPPROVE-GIT-RESET` | MCP configuration auto-approves `Bash(git reset:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC556 / MCP-AUTOAPPROVE-GIT-CLEAN` | MCP configuration auto-approves `Bash(git clean:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC557 / MCP-AUTOAPPROVE-GH-API-DELETE` | MCP configuration auto-approves `Bash(gh api --method DELETE:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC558 / MCP-AUTOAPPROVE-GH-API-PATCH` | MCP configuration auto-approves `Bash(gh api --method PATCH:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC559 / MCP-AUTOAPPROVE-GH-API-PUT` | MCP configuration auto-approves `Bash(gh api --method PUT:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC560 / MCP-AUTOAPPROVE-GH-ISSUE-CREATE` | MCP configuration auto-approves `Bash(gh issue create:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC561 / MCP-AUTOAPPROVE-GH-REPO-CREATE` | MCP configuration auto-approves `Bash(gh repo create:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC562 / MCP-AUTOAPPROVE-GH-REPO-DELETE` | MCP configuration auto-approves `Bash(gh repo delete:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC563 / MCP-AUTOAPPROVE-GH-REPO-EDIT` | MCP configuration auto-approves `Bash(gh repo edit:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC564 / MCP-AUTOAPPROVE-GH-SECRET-SET` | MCP configuration auto-approves `Bash(gh secret set:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC565 / MCP-AUTOAPPROVE-GH-VARIABLE-SET` | MCP configuration auto-approves `Bash(gh variable set:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC566 / MCP-AUTOAPPROVE-GH-WORKFLOW-RUN` | MCP configuration auto-approves `Bash(gh workflow run:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC567 / MCP-AUTOAPPROVE-READ-WILDCARD` | MCP configuration auto-approves `Read(*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC568 / MCP-AUTOAPPROVE-WRITE-WILDCARD` | MCP configuration auto-approves `Write(*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC569 / MCP-AUTOAPPROVE-EDIT-WILDCARD` | MCP configuration auto-approves `Edit(*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC570 / MCP-AUTOAPPROVE-GLOB-WILDCARD` | MCP configuration auto-approves `Glob(*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC571 / MCP-AUTOAPPROVE-GREP-WILDCARD` | MCP configuration auto-approves `Grep(*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC572 / MCP-AUTOAPPROVE-WEBFETCH-WILDCARD` | MCP configuration auto-approves `WebFetch(*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC573 / MCP-AUTOAPPROVE-WEBSEARCH-WILDCARD` | MCP configuration auto-approves `WebSearch(*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC574 / MCP-AUTOAPPROVE-READ-UNSAFE-PATH` | MCP configuration auto-approves `Read(...)` over an unsafe path through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC575 / MCP-AUTOAPPROVE-WRITE-UNSAFE-PATH` | MCP configuration auto-approves `Write(...)` over an unsafe path through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC576 / MCP-AUTOAPPROVE-EDIT-UNSAFE-PATH` | MCP configuration auto-approves `Edit(...)` over an unsafe path through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC577 / MCP-AUTOAPPROVE-GLOB-UNSAFE-PATH` | MCP configuration auto-approves `Glob(...)` over an unsafe path through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC578 / MCP-AUTOAPPROVE-GREP-UNSAFE-PATH` | MCP configuration auto-approves `Grep(...)` over an unsafe path through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC579 / MCP-AUTOAPPROVE-GH-SECRET-DELETE` | MCP configuration auto-approves `Bash(gh secret delete:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC580 / MCP-AUTOAPPROVE-GH-VARIABLE-DELETE` | MCP configuration auto-approves `Bash(gh variable delete:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC581 / MCP-AUTOAPPROVE-GH-WORKFLOW-DISABLE` | MCP configuration auto-approves `Bash(gh workflow disable:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC582 / MCP-AUTOAPPROVE-GH-REPO-TRANSFER` | MCP configuration auto-approves `Bash(gh repo transfer:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC583 / MCP-AUTOAPPROVE-GH-RELEASE-CREATE` | MCP configuration auto-approves `Bash(gh release create:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC584 / MCP-AUTOAPPROVE-GH-RELEASE-DELETE` | MCP configuration auto-approves `Bash(gh release delete:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC585 / MCP-AUTOAPPROVE-GH-RELEASE-UPLOAD` | MCP configuration auto-approves `Bash(gh release upload:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC586 / MCP-AUTOAPPROVE-NPX` | MCP configuration auto-approves `Bash(npx ...)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC587 / MCP-AUTOAPPROVE-UVX` | MCP configuration auto-approves `Bash(uvx ...)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC588 / MCP-AUTOAPPROVE-NPM-EXEC` | MCP configuration auto-approves `Bash(npm exec ...)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC589 / MCP-AUTOAPPROVE-BUNX` | MCP configuration auto-approves `Bash(bunx ...)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC590 / MCP-AUTOAPPROVE-PNPM-DLX` | MCP configuration auto-approves `Bash(pnpm dlx ...)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC591 / MCP-AUTOAPPROVE-YARN-DLX` | MCP configuration auto-approves `Bash(yarn dlx ...)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC592 / MCP-AUTOAPPROVE-PIPX-RUN` | MCP configuration auto-approves `Bash(pipx run ...)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC593 / MCP-AUTOAPPROVE-PACKAGE-INSTALL` | MCP configuration auto-approves package installation commands through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC594 / MCP-AUTOAPPROVE-GIT-CLONE` | MCP configuration auto-approves `Bash(git clone:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC595 / MCP-AUTOAPPROVE-GIT-FETCH` | MCP configuration auto-approves `Bash(git fetch:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC596 / MCP-AUTOAPPROVE-GIT-LS-REMOTE` | MCP configuration auto-approves `Bash(git ls-remote:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC597 / MCP-AUTOAPPROVE-GIT-ADD` | MCP configuration auto-approves `Bash(git add:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC598 / MCP-AUTOAPPROVE-GIT-CONFIG` | MCP configuration auto-approves `Bash(git config:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC599 / MCP-AUTOAPPROVE-GIT-TAG` | MCP configuration auto-approves `Bash(git tag:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC600 / MCP-AUTOAPPROVE-GIT-BRANCH` | MCP configuration auto-approves `Bash(git branch:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC601 / MCP-AUTOAPPROVE-GH-PR` | MCP configuration auto-approves `Bash(gh pr:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC602 / MCP-AUTOAPPROVE-GIT-STASH` | MCP configuration auto-approves `Bash(git stash:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC603 / MCP-AUTOAPPROVE-GIT-RESTORE` | MCP configuration auto-approves `Bash(git restore:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC604 / MCP-AUTOAPPROVE-GIT-REBASE` | MCP configuration auto-approves `Bash(git rebase:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC605 / MCP-AUTOAPPROVE-GIT-MERGE` | MCP configuration auto-approves `Bash(git merge:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC606 / MCP-AUTOAPPROVE-GIT-CHERRY-PICK` | MCP configuration auto-approves `Bash(git cherry-pick:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC607 / MCP-AUTOAPPROVE-GIT-APPLY` | MCP configuration auto-approves `Bash(git apply:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC608 / MCP-AUTOAPPROVE-GIT-AM` | MCP configuration auto-approves `Bash(git am:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC609 / MCP-AUTOAPPROVE-CRONTAB` | MCP configuration auto-approves `Bash(crontab:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC610 / MCP-AUTOAPPROVE-SYSTEMCTL-ENABLE` | MCP configuration auto-approves `Bash(systemctl enable:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC611 / MCP-AUTOAPPROVE-LAUNCHCTL-LOAD` | MCP configuration auto-approves `Bash(launchctl load:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC612 / MCP-AUTOAPPROVE-LAUNCHCTL-BOOTSTRAP` | MCP configuration auto-approves `Bash(launchctl bootstrap:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC613 / MCP-AUTOAPPROVE-CHMOD` | MCP configuration auto-approves `Bash(chmod:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC614 / MCP-AUTOAPPROVE-CHOWN` | MCP configuration auto-approves `Bash(chown:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC615 / MCP-AUTOAPPROVE-CHGRP` | MCP configuration auto-approves `Bash(chgrp:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC616 / MCP-AUTOAPPROVE-SU` | MCP configuration auto-approves `Bash(su:*)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC617 / MCP-AUTOAPPROVE-WEBFETCH-RAW-GITHUB` | MCP configuration auto-approves `WebFetch(domain:raw.githubusercontent.com)` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC618 / MCP-AUTOAPPROVE-READ` | MCP configuration auto-approves bare `Read` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC619 / MCP-AUTOAPPROVE-WRITE` | MCP configuration auto-approves bare `Write` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC620 / MCP-AUTOAPPROVE-EDIT` | MCP configuration auto-approves bare `Edit` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC621 / MCP-AUTOAPPROVE-GLOB` | MCP configuration auto-approves bare `Glob` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC622 / MCP-AUTOAPPROVE-GREP` | MCP configuration auto-approves bare `Grep` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC623 / MCP-AUTOAPPROVE-WEBFETCH` | MCP configuration auto-approves bare `WebFetch` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC624 / MCP-AUTOAPPROVE-WEBSEARCH` | MCP configuration auto-approves bare `WebSearch` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC625 / MCP-AUTOAPPROVE-BASH` | MCP configuration auto-approves bare `Bash` through `autoApprove` | `governance` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `governance`, `mcp` |
| `SEC626 / CLAUDE-BASH` | Claude settings permissions allow bare `Bash` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC627 / CLAUDE-READ` | Claude settings permissions allow bare `Read` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC628 / CLAUDE-WRITE` | Claude settings permissions allow bare `Write` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC629 / CLAUDE-EDIT` | Claude settings permissions allow bare `Edit` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC630 / CLAUDE-GLOB` | Claude settings permissions allow bare `Glob` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC631 / CLAUDE-GREP` | Claude settings permissions allow bare `Grep` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC632 / CLAUDE-WEBFETCH` | Claude settings permissions allow bare `WebFetch` in a shared committed config | `governance` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `governance`, `claude` |
| `SEC633` | Hook script attempts destructive root deletion | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC634` | Hook script accesses a sensitive system password file | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC635` | Hook script writes to a shell profile startup file | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC636` | Hook script writes to SSH authorized_keys | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC637` | MCP configuration command attempts destructive root deletion | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC638` | MCP configuration command accesses a sensitive system password file | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC639` | MCP configuration command writes to a shell profile startup file | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC640` | MCP configuration command writes to SSH authorized_keys | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC641` | Claude settings command hook attempts destructive root deletion | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC642` | Claude settings command hook accesses a sensitive system password file | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC643` | Claude settings command hook writes to a shell profile startup file | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC644` | Claude settings command hook writes to SSH authorized_keys | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC645` | Plugin hook command attempts destructive root deletion | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC646` | Plugin hook command accesses a sensitive system password file | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC647` | Plugin hook command writes to a shell profile startup file | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC648` | Plugin hook command writes to SSH authorized_keys | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC649` | Hook script manipulates cron persistence | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC650` | Hook script registers a systemd service or unit for persistence | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC651` | Hook script registers a launchd plist for persistence | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC652` | MCP configuration command manipulates cron persistence | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC653` | MCP configuration command registers a systemd service or unit for persistence | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC654` | MCP configuration command registers a launchd plist for persistence | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC655` | Claude settings command hook manipulates cron persistence | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC656` | Claude settings command hook registers a systemd service or unit for persistence | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC657` | Claude settings command hook registers a launchd plist for persistence | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC658` | Plugin hook command manipulates cron persistence | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC659` | Plugin hook command registers a systemd service or unit for persistence | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC660` | Plugin hook command registers a launchd plist for persistence | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC661` | Hook script performs an insecure permission change | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC662` | Hook script manipulates setuid or setgid permissions | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC663` | Hook script manipulates Linux capabilities | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC664` | MCP configuration command performs an insecure permission change | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC665` | MCP configuration command manipulates setuid or setgid permissions | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC666` | MCP configuration command manipulates Linux capabilities | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC667` | Claude settings command hook performs an insecure permission change | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC668` | Claude settings command hook manipulates setuid or setgid permissions | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC669` | Claude settings command hook manipulates Linux capabilities | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC670` | Plugin hook command performs an insecure permission change | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC671` | Plugin hook command manipulates setuid or setgid permissions | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC672` | Plugin hook command manipulates Linux capabilities | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC673` | Hook script posts secret material to a webhook endpoint | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC674` | MCP configuration command appears to send secret material over the network | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC675` | MCP configuration command sends secret material to an insecure http:// endpoint | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC676` | MCP configuration command posts secret material to a webhook endpoint | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC677` | Claude settings command hook appears to send secret material over the network | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC678` | Claude settings command hook sends secret material to an insecure http:// endpoint | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC679` | Claude settings command hook posts secret material to a webhook endpoint | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC680` | Plugin hook command appears to send secret material over the network | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC681` | Plugin hook command sends secret material to an insecure http:// endpoint | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC682` | Plugin hook command posts secret material to a webhook endpoint | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC683` | Hook script transfers a sensitive credential file to a remote destination | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC684` | MCP configuration command transfers a sensitive credential file to a remote destination | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC685` | Claude settings command hook transfers a sensitive credential file to a remote destination | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC686` | Plugin hook command transfers a sensitive credential file to a remote destination | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC687` | Hook script reads local clipboard contents | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC688` | Hook script accesses browser credential or cookie stores | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC689` | MCP configuration command reads local clipboard contents | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC690` | MCP configuration command accesses browser credential or cookie stores | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC691` | Claude settings command hook reads local clipboard contents | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC692` | Claude settings command hook accesses browser credential or cookie stores | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC693` | Plugin hook command reads local clipboard contents | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC694` | Plugin hook command accesses browser credential or cookie stores | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC695` | Hook script exfiltrates clipboard contents over the network | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC696` | Hook script exfiltrates browser credential or cookie store data | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC697` | MCP configuration command exfiltrates clipboard contents over the network | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC698` | MCP configuration command exfiltrates browser credential or cookie store data | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC699` | Claude settings command hook exfiltrates clipboard contents over the network | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC700` | Claude settings command hook exfiltrates browser credential or cookie store data | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC701` | Plugin hook command exfiltrates clipboard contents over the network | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC702` | Plugin hook command exfiltrates browser credential or cookie store data | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC703` | Hook script captures a screenshot or desktop image | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC704` | Hook script captures and exfiltrates a screenshot or desktop image | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC705` | MCP configuration command captures a screenshot or desktop image | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC706` | MCP configuration command captures and exfiltrates a screenshot or desktop image | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC707` | Claude settings command hook captures a screenshot or desktop image | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC708` | Claude settings command hook captures and exfiltrates a screenshot or desktop image | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC709` | Plugin hook command captures a screenshot or desktop image | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC710` | Plugin hook command captures and exfiltrates a screenshot or desktop image | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC711` | Hook script captures a camera image or webcam stream | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC712` | Hook script records microphone or audio input | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC713` | Hook script captures and exfiltrates camera or webcam data | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC714` | Hook script records and exfiltrates microphone or audio input | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC715` | MCP configuration command captures a webcam or camera image | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC716` | MCP configuration command captures microphone audio | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC717` | MCP configuration command captures and exfiltrates webcam or camera data | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC718` | MCP configuration command captures and exfiltrates microphone audio | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC719` | Claude settings command hook captures a webcam or camera image | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC720` | Claude settings command hook captures microphone audio | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC721` | Claude settings command hook captures and exfiltrates webcam or camera data | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC722` | Claude settings command hook captures and exfiltrates microphone audio | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC723` | Plugin hook command captures a webcam or camera image | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC724` | Plugin hook command captures microphone audio | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC725` | Plugin hook command captures and exfiltrates webcam or camera data | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC726` | Plugin hook command captures and exfiltrates microphone audio | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC727` | Hook script captures keystrokes or keyboard input | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC728` | Hook script captures and exfiltrates keystrokes or keyboard input | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC729` | MCP configuration command captures keystrokes or keyboard input | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC730` | MCP configuration command captures and exfiltrates keystrokes or keyboard input | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC731` | Claude settings command hook captures keystrokes or keyboard input | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC732` | Claude settings command hook captures and exfiltrates keystrokes or keyboard input | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC733` | Plugin hook command captures keystrokes or keyboard input | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC734` | Plugin hook command captures and exfiltrates keystrokes or keyboard input | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC735` | Hook script dumps environment variables or shell state | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC736` | Hook script dumps and exfiltrates environment variables or shell state | `threat-review` | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` | `threat-review` |
| `SEC737` | MCP configuration command dumps environment variables or shell state | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC738` | MCP configuration command dumps and exfiltrates environment variables or shell state | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC739` | Claude settings command hook dumps environment variables or shell state | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC740` | Claude settings command hook dumps and exfiltrates environment variables or shell state | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` | `threat-review`, `claude` |
| `SEC741` | Plugin hook command dumps environment variables or shell state | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC742` | Plugin hook command dumps and exfiltrates environment variables or shell state | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `threat-review`, `mcp` |
| `SEC743` | package.json defines a dangerous install-time lifecycle script | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `supply-chain` |
| `SEC744` | package.json installs a dependency from a git or forge shortcut source | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `supply-chain` |
| `SEC745` | package.json uses an unbounded dependency version like * or latest | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `supply-chain` |
| `SEC746` | Dockerfile RUN downloads remote code and executes it | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `dockerfile` | `structural` | `message_only` | `supply-chain` |
| `SEC747` | Dockerfile final stage explicitly runs as root | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `dockerfile` | `structural` | `message_only` | `supply-chain` |
| `SEC748` | Docker Compose service enables privileged container runtime or host namespace access | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `docker-compose` | `structural` | `message_only` | `threat-review` |
| `SEC749` | Dockerfile FROM uses a mutable registry image without a digest pin | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `dockerfile` | `structural` | `message_only` | `supply-chain` |
| `SEC750` | Docker Compose service image uses a mutable registry reference without a digest pin | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `docker-compose` | `structural` | `message_only` | `supply-chain` |
| `SEC751` | Dockerfile FROM uses a latest or implicit-latest image tag | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `dockerfile` | `structural` | `message_only` | `supply-chain` |
| `SEC752` | Docker Compose service image uses a latest or implicit-latest tag | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `docker-compose` | `structural` | `message_only` | `supply-chain` |
| `SEC753` | package.json installs a dependency from a direct archive URL source | `supply-chain` | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` | `supply-chain` |
| `SEC754` | Devcontainer config defines a host-side initializeCommand | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `devcontainer` | `structural` | `message_only` | `threat-review` |
| `SEC755` | Devcontainer config bind-mounts sensitive local host material | `threat-review` | Stable | `stable_gated` | Warn | `per_file` | `devcontainer` | `structural` | `message_only` | `threat-review` |
| `SEC756` | Installed npm dependency version matches an offline vulnerability advisory | `advisory` | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `suggestion` | `advisory` |

## Builtin preset activation model

All shipped rules now participate in the preset model through a deterministic surface-and-tier mapping:

- `recommended`: the quiet practical default for most teams, composed from curated high-signal shipped rules
- `base`: the minimal stable baseline kept for explicit compatibility-focused setups
- `preview`: deeper-review rules that expand coverage beyond the recommended default without becoming the catch-all malicious-behavior bucket
- `threat-review`: explicit malicious, credential-bearing, or spyware-like review rules that stay opt-in because they should not shape the quiet default or the softer preview lane
- `compat`: workspace policy mismatch rules (`SEC401`-`SEC403`) kept as a separate policy lane
- `skills`: markdown-surface rules for the core instruction/skills lane
- `mcp`: all `json`, `tool_json`, and `server_json` surface rules, including preview MCP/config rules
- `claude`: all `claude_settings` surface rules
- `guidance`: advice-oriented guidance checks such as Copilot instruction layout and length guidance
- `governance`: opt-in review rules for shared mutation authority and broad bare tool grants that should stay separate from the main security lane
- `supply-chain`: sidecar supply-chain hardening checks such as GitHub Actions workflow rules
- `advisory`: offline dependency vulnerability checks driven by installed lockfile versions and the active advisory snapshot

Important behavior:

- `strict` is a severity overlay, not a membership preset: when enabled, active security rules are raised through preset policy instead of silently activating new rules by itself.
- if `[presets]` is omitted, `lintai` enables `recommended` by default.
- Dedicated sidecar lanes such as `threat-review`, `compat`, `guidance`, `governance`, `supply-chain`, and `advisory` stay opt-in and are not implied by `base` or `preview`.
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
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `threat-review`, `skills`
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
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `threat-review`, `skills`
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
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `threat-review`, `skills`
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
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `threat-review`, `skills`
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
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `threat-review`, `skills`
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
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit remote download-and-execute behavior in hook shell lines, not prose text.
- Deterministic Signal Basis: HookSignals download-and-execute observation over non-comment hook lines.
- Malicious Corpus: `hook-download-exec`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC202 / HOOK-SECRET-EXFIL` — Hook script appears to exfiltrate secrets through a network call

- Provider: `lintai-ai-security`
- Alias: `HOOK-SECRET-EXFIL`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches secret-bearing network exfil behavior in executable hook lines.
- Deterministic Signal Basis: HookSignals secret exfil observation from network markers plus secret markers on non-comment lines.
- Malicious Corpus: `hook-secret-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC203 / HOOK-PLAIN-HTTP-SECRET-EXFIL` — Hook script sends secret material to an insecure http:// endpoint

- Provider: `lintai-ai-security`
- Alias: `HOOK-PLAIN-HTTP-SECRET-EXFIL`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches insecure HTTP transport on a secret-bearing hook exfil path.
- Deterministic Signal Basis: HookSignals precise http:// span observation gated by concurrent secret exfil markers.
- Malicious Corpus: `hook-plain-http-secret-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC204 / HOOK-TLS-BYPASS` — Hook script disables TLS or certificate verification for a network call

- Provider: `lintai-ai-security`
- Alias: `HOOK-TLS-BYPASS`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit TLS verification bypass tokens in executable hook network context.
- Deterministic Signal Basis: HookSignals TLS-bypass token observation over parsed hook line tokens and network context.
- Malicious Corpus: `hook-tls-bypass`
- Benign Corpus: `cursor-plugin-tls-verified-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC205 / HOOK-STATIC-AUTH` — Hook script embeds static authentication material in a network call

- Provider: `lintai-ai-security`
- Alias: `HOOK-STATIC-AUTH`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches literal static auth material in hook URLs or authorization headers.
- Deterministic Signal Basis: HookSignals userinfo/header literal extraction excluding dynamic references.
- Malicious Corpus: `hook-static-auth-userinfo`
- Benign Corpus: `hook-auth-dynamic-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC206 / HOOK-BASE64-EXEC` — Hook script decodes a base64 payload and executes it

- Provider: `lintai-ai-security`
- Alias: `HOOK-BASE64-EXEC`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit base64 decode-and-execute behavior in executable hook lines.
- Deterministic Signal Basis: HookSignals base64-decode plus exec observation over non-comment hook lines.
- Malicious Corpus: `hook-base64-exec`
- Benign Corpus: `hook-base64-decode-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC301 / MCP-SHELL-WRAPPER` — MCP configuration shells out through sh -c or bash -c

- Provider: `lintai-ai-security`
- Alias: `MCP-SHELL-WRAPPER`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit shell-wrapper command structure in JSON config, whether the shell is the command itself or the first launch argument, and is best reviewed as an overt threat-review signal rather than a softer middle-lane prompt.
- Deterministic Signal Basis: JsonSignals command and args structure observation for sh -c or bash -c wrappers, either through `command` or `args[0]`.
- Malicious Corpus: `mcp-shell-wrapper`, `mcp-shell-wrapper-args0`
- Benign Corpus: `mcp-safe-basic`, `mcp-shell-wrapper-args-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC302 / MCP-PLAIN-HTTP-ENDPOINT` — Configuration contains an insecure http:// endpoint

- Provider: `lintai-ai-security`
- Alias: `MCP-PLAIN-HTTP-ENDPOINT`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit insecure http:// endpoints in configuration values.
- Deterministic Signal Basis: JsonSignals precise http:// endpoint span resolution from parsed JSON location map.
- Malicious Corpus: `mcp-plain-http`
- Benign Corpus: `mcp-trusted-endpoint-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC303 / MCP-CREDENTIAL-ENV-PASSTHROUGH` — MCP configuration passes through credential environment variables

- Provider: `lintai-ai-security`
- Alias: `MCP-CREDENTIAL-ENV-PASSTHROUGH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
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
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit TLS or certificate verification disable flags in configuration.
- Deterministic Signal Basis: JsonSignals boolean and key observation for trust-verification disable settings.
- Malicious Corpus: `mcp-trust-verification-disabled`
- Benign Corpus: `mcp-trust-verified-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC305 / MCP-STATIC-AUTH` — Configuration embeds static authentication material in a connection or auth value

- Provider: `lintai-ai-security`
- Alias: `MCP-STATIC-AUTH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches literal static auth material embedded directly in configuration values.
- Deterministic Signal Basis: JsonSignals literal authorization or userinfo span extraction excluding dynamic placeholders.
- Malicious Corpus: `mcp-static-authorization`
- Benign Corpus: `mcp-authorization-placeholder-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC306 / MCP-HIDDEN-INSTRUCTIONS` — JSON configuration description contains override-style hidden instructions

- Provider: `lintai-ai-security`
- Alias: `MCP-HIDDEN-INSTRUCTIONS`
- Scope: `per_file`
- Surface: `json`
- Detection: `heuristic`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Override-style instructions in config descriptions are useful threat-review signals, but the detector still depends on descriptive-field phrase heuristics in JSON text.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC307 / MCP-SENSITIVE-ENV-REFERENCE` — Configuration forwards sensitive environment variable references

- Provider: `lintai-ai-security`
- Alias: `MCP-SENSITIVE-ENV-REFERENCE`
- Scope: `per_file`
- Surface: `json`
- Detection: `heuristic`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `mcp`
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
- Public Lane: `preview`
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
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches literal secret material committed into env, header, or auth-like JSON fields.
- Deterministic Signal Basis: JsonSignals literal secret observation over env, header, and auth-like keys excluding dynamic placeholders.
- Malicious Corpus: `mcp-literal-secret-config`
- Benign Corpus: `mcp-secret-placeholder-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC310 / MCP-METADATA-HOST-LITERAL` — Configuration endpoint targets a metadata or private-network host literal

- Provider: `lintai-ai-security`
- Alias: `MCP-METADATA-HOST-LITERAL`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit metadata-service or private-network host literals in endpoint-like configuration values and is best reviewed as an overt threat-review signal rather than a softer middle-lane prompt.
- Deterministic Signal Basis: JsonSignals endpoint-host extraction over URL-like endpoint fields with metadata/private-host classification.
- Malicious Corpus: `mcp-metadata-host-literal`
- Benign Corpus: `mcp-public-endpoint-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC311 / PLUGIN-UNSAFE-PATH` — Cursor plugin manifest contains an unsafe absolute or parent-traversing path

- Provider: `lintai-ai-security`
- Alias: `PLUGIN-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `compat`, `mcp`
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
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `skills`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit committed private-key PEM markers inside agent markdown surfaces.
- Deterministic Signal Basis: MarkdownSignals private-key marker observation across parsed markdown regions excluding placeholder examples.
- Malicious Corpus: `skill-private-key-pem`
- Benign Corpus: `skill-public-key-pem-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC313 / MD-PIPE-SHELL` — Fenced shell example pipes remote content directly into a shell

- Provider: `lintai-ai-security`
- Alias: `MD-PIPE-SHELL`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `threat-review`, `skills`
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
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `compat`, `mcp`
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
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `compat`, `mcp`
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
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `compat`, `mcp`
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
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `compat`, `mcp`
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
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `compat`, `mcp`
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
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks MCP registry remotes[] URLs for insecure HTTP and non-public host literals without inspecting local package transport URLs.
- Deterministic Signal Basis: ServerJsonSignals remotes[] URL analysis limited to streamable-http and sse entries.
- Malicious Corpus: `server-json-insecure-remote-url`
- Benign Corpus: `server-json-loopback-package-transport-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC320 / SERVER-UNDEFINED-URL-VAR` — server.json remotes URL references an undefined template variable

- Provider: `lintai-ai-security`
- Alias: `SERVER-UNDEFINED-URL-VAR`
- Scope: `per_file`
- Surface: `server_json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `compat`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks server.json remotes[] URL templates for placeholder/variables contract mismatches on the same remote entry.
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
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks remotes[].headers[] auth-like values for literal bearer/basic material or literal API key style values.
- Deterministic Signal Basis: ServerJsonSignals inspects remotes[].headers[] auth-like names and value literals without looking at packages[].transport.
- Malicious Corpus: `server-json-literal-auth-header`
- Benign Corpus: `server-json-auth-header-placeholder-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC322 / SERVER-UNDEFINED-HEADER-VAR` — server.json remotes header value references an undefined template variable

- Provider: `lintai-ai-security`
- Alias: `SERVER-UNDEFINED-HEADER-VAR`
- Scope: `per_file`
- Surface: `server_json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `compat`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks auth-like remotes[].headers[].value placeholders against variables defined on the same header object so registry consumers do not ship broken header templates.
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
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `compat`, `mcp`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Registry producers do not all enforce the same explicit secret-marker contract, so this remains a compatibility review signal until wider producer evidence converges.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC324 / GHA-UNPINNED-ACTION` — GitHub Actions workflow uses a third-party action that is not pinned to a full commit SHA

- Provider: `lintai-ai-security`
- Alias: `GHA-UNPINNED-ACTION`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
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
- Public Lane: `supply-chain`
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
- Public Lane: `supply-chain`
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
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC327 / GHA-WRITE-ALL-PERMISSIONS` — GitHub Actions workflow grants GITHUB_TOKEN write-all permissions

- Provider: `lintai-ai-security`
- Alias: `GHA-WRITE-ALL-PERMISSIONS`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
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
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC328 / GHA-WRITE-CAPABLE-THIRD-PARTY-ACTION` — GitHub Actions workflow combines explicit write-capable permissions with a third-party action

- Provider: `lintai-ai-security`
- Alias: `GHA-WRITE-CAPABLE-THIRD-PARTY-ACTION`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
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
- Public Lane: `recommended`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `recommended`, `base`, `mcp`
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
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config command and args values for explicit curl|shell or wget|shell execution chains.
- Deterministic Signal Basis: JsonSignals command/args string analysis over ArtifactKind::McpConfig objects, limited to explicit download-pipe-shell patterns.
- Malicious Corpus: `mcp-inline-download-exec`
- Benign Corpus: `mcp-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC331 / MCP-TLS-BYPASS` — MCP configuration command disables TLS verification in a network-capable execution path

- Provider: `lintai-ai-security`
- Alias: `MCP-TLS-BYPASS`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config command and args values for explicit TLS-bypass tokens in a network-capable execution context.
- Deterministic Signal Basis: JsonSignals command/args string analysis over ArtifactKind::McpConfig objects gated by network markers plus TLS-bypass tokens.
- Malicious Corpus: `mcp-command-tls-bypass`
- Benign Corpus: `mcp-network-tls-verified-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC335 / MD-METADATA-SERVICE-ACCESS` — AI-native markdown contains a direct cloud metadata-service access example

- Provider: `lintai-ai-security`
- Alias: `MD-METADATA-SERVICE-ACCESS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `threat-review`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Metadata-service access examples are strong threat-review signals, but labs and cloud-security training content can still reference them legitimately.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC336 / MCP-BROAD-ENVFILE` — Repo-local MCP client config loads a broad dotenv-style envFile

- Provider: `lintai-ai-security`
- Alias: `MCP-BROAD-ENVFILE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `mcp`
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
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config Docker launch paths for image references that are not pinned by digest, including tag-only refs such as :latest or :1.2.3.
- Deterministic Signal Basis: JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to command == docker plus args beginning with run.
- Malicious Corpus: `mcp-docker-unpinned-image`
- Benign Corpus: `mcp-docker-digest-pinned-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC338 / MCP-DOCKER-SENSITIVE-MOUNT` — MCP configuration launches Docker with a bind mount of sensitive host material

- Provider: `lintai-ai-security`
- Alias: `MCP-DOCKER-SENSITIVE-MOUNT`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config Docker launch paths for bind mounts of sensitive host sources such as docker.sock, SSH material, cloud credentials, and kubeconfig directories.
- Deterministic Signal Basis: JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to -v/--volume and --mount bind forms with sensitive host-path markers.
- Malicious Corpus: `mcp-docker-sensitive-mount`
- Benign Corpus: `mcp-docker-named-volume-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC339 / MCP-DOCKER-HOST-ESCAPE` — MCP configuration launches Docker with a host-escape or privileged runtime flag

- Provider: `lintai-ai-security`
- Alias: `MCP-DOCKER-HOST-ESCAPE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config Docker launch paths for privileged or host-escape runtime flags such as --privileged, --network host, --pid host, and --ipc host.
- Deterministic Signal Basis: JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to explicit privileged and host namespace flags.
- Malicious Corpus: `mcp-docker-host-escape`
- Benign Corpus: `mcp-docker-safe-run`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC340 / CLAUDE-HOOK-MUTABLE-LAUNCHER` — Claude settings command hook uses a mutable package launcher

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HOOK-MUTABLE-LAUNCHER`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `recommended`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `recommended`, `base`, `claude`
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
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit curl|shell or wget|shell execution chains.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command, limited to explicit download-pipe-shell patterns.
- Malicious Corpus: `claude-settings-inline-download-exec`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC342 / CLAUDE-HOOK-TLS-BYPASS` — Claude settings command hook disables TLS verification in a network-capable execution path

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HOOK-TLS-BYPASS`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit TLS-bypass tokens in a network-capable execution context.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command, gated by network markers plus TLS-bypass tokens.
- Malicious Corpus: `claude-settings-command-tls-bypass`
- Benign Corpus: `claude-settings-network-tls-verified-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC343 / PLUGIN-HOOK-MUTABLE-LAUNCHER` — Plugin hook command uses a mutable package launcher

- Provider: `lintai-ai-security`
- Alias: `PLUGIN-HOOK-MUTABLE-LAUNCHER`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for mutable package launchers such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects limited to actual hook command values.
- Malicious Corpus: `plugin-hook-command-mutable-launcher`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC344 / PLUGIN-HOOK-DOWNLOAD-EXEC` — Plugin hook command downloads remote content and pipes it into a shell

- Provider: `lintai-ai-security`
- Alias: `PLUGIN-HOOK-DOWNLOAD-EXEC`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit curl|shell or wget|shell execution chains.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects, limited to explicit download-pipe-shell patterns.
- Malicious Corpus: `plugin-hook-command-inline-download-exec`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC345 / PLUGIN-HOOK-TLS-BYPASS` — Plugin hook command disables TLS verification in a network-capable execution path

- Provider: `lintai-ai-security`
- Alias: `PLUGIN-HOOK-TLS-BYPASS`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit TLS-bypass tokens in a network-capable execution context.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects gated by network markers plus TLS-bypass tokens.
- Malicious Corpus: `plugin-hook-command-tls-bypass`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC346 / MCP-DOCKER-PULL-ALWAYS` — MCP configuration forces Docker to refresh from a mutable registry source

- Provider: `lintai-ai-security`
- Alias: `MCP-DOCKER-PULL-ALWAYS`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config Docker launch paths for explicit --pull always refresh policies that force a mutable registry fetch at runtime.
- Deterministic Signal Basis: JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to explicit --pull=always or --pull always forms.
- Malicious Corpus: `gemini-mcp-docker-pull-always`
- Benign Corpus: `gemini-mcp-docker-digest-pinned-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC347 / MD-MCP-MUTABLE-LAUNCHER` — AI-native markdown example launches MCP through a mutable package runner

- Provider: `lintai-ai-security`
- Alias: `MD-MCP-MUTABLE-LAUNCHER`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Mutable MCP launcher examples in markdown can be legitimate setup guidance, so the first release stays in the explicit supply-chain lane while broader field validation continues.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC348 / MD-DOCKER-MUTABLE-IMAGE` — AI-native markdown Docker example uses a mutable registry image

- Provider: `lintai-ai-security`
- Alias: `MD-DOCKER-MUTABLE-IMAGE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Mutable Docker image examples in markdown can be legitimate setup guidance, so the first release stays in the explicit supply-chain lane rather than a stronger default posture.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC349 / MD-DOCKER-HOST-ESCAPE` — AI-native markdown Docker example uses a host-escape or privileged runtime pattern

- Provider: `lintai-ai-security`
- Alias: `MD-DOCKER-HOST-ESCAPE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `threat-review`, `skills`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Docker host-escape examples are strong threat-review signals, but infra-debugging and lab material can still document them intentionally.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC350 / MD-UNTRUSTED-INSTRUCTION-PROMOTION` — Instruction markdown promotes untrusted external content to developer/system-level instructions

- Provider: `lintai-ai-security`
- Alias: `MD-UNTRUSTED-INSTRUCTION-PROMOTION`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `threat-review`, `skills`
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
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `threat-review`, `skills`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for exact bare `Bash` grants that expose unconstrained shell authority as shared default policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for bare `Bash` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-unscoped-bash-allowed-tools`
- Benign Corpus: `skill-scoped-bash-allowed-tools-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC353 / COPILOT-4K` — GitHub Copilot instruction markdown exceeds the 4000-character guidance limit

- Provider: `lintai-ai-security`
- Alias: `COPILOT-4K`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `guidance`
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
- Public Lane: `guidance`
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
- Public Lane: `guidance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
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
- Public Lane: `guidance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
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
- Public Lane: `guidance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
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
- Public Lane: `guidance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
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
- Public Lane: `guidance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
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
- Public Lane: `guidance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
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
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `compat`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for omission of a top-level `$schema` reference.
- Deterministic Signal Basis: ClaudeSettingsSignals exact top-level `$schema` presence detection in parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-missing-schema`
- Benign Corpus: `claude-settings-schema-present-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC362 / CLAUDE-BASH-WILDCARD` — Claude settings permissions allow `Bash(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-BASH-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for explicit wildcard `Bash(*)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-bash-wildcard`
- Benign Corpus: `claude-settings-bash-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC363 / CLAUDE-HOME-HOOK-PATH` — Claude settings hook command uses a home-directory path in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HOME-HOOK-PATH`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `compat`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for hook commands rooted in the home directory.
- Deterministic Signal Basis: ClaudeSettingsSignals exact command-path analysis for home-directory rooted hook commands in parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-home-directory-hook-path`
- Benign Corpus: `claude-settings-home-directory-safe-project-scoped`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC364 / CLAUDE-BYPASS-PERMISSIONS` — Claude settings set `permissions.defaultMode` to `bypassPermissions` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-BYPASS-PERMISSIONS`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for explicit `permissions.defaultMode = bypassPermissions`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `permissions.defaultMode = bypassPermissions` on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-bypass-permissions`
- Benign Corpus: `claude-settings-bypass-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC365 / CLAUDE-HTTP-HOOK-URL` — Claude settings allow non-HTTPS HTTP hook URLs in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HTTP-HOOK-URL`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `supply-chain`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for non-HTTPS `allowedHttpHookUrls` entries.
- Deterministic Signal Basis: ClaudeSettingsSignals exact URL-scheme analysis over `allowedHttpHookUrls` entries in parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-http-hook-url`
- Benign Corpus: `claude-settings-http-hook-loopback-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC366 / CLAUDE-HTTP-HOOK-HOST` — Claude settings allow dangerous host literals in `allowedHttpHookUrls`

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HTTP-HOOK-HOST`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `supply-chain`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for dangerous host literals in `allowedHttpHookUrls`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact host analysis over `allowedHttpHookUrls` entries in parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-dangerous-http-hook-host`
- Benign Corpus: `claude-settings-http-hook-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC367 / CLAUDE-WEBFETCH-WILDCARD` — Claude settings permissions allow `WebFetch(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WEBFETCH-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for explicit wildcard `WebFetch(*)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `WebFetch(*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-webfetch-wildcard`
- Benign Corpus: `claude-settings-webfetch-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC368 / CLAUDE-ABS-HOOK-PATH` — Claude settings hook command uses a repo-external absolute path in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-ABS-HOOK-PATH`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `compat`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for repo-external absolute hook command paths.
- Deterministic Signal Basis: ClaudeSettingsSignals exact command-path analysis for repo-external absolute hook commands in parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-repo-external-absolute-hook-path`
- Benign Corpus: `claude-settings-repo-external-absolute-hook-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC369 / CLAUDE-WRITE-WILDCARD` — Claude settings permissions allow `Write(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WRITE-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for explicit wildcard `Write(*)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Write(*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-write-wildcard`
- Benign Corpus: `claude-settings-write-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC370 / COPILOT-PATH-SUFFIX` — Path-specific GitHub Copilot instruction markdown under `.github/instructions/` uses the wrong file suffix

- Provider: `lintai-ai-security`
- Alias: `COPILOT-PATH-SUFFIX`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `guidance`
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
- Public Lane: `guidance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for explicit wildcard `Read(*)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Read(*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-read-wildcard`
- Benign Corpus: `claude-settings-read-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC373 / CLAUDE-EDIT-WILDCARD` — Claude settings permissions allow `Edit(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-EDIT-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for explicit wildcard `Edit(*)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Edit(*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-edit-wildcard`
- Benign Corpus: `claude-settings-edit-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC374 / CLAUDE-WEBSEARCH-WILDCARD` — Claude settings permissions allow `WebSearch(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WEBSEARCH-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for explicit wildcard `WebSearch(*)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `WebSearch(*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-websearch-wildcard`
- Benign Corpus: `claude-settings-websearch-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC375 / CLAUDE-GLOB-WILDCARD` — Claude settings permissions allow `Glob(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GLOB-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for explicit wildcard `Glob(*)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Glob(*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-glob-wildcard`
- Benign Corpus: `claude-settings-glob-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC376 / CLAUDE-GREP-WILDCARD` — Claude settings permissions allow `Grep(*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GREP-WILDCARD`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for explicit wildcard `Grep(*)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Grep(*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-grep-wildcard`
- Benign Corpus: `claude-settings-grep-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC377 / COPILOT-APPLYTO-GLOB` — Path-specific GitHub Copilot instruction markdown has an invalid `applyTo` glob pattern

- Provider: `lintai-ai-security`
- Alias: `COPILOT-APPLYTO-GLOB`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `guidance`
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
- Public Lane: `guidance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
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
- Public Lane: `guidance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
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
- Public Lane: `guidance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
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
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `compat`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact omission of `timeout` on command hooks.
- Deterministic Signal Basis: ClaudeSettingsSignals exact command-hook timeout presence detection in parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-missing-hook-timeout`
- Benign Corpus: `claude-settings-hook-timeout-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC382 / CLAUDE-HOOK-MATCHER-EVENT` — Claude settings should not use `matcher` on unsupported hook events

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HOOK-MATCHER-EVENT`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `compat`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact use of `matcher` on unsupported hook events.
- Deterministic Signal Basis: ClaudeSettingsSignals exact hook-event and matcher presence detection in parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-matcher-on-stop-event`
- Benign Corpus: `claude-settings-matcher-pretooluse-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC383 / CLAUDE-HOOK-MISSING-MATCHER` — Claude settings should set `matcher` on matcher-capable hook events

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-HOOK-MISSING-MATCHER`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `compat`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact omission of `matcher` on matcher-capable hook events.
- Deterministic Signal Basis: ClaudeSettingsSignals exact hook-event and matcher absence detection in parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-missing-required-matcher`
- Benign Corpus: `claude-settings-required-matcher-present-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC384 / CLAUDE-WEBSEARCH-UNSCOPED` — Claude settings permissions allow bare `WebSearch` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WEBSEARCH-UNSCOPED`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for bare `WebSearch` grants without a reviewed scope.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for bare `WebSearch` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-unscoped-websearch`
- Benign Corpus: `claude-settings-websearch-scoped-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC385 / CLAUDE-GIT-PUSH-PERMISSION` — Claude settings permissions allow `Bash(git push)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-PUSH-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git push)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git push)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-git-push-permission`
- Benign Corpus: `claude-settings-git-push-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC386 / CLAUDE-GIT-CHECKOUT-PERMISSION` — Claude settings permissions allow `Bash(git checkout:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-CHECKOUT-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git checkout:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git checkout:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-git-checkout-permission`
- Benign Corpus: `claude-settings-git-checkout-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC387 / CLAUDE-GIT-COMMIT-PERMISSION` — Claude settings permissions allow `Bash(git commit:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-COMMIT-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git commit:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git commit:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-git-commit-permission`
- Benign Corpus: `claude-settings-git-commit-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC388 / CLAUDE-GIT-STASH-PERMISSION` — Claude settings permissions allow `Bash(git stash:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-STASH-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git stash:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git stash:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-git-stash-permission`
- Benign Corpus: `claude-settings-git-stash-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC389 / MD-WEBSEARCH-UNSCOPED` — AI-native markdown frontmatter grants bare `WebSearch` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-WEBSEARCH-UNSCOPED`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for bare WebSearch grants that omit a reviewed search scope.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for bare `WebSearch` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-risky-frontmatter-tool-grants`
- Benign Corpus: `skill-reviewed-frontmatter-tool-grants-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC390 / MD-GIT-PUSH-PERMISSION` — AI-native markdown frontmatter grants `Bash(git push)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-PUSH-PERMISSION`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
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
- Public Lane: `governance`
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
- Public Lane: `governance`
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
- Public Lane: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(npx ...)` mutable package-runner authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(npx ...)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-npx-permission`
- Benign Corpus: `claude-settings-npx-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC400 / CLAUDE-ENABLED-MCPJSON-SERVERS` — Claude settings enable `enabledMcpjsonServers` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-ENABLED-MCPJSON-SERVERS`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `enabledMcpjsonServers` enablement.
- Deterministic Signal Basis: ClaudeSettingsSignals exact non-empty `enabledMcpjsonServers` detection in parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-enabled-mcpjson-servers`
- Benign Corpus: `claude-settings-empty-enabled-mcpjson-servers-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC404 / MD-WEBFETCH-UNSCOPED` — AI-native markdown frontmatter grants bare `WebFetch` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-WEBFETCH-UNSCOPED`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for exact bare `WebFetch` grants that expose unconstrained remote fetch authority as shared default policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for bare `WebFetch` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-unscoped-webfetch-allowed-tools`
- Benign Corpus: `skill-scoped-webfetch-allowed-tools-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC405 / CLAUDE-PACKAGE-INSTALL-PERMISSION` — Claude settings permissions allow package installation commands in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-PACKAGE-INSTALL-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for broad package installation authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string-family detection for package installation permissions such as `Bash(pip install)` or `Bash(npm install)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-package-install-permission`
- Benign Corpus: `claude-settings-bash-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC406 / CLAUDE-GIT-ADD-PERMISSION` — Claude settings permissions allow `Bash(git add:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-ADD-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git add:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git add:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-git-add-permission`
- Benign Corpus: `claude-settings-git-add-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC407 / CLAUDE-GIT-CLONE-PERMISSION` — Claude settings permissions allow `Bash(git clone:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-CLONE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git clone:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git clone:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-git-clone-permission`
- Benign Corpus: `claude-settings-git-clone-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC408 / CLAUDE-GH-PR-PERMISSION` — Claude settings permissions allow `Bash(gh pr:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-PR-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(gh pr:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(gh pr:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-gh-pr-permission`
- Benign Corpus: `claude-settings-gh-pr-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC409 / CLAUDE-GIT-FETCH-PERMISSION` — Claude settings permissions allow `Bash(git fetch:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-FETCH-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git fetch:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git fetch:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-git-fetch-permission`
- Benign Corpus: `claude-settings-git-fetch-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC410 / CLAUDE-GIT-LS-REMOTE-PERMISSION` — Claude settings permissions allow `Bash(git ls-remote:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-LS-REMOTE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for wildcard remote repository inspection grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(git ls-remote:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-git-ls-remote-permission`
- Benign Corpus: `claude-settings-git-ls-remote-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC411 / CLAUDE-CURL-PERMISSION` — Claude settings permissions allow `Bash(curl:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-CURL-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
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
- Public Lane: `guidance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `guidance`
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
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip install` examples that pull directly from mutable git+https sources without commit pinning.
- Deterministic Signal Basis: MarkdownSignals exact `pip install` plus `git+https://` token analysis with commit-pin detection inside parsed markdown regions.
- Malicious Corpus: `claude-unpinned-pip-git-install`
- Benign Corpus: `claude-unpinned-pip-git-install-commit-pinned-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC418 / CLAUDE-WEBFETCH-RAW-GITHUB` — Claude settings permissions allow `WebFetch(domain:raw.githubusercontent.com)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WEBFETCH-RAW-GITHUB`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for explicit wildcard curl grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(curl:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-curl-allowed-tools`
- Benign Corpus: `skill-curl-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC420 / MD-WGET-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(wget:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-WGET-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for explicit wildcard wget grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(wget:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-wget-allowed-tools`
- Benign Corpus: `skill-wget-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC421 / MD-GIT-CLONE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git clone:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-CLONE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for wildcard git clone grants in shared allowed-tools policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(git clone:*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-git-clone-allowed-tools`
- Benign Corpus: `skill-git-clone-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC422 / MCP-COMMAND-SUDO` — MCP configuration launches the server through `sudo`

- Provider: `lintai-ai-security`
- Alias: `MCP-COMMAND-SUDO`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact MCP server launch paths that run under `sudo`.
- Deterministic Signal Basis: JsonSignals exact string detection for `command: "sudo"` on parsed MCP configuration objects.
- Malicious Corpus: `mcp-command-sudo`
- Benign Corpus: `mcp-command-non-sudo-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC423 / MD-READ-UNSCOPED` — AI-native markdown frontmatter grants bare `Read` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-READ-UNSCOPED`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact MCP server launch paths that pass `sudo` as the first argv element.
- Deterministic Signal Basis: JsonSignals exact string detection for `args[0] == "sudo"` on parsed MCP configuration objects.
- Malicious Corpus: `mcp-args-sudo`
- Benign Corpus: `mcp-args-non-sudo-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC447 / MD-PACKAGE-INSTALL-ALLOWED-TOOLS` — AI-native markdown frontmatter grants package installation authority

- Provider: `lintai-ai-security`
- Alias: `MD-PACKAGE-INSTALL-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip install` examples that disable host trust checks with `--trusted-host`.
- Deterministic Signal Basis: MarkdownSignals exact `pip install` token analysis with `--trusted-host` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-trusted-host`
- Benign Corpus: `skill-pip-index-url-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC449 / MD-PIP-HTTP-INDEX` — AI-native markdown installs Python packages from an insecure `http://` package index

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-HTTP-INDEX`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip install` examples that point package index resolution at `http://` sources.
- Deterministic Signal Basis: MarkdownSignals exact `pip install` token analysis with `--index-url http://` or `--extra-index-url http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-http-index`
- Benign Corpus: `skill-pip-https-index-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC450 / MD-NPM-HTTP-REGISTRY` — AI-native markdown installs JavaScript packages from an insecure `http://` registry

- Provider: `lintai-ai-security`
- Alias: `MD-NPM-HTTP-REGISTRY`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `npm`, `pnpm`, `yarn`, and `bun` install examples that point dependency resolution at `http://` registries.
- Deterministic Signal Basis: MarkdownSignals exact `npm install`, `npm i`, `pnpm add/install`, `yarn add`, or `bun add` token analysis with `--registry http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-npm-http-registry`
- Benign Corpus: `skill-npm-https-registry-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC451 / MD-CARGO-HTTP-GIT-INSTALL` — AI-native markdown installs Rust packages from an insecure `http://` git source

- Provider: `lintai-ai-security`
- Alias: `MD-CARGO-HTTP-GIT-INSTALL`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `cargo install` examples that fetch a crate directly from an `http://` git source.
- Deterministic Signal Basis: MarkdownSignals exact `cargo install` token analysis with `--git http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-cargo-http-git-install`
- Benign Corpus: `skill-cargo-https-git-install-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC452 / MD-CARGO-HTTP-INDEX` — AI-native markdown installs Rust packages from an insecure `http://` index

- Provider: `lintai-ai-security`
- Alias: `MD-CARGO-HTTP-INDEX`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `cargo install` examples that resolve crates through an `http://` index.
- Deterministic Signal Basis: MarkdownSignals exact `cargo install` token analysis with `--index http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-cargo-http-index`
- Benign Corpus: `skill-cargo-https-index-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC453 / MD-PIP-HTTP-SOURCE` — AI-native markdown installs Python packages from an insecure direct `http://` source

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-HTTP-SOURCE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip install` examples that fetch a direct package source over `http://`.
- Deterministic Signal Basis: MarkdownSignals exact `pip install` token analysis with direct `http://` source detection inside parsed markdown regions, excluding `--index-url` and `--extra-index-url` forms already covered by SEC449.
- Malicious Corpus: `skill-pip-http-source`
- Benign Corpus: `skill-pip-https-source-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC454 / MD-NPM-HTTP-SOURCE` — AI-native markdown installs JavaScript packages from an insecure direct `http://` source

- Provider: `lintai-ai-security`
- Alias: `MD-NPM-HTTP-SOURCE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `npm`, `pnpm`, `yarn`, and `bun` install examples that fetch a direct package source over `http://`.
- Deterministic Signal Basis: MarkdownSignals exact `npm install`, `npm i`, `pnpm add/install`, `yarn add`, or `bun add` token analysis with direct `http://` source detection inside parsed markdown regions, excluding `--registry http://` forms already covered by SEC450.
- Malicious Corpus: `skill-npm-http-source`
- Benign Corpus: `skill-npm-https-source-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC455 / MD-PIP-HTTP-GIT-INSTALL` — AI-native markdown installs Python packages from an insecure `git+http://` source

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-HTTP-GIT-INSTALL`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip install` examples that fetch Python packages from an insecure `git+http://` source.
- Deterministic Signal Basis: MarkdownSignals exact `pip install` token analysis with `git+http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-http-git-install`
- Benign Corpus: `skill-pip-https-git-install-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC456 / MD-PIP-HTTP-FIND-LINKS` — AI-native markdown installs Python packages with insecure `http://` find-links

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-HTTP-FIND-LINKS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip install` examples that point package discovery at `http://` find-links sources.
- Deterministic Signal Basis: MarkdownSignals exact `pip install` token analysis with `--find-links http://`, `--find-links=http://`, or `-f http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-http-find-links`
- Benign Corpus: `skill-pip-https-find-links-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC457 / MD-JS-PACKAGE-STRICT-SSL-FALSE` — AI-native markdown disables strict SSL verification for JavaScript package manager config

- Provider: `lintai-ai-security`
- Alias: `MD-JS-PACKAGE-STRICT-SSL-FALSE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for JavaScript package-manager config commands that explicitly disable strict SSL verification.
- Deterministic Signal Basis: MarkdownSignals exact `npm config set`, `pnpm config set`, or `yarn config set` token analysis with `strict-ssl false` or `strict-ssl=false` detection inside parsed markdown regions.
- Malicious Corpus: `skill-js-package-strict-ssl-false`
- Benign Corpus: `skill-js-package-strict-ssl-true-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC458 / MD-PIP-CONFIG-HTTP-INDEX` — AI-native markdown configures Python package resolution with an insecure `http://` package index

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-CONFIG-HTTP-INDEX`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip config set` commands that point package index configuration at `http://` sources.
- Deterministic Signal Basis: MarkdownSignals exact `pip config set`, `pip3 config set`, or `python -m pip config set` token analysis with `global.index-url http://` or `global.extra-index-url http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-config-http-index`
- Benign Corpus: `skill-pip-config-https-index-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC459 / MD-JS-PACKAGE-CONFIG-HTTP-REGISTRY` — AI-native markdown configures a JavaScript package manager with an insecure `http://` registry

- Provider: `lintai-ai-security`
- Alias: `MD-JS-PACKAGE-CONFIG-HTTP-REGISTRY`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for JavaScript package-manager config commands that point registry configuration at `http://` sources.
- Deterministic Signal Basis: MarkdownSignals exact `npm config set`, `pnpm config set`, or `yarn config set` token analysis with `registry http://` or `registry=http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-js-package-config-http-registry`
- Benign Corpus: `skill-js-package-config-https-registry-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC460 / MD-PIP-CONFIG-HTTP-FIND-LINKS` — AI-native markdown configures Python package discovery with insecure `http://` find-links

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-CONFIG-HTTP-FIND-LINKS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip config set` commands that point package discovery configuration at `http://` find-links sources.
- Deterministic Signal Basis: MarkdownSignals exact `pip config set`, `pip3 config set`, or `python -m pip config set` token analysis with `global.find-links http://` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-config-http-find-links`
- Benign Corpus: `skill-pip-config-https-find-links-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC461 / MD-PIP-CONFIG-TRUSTED-HOST` — AI-native markdown configures Python package resolution with `trusted-host`

- Provider: `lintai-ai-security`
- Alias: `MD-PIP-CONFIG-TRUSTED-HOST`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `pip config set` commands that configure trusted-host bypass behavior.
- Deterministic Signal Basis: MarkdownSignals exact `pip config set`, `pip3 config set`, or `python -m pip config set` token analysis with `global.trusted-host` detection inside parsed markdown regions.
- Malicious Corpus: `skill-pip-config-trusted-host`
- Benign Corpus: `skill-pip-config-unrelated-key-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC462 / MD-NETWORK-TLS-BYPASS` — AI-native markdown disables TLS verification for a network-capable command

- Provider: `lintai-ai-security`
- Alias: `MD-NETWORK-TLS-BYPASS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for exact network-command examples that disable TLS verification, including PowerShell certificate-bypass forms.
- Deterministic Signal Basis: MarkdownSignals exact command-token analysis with `--insecure`, `-k`, `--no-check-certificate`, `-SkipCertificateCheck`, or `NODE_TLS_REJECT_UNAUTHORIZED=0` detection inside parsed markdown regions, with safety-guidance suppression.
- Malicious Corpus: `skill-markdown-network-tls-bypass`, `skill-markdown-network-tls-bypass-powershell`
- Benign Corpus: `skill-markdown-network-tls-bypass-warning-safe`, `skill-markdown-network-tls-bypass-powershell-warning-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC463 / MD-SUDO-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(sudo:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-SUDO-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `git clone` examples that fetch repositories directly from an insecure `http://` source.
- Deterministic Signal Basis: MarkdownSignals exact `git clone` token analysis with direct `http://` source detection inside parsed markdown regions.
- Malicious Corpus: `skill-git-http-clone`
- Benign Corpus: `skill-git-https-clone-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC465 / MD-GIT-HTTP-REMOTE` — AI-native markdown configures a Git remote with an insecure `http://` source

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-HTTP-REMOTE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for `git remote add` examples that configure a repository remote through an insecure `http://` source.
- Deterministic Signal Basis: MarkdownSignals exact `git remote add` token analysis with direct `http://` source detection inside parsed markdown regions.
- Malicious Corpus: `skill-git-http-remote`
- Benign Corpus: `skill-git-https-remote-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC466 / MD-RM-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(rm:*)` authority

- Provider: `lintai-ai-security`
- Alias: `MD-RM-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
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
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for exact `git config` examples that disable Git TLS verification through `http.sslVerify false`.
- Deterministic Signal Basis: MarkdownSignals exact `git config` token analysis with `http.sslVerify false` or `http.sslVerify=false` detection inside parsed markdown regions, excluding safety-warning phrasing.
- Malicious Corpus: `skill-git-sslverify-false`
- Benign Corpus: `skill-git-sslverify-true-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC472 / MD-GIT-SSL-NO-VERIFY` — AI-native markdown disables Git TLS verification with `GIT_SSL_NO_VERIFY`

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-SSL-NO-VERIFY`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for exact Git command examples that disable TLS verification through `GIT_SSL_NO_VERIFY`.
- Deterministic Signal Basis: MarkdownSignals exact `GIT_SSL_NO_VERIFY=1` or `GIT_SSL_NO_VERIFY=true` token analysis when a Git command appears in the same parsed markdown region, excluding safety-warning phrasing.
- Malicious Corpus: `skill-git-ssl-no-verify`
- Benign Corpus: `skill-git-ssl-no-verify-disabled-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC473 / MD-GIT-INLINE-SSLVERIFY-FALSE` — AI-native markdown disables Git TLS verification with `git -c http.sslVerify=false`

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-INLINE-SSLVERIFY-FALSE`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown for exact `git -c` examples that disable Git TLS verification inline through `http.sslVerify=false`.
- Deterministic Signal Basis: MarkdownSignals exact `git -c http.sslVerify=false` token analysis inside parsed markdown regions, excluding safety-warning phrasing.
- Malicious Corpus: `skill-git-inline-sslverify-false`
- Benign Corpus: `skill-git-inline-sslverify-true-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC474 / MD-GH-PR-PERMISSION` — AI-native markdown frontmatter grants `Bash(gh pr:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-PR-PERMISSION`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub pull-request authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh pr:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-pr-allowed-tools`
- Benign Corpus: `skill-gh-pr-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC475 / CLAUDE-READ-UNSAFE-PATH` — Claude settings permissions allow `Read(...)` over an unsafe path in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-READ-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for exact unsafe-path `Read(...)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission-scope detection for `Read(...)` entries that target absolute, home-relative, parent-traversing, or drive-qualified paths inside parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-unsafe-path-permissions`
- Benign Corpus: `claude-settings-unsafe-path-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC476 / CLAUDE-WRITE-UNSAFE-PATH` — Claude settings permissions allow `Write(...)` over an unsafe path in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WRITE-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for exact unsafe-path `Write(...)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission-scope detection for `Write(...)` entries that target absolute, home-relative, parent-traversing, or drive-qualified paths inside parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-unsafe-path-permissions`
- Benign Corpus: `claude-settings-unsafe-path-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC477 / CLAUDE-EDIT-UNSAFE-PATH` — Claude settings permissions allow `Edit(...)` over an unsafe path in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-EDIT-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for exact unsafe-path `Edit(...)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission-scope detection for `Edit(...)` entries that target absolute, home-relative, parent-traversing, or drive-qualified paths inside parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-unsafe-path-permissions`
- Benign Corpus: `claude-settings-unsafe-path-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC478 / CLAUDE-GIT-RESET-PERMISSION` — Claude settings permissions allow `Bash(git reset:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-RESET-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git reset:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git reset:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-destructive-git-permissions`
- Benign Corpus: `claude-settings-destructive-git-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC479 / CLAUDE-GIT-CLEAN-PERMISSION` — Claude settings permissions allow `Bash(git clean:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-CLEAN-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git clean:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git clean:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-destructive-git-permissions`
- Benign Corpus: `claude-settings-destructive-git-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC480 / CLAUDE-GIT-RESTORE-PERMISSION` — Claude settings permissions allow `Bash(git restore:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-RESTORE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git restore:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git restore:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-destructive-git-permissions`
- Benign Corpus: `claude-settings-destructive-git-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC481 / CLAUDE-GIT-REBASE-PERMISSION` — Claude settings permissions allow `Bash(git rebase:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-REBASE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git rebase:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git rebase:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-destructive-git-permissions`
- Benign Corpus: `claude-settings-destructive-git-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC482 / CLAUDE-GIT-MERGE-PERMISSION` — Claude settings permissions allow `Bash(git merge:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-MERGE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git merge:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git merge:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-destructive-git-permissions`
- Benign Corpus: `claude-settings-destructive-git-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC483 / CLAUDE-GIT-CHERRY-PICK-PERMISSION` — Claude settings permissions allow `Bash(git cherry-pick:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-CHERRY-PICK-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git cherry-pick:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git cherry-pick:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-destructive-git-permissions`
- Benign Corpus: `claude-settings-destructive-git-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC484 / CLAUDE-GIT-APPLY-PERMISSION` — Claude settings permissions allow `Bash(git apply:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-APPLY-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git apply:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git apply:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-destructive-git-permissions`
- Benign Corpus: `claude-settings-destructive-git-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC485 / CLAUDE-GIT-AM-PERMISSION` — Claude settings permissions allow `Bash(git am:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GIT-AM-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(git am:*)` authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(git am:*)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-destructive-git-permissions`
- Benign Corpus: `claude-settings-destructive-git-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC486 / CLAUDE-GLOB-UNSAFE-PATH` — Claude settings permissions allow `Glob(...)` over an unsafe path in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GLOB-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for exact unsafe-path `Glob(...)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission-scope detection for `Glob(...)` entries that target absolute, home-relative, parent-traversing, or drive-qualified paths inside parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-glob-grep-unsafe-path-permissions`
- Benign Corpus: `claude-settings-unsafe-path-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC487 / CLAUDE-GREP-UNSAFE-PATH` — Claude settings permissions allow `Grep(...)` over an unsafe path in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GREP-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for exact unsafe-path `Grep(...)` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission-scope detection for `Grep(...)` entries that target absolute, home-relative, parent-traversing, or drive-qualified paths inside parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-glob-grep-unsafe-path-permissions`
- Benign Corpus: `claude-settings-unsafe-path-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC488 / CLAUDE-UVX-PERMISSION` — Claude settings permissions allow `Bash(uvx ...)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-UVX-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(uvx ...)` mutable package-runner authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(uvx ...)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-mutable-runner-permissions`
- Benign Corpus: `claude-settings-package-runner-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC489 / CLAUDE-PNPM-DLX-PERMISSION` — Claude settings permissions allow `Bash(pnpm dlx ...)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-PNPM-DLX-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(pnpm dlx ...)` mutable package-runner authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(pnpm dlx ...)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-mutable-runner-permissions`
- Benign Corpus: `claude-settings-package-runner-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC490 / CLAUDE-YARN-DLX-PERMISSION` — Claude settings permissions allow `Bash(yarn dlx ...)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-YARN-DLX-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(yarn dlx ...)` mutable package-runner authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(yarn dlx ...)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-mutable-runner-permissions`
- Benign Corpus: `claude-settings-package-runner-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC491 / CLAUDE-PIPX-RUN-PERMISSION` — Claude settings permissions allow `Bash(pipx run ...)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-PIPX-RUN-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(pipx run ...)` mutable package-runner authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(pipx run ...)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-mutable-runner-permissions`
- Benign Corpus: `claude-settings-package-runner-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC492 / CLAUDE-NPM-EXEC-PERMISSION` — Claude settings permissions allow `Bash(npm exec ...)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-NPM-EXEC-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(npm exec ...)` mutable package-runner authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(npm exec ...)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-npm-exec-bunx-permissions`
- Benign Corpus: `claude-settings-npm-exec-bunx-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC493 / CLAUDE-BUNX-PERMISSION` — Claude settings permissions allow `Bash(bunx ...)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-BUNX-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared committed Claude settings for exact `Bash(bunx ...)` mutable package-runner authority.
- Deterministic Signal Basis: ClaudeSettingsSignals exact permission detection for `Bash(bunx ...)` entries inside permissions.allow.
- Malicious Corpus: `claude-settings-npm-exec-bunx-permissions`
- Benign Corpus: `claude-settings-npm-exec-bunx-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC494 / MD-NPM-EXEC-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(npm exec:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-NPM-EXEC-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact mutable `npm exec` authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(npm exec:*)` in allowed-tools entries.
- Malicious Corpus: `skill-npm-exec-bunx-allowed-tools`
- Benign Corpus: `skill-npm-exec-bunx-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC495 / MD-BUNX-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(bunx:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-BUNX-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact mutable `bunx` authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(bunx:*)` in allowed-tools entries.
- Malicious Corpus: `skill-npm-exec-bunx-allowed-tools`
- Benign Corpus: `skill-npm-exec-bunx-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC496 / MD-UVX-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(uvx:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-UVX-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact mutable `uvx` authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(uvx:*)` in allowed-tools entries.
- Malicious Corpus: `skill-uvx-dlx-pipx-allowed-tools`
- Benign Corpus: `skill-uvx-dlx-pipx-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC497 / MD-PNPM-DLX-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(pnpm dlx:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-PNPM-DLX-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact mutable `pnpm dlx` authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(pnpm dlx:*)` in allowed-tools entries.
- Malicious Corpus: `skill-uvx-dlx-pipx-allowed-tools`
- Benign Corpus: `skill-uvx-dlx-pipx-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC498 / MD-YARN-DLX-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(yarn dlx:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-YARN-DLX-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact mutable `yarn dlx` authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(yarn dlx:*)` in allowed-tools entries.
- Malicious Corpus: `skill-uvx-dlx-pipx-allowed-tools`
- Benign Corpus: `skill-uvx-dlx-pipx-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC499 / MD-PIPX-RUN-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(pipx run:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-PIPX-RUN-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact mutable `pipx run` authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(pipx run:*)` in allowed-tools entries.
- Malicious Corpus: `skill-uvx-dlx-pipx-allowed-tools`
- Benign Corpus: `skill-uvx-dlx-pipx-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC500 / MD-NPX-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(npx:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-NPX-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact mutable `npx` authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(npx:*)` in allowed-tools entries.
- Malicious Corpus: `skill-npx-git-ls-remote-allowed-tools`
- Benign Corpus: `skill-npx-git-ls-remote-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC501 / MD-GIT-LS-REMOTE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(git ls-remote:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GIT-LS-REMOTE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact remote repository inspection authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(git ls-remote:*)` in allowed-tools entries.
- Malicious Corpus: `skill-npx-git-ls-remote-allowed-tools`
- Benign Corpus: `skill-npx-git-ls-remote-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC502 / CLAUDE-GH-API-POST-PERMISSION` — Claude settings permissions allow `Bash(gh api --method POST:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-API-POST-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub API POST mutation authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh api --method POST:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-mutation-permissions`
- Benign Corpus: `claude-settings-gh-mutation-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC503 / CLAUDE-GH-ISSUE-CREATE-PERMISSION` — Claude settings permissions allow `Bash(gh issue create:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-ISSUE-CREATE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub issue creation authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh issue create:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-mutation-permissions`
- Benign Corpus: `claude-settings-gh-mutation-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC504 / CLAUDE-GH-REPO-CREATE-PERMISSION` — Claude settings permissions allow `Bash(gh repo create:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-REPO-CREATE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub repository creation authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh repo create:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-mutation-permissions`
- Benign Corpus: `claude-settings-gh-mutation-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC505 / MD-GH-API-POST-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh api --method POST:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-API-POST-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub API POST mutation authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh api --method POST:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-mutation-allowed-tools`
- Benign Corpus: `skill-gh-mutation-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC506 / MD-GH-ISSUE-CREATE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh issue create:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-ISSUE-CREATE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub issue creation authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh issue create:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-mutation-allowed-tools`
- Benign Corpus: `skill-gh-mutation-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC507 / MD-GH-REPO-CREATE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh repo create:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-REPO-CREATE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub repository creation authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh repo create:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-mutation-allowed-tools`
- Benign Corpus: `skill-gh-mutation-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC508 / CLAUDE-GH-SECRET-SET-PERMISSION` — Claude settings permissions allow `Bash(gh secret set:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-SECRET-SET-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub secret mutation authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh secret set:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-secret-variable-workflow-permissions`
- Benign Corpus: `claude-settings-gh-secret-variable-workflow-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC509 / CLAUDE-GH-VARIABLE-SET-PERMISSION` — Claude settings permissions allow `Bash(gh variable set:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-VARIABLE-SET-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub variable mutation authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh variable set:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-secret-variable-workflow-permissions`
- Benign Corpus: `claude-settings-gh-secret-variable-workflow-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC510 / CLAUDE-GH-WORKFLOW-RUN-PERMISSION` — Claude settings permissions allow `Bash(gh workflow run:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-WORKFLOW-RUN-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub workflow dispatch authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh workflow run:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-secret-variable-workflow-permissions`
- Benign Corpus: `claude-settings-gh-secret-variable-workflow-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC511 / MD-GH-SECRET-SET-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh secret set:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-SECRET-SET-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub secret mutation authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh secret set:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-secret-variable-workflow-allowed-tools`
- Benign Corpus: `skill-gh-secret-variable-workflow-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC512 / MD-GH-VARIABLE-SET-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh variable set:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-VARIABLE-SET-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub variable mutation authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh variable set:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-secret-variable-workflow-allowed-tools`
- Benign Corpus: `skill-gh-secret-variable-workflow-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC513 / MD-GH-WORKFLOW-RUN-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh workflow run:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-WORKFLOW-RUN-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub workflow dispatch authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh workflow run:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-secret-variable-workflow-allowed-tools`
- Benign Corpus: `skill-gh-secret-variable-workflow-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC514 / CLAUDE-GH-SECRET-DELETE-PERMISSION` — Claude settings permissions allow `Bash(gh secret delete:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-SECRET-DELETE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub secret deletion authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh secret delete:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-mutation-permissions`
- Benign Corpus: `claude-settings-gh-mutation-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC515 / CLAUDE-GH-VARIABLE-DELETE-PERMISSION` — Claude settings permissions allow `Bash(gh variable delete:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-VARIABLE-DELETE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub variable deletion authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh variable delete:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-mutation-permissions`
- Benign Corpus: `claude-settings-gh-mutation-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC516 / CLAUDE-GH-WORKFLOW-DISABLE-PERMISSION` — Claude settings permissions allow `Bash(gh workflow disable:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-WORKFLOW-DISABLE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub workflow disable authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh workflow disable:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-mutation-permissions`
- Benign Corpus: `claude-settings-gh-mutation-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC517 / MD-GH-SECRET-DELETE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh secret delete:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-SECRET-DELETE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub secret deletion authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh secret delete:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-mutation-allowed-tools`
- Benign Corpus: `skill-gh-mutation-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC518 / MD-GH-VARIABLE-DELETE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh variable delete:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-VARIABLE-DELETE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub variable deletion authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh variable delete:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-mutation-allowed-tools`
- Benign Corpus: `skill-gh-mutation-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC519 / MD-GH-WORKFLOW-DISABLE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh workflow disable:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-WORKFLOW-DISABLE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub workflow disable authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh workflow disable:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-mutation-allowed-tools`
- Benign Corpus: `skill-gh-mutation-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC520 / MD-READ-WILDCARD` — AI-native markdown frontmatter grants `Read(*)` wildcard access

- Provider: `lintai-ai-security`
- Alias: `MD-READ-WILDCARD`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for exact `Read(*)` grants that expose unconstrained reading as shared default policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Read(*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-core-wildcard-allowed-tools`
- Benign Corpus: `skill-core-wildcard-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC521 / MD-WRITE-WILDCARD` — AI-native markdown frontmatter grants `Write(*)` wildcard access

- Provider: `lintai-ai-security`
- Alias: `MD-WRITE-WILDCARD`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for exact `Write(*)` grants that expose unconstrained mutation as shared default policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Write(*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-core-wildcard-allowed-tools`
- Benign Corpus: `skill-core-wildcard-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC522 / MD-EDIT-WILDCARD` — AI-native markdown frontmatter grants `Edit(*)` wildcard access

- Provider: `lintai-ai-security`
- Alias: `MD-EDIT-WILDCARD`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for exact `Edit(*)` grants that expose unconstrained editing as shared default policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Edit(*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-core-wildcard-allowed-tools`
- Benign Corpus: `skill-core-wildcard-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC523 / MD-GLOB-WILDCARD` — AI-native markdown frontmatter grants `Glob(*)` wildcard access

- Provider: `lintai-ai-security`
- Alias: `MD-GLOB-WILDCARD`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for exact `Glob(*)` grants that expose unconstrained file discovery as shared default policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Glob(*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-core-wildcard-allowed-tools`
- Benign Corpus: `skill-core-wildcard-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC524 / MD-GREP-WILDCARD` — AI-native markdown frontmatter grants `Grep(*)` wildcard access

- Provider: `lintai-ai-security`
- Alias: `MD-GREP-WILDCARD`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for exact `Grep(*)` grants that expose unconstrained content search as shared default policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Grep(*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-core-wildcard-allowed-tools`
- Benign Corpus: `skill-core-wildcard-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC525 / MD-WEBFETCH-WILDCARD` — AI-native markdown frontmatter grants `WebFetch(*)` wildcard access

- Provider: `lintai-ai-security`
- Alias: `MD-WEBFETCH-WILDCARD`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for exact `WebFetch(*)` grants that expose unconstrained remote fetch authority as shared default policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `WebFetch(*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-core-wildcard-allowed-tools`
- Benign Corpus: `skill-core-wildcard-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC526 / MD-WEBSEARCH-WILDCARD` — AI-native markdown frontmatter grants `WebSearch(*)` wildcard access

- Provider: `lintai-ai-security`
- Alias: `MD-WEBSEARCH-WILDCARD`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for exact `WebSearch(*)` grants that expose unconstrained search authority as shared default policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `WebSearch(*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-core-wildcard-allowed-tools`
- Benign Corpus: `skill-core-wildcard-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC527 / MD-BASH-WILDCARD` — AI-native markdown frontmatter grants `Bash(*)` wildcard access

- Provider: `lintai-ai-security`
- Alias: `MD-BASH-WILDCARD`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native frontmatter for exact `Bash(*)` grants that expose unconstrained shell execution as shared default policy.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter token detection for `Bash(*)` inside allowed-tools or allowed_tools.
- Malicious Corpus: `skill-bash-wildcard-allowed-tools`
- Benign Corpus: `skill-bash-wildcard-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC528 / CLAUDE-GH-API-DELETE-PERMISSION` — Claude settings permissions allow `Bash(gh api --method DELETE:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-API-DELETE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub API DELETE mutation authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh api --method DELETE:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-api-delete-permission`
- Benign Corpus: `claude-settings-gh-api-delete-permission-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC529 / MD-GH-API-DELETE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh api --method DELETE:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-API-DELETE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub API DELETE mutation authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh api --method DELETE:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-api-delete-allowed-tools`
- Benign Corpus: `skill-gh-api-delete-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC530 / CLAUDE-GH-API-PATCH-PERMISSION` — Claude settings permissions allow `Bash(gh api --method PATCH:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-API-PATCH-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub API PATCH mutation authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh api --method PATCH:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-api-patch-permission`
- Benign Corpus: `claude-settings-gh-api-patch-permission-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC531 / CLAUDE-GH-API-PUT-PERMISSION` — Claude settings permissions allow `Bash(gh api --method PUT:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-API-PUT-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub API PUT mutation authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh api --method PUT:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-api-put-permission`
- Benign Corpus: `claude-settings-gh-api-put-permission-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC532 / MD-GH-API-PATCH-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh api --method PATCH:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-API-PATCH-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub API PATCH mutation authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh api --method PATCH:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-api-patch-allowed-tools`
- Benign Corpus: `skill-gh-api-patch-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC533 / MD-GH-API-PUT-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh api --method PUT:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-API-PUT-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub API PUT mutation authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh api --method PUT:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-api-put-allowed-tools`
- Benign Corpus: `skill-gh-api-put-allowed-tools-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC534 / CLAUDE-GH-REPO-DELETE-PERMISSION` — Claude settings permissions allow `Bash(gh repo delete:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-REPO-DELETE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub repository deletion authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh repo delete:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-repo-release-delete-permissions`
- Benign Corpus: `claude-settings-gh-repo-release-delete-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC535 / MD-GH-REPO-DELETE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh repo delete:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-REPO-DELETE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub repository deletion authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh repo delete:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-repo-release-delete-allowed-tools`
- Benign Corpus: `skill-gh-repo-release-delete-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC536 / CLAUDE-GH-RELEASE-DELETE-PERMISSION` — Claude settings permissions allow `Bash(gh release delete:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-RELEASE-DELETE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub release deletion authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh release delete:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-repo-release-delete-permissions`
- Benign Corpus: `claude-settings-gh-repo-release-delete-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC537 / MD-GH-RELEASE-DELETE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh release delete:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-RELEASE-DELETE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub release deletion authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh release delete:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-repo-release-delete-allowed-tools`
- Benign Corpus: `skill-gh-repo-release-delete-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC538 / CLAUDE-GH-REPO-EDIT-PERMISSION` — Claude settings permissions allow `Bash(gh repo edit:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-REPO-EDIT-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub repository settings mutation authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh repo edit:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-repo-edit-release-create-permissions`
- Benign Corpus: `claude-settings-gh-repo-edit-release-create-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC539 / MD-GH-REPO-EDIT-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh repo edit:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-REPO-EDIT-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub repository settings mutation authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh repo edit:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-repo-edit-release-create-allowed-tools`
- Benign Corpus: `skill-gh-repo-edit-release-create-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC540 / CLAUDE-GH-RELEASE-CREATE-PERMISSION` — Claude settings permissions allow `Bash(gh release create:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-RELEASE-CREATE-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub release creation authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh release create:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-repo-edit-release-create-permissions`
- Benign Corpus: `claude-settings-gh-repo-edit-release-create-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC541 / MD-GH-RELEASE-CREATE-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh release create:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-RELEASE-CREATE-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub release creation authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh release create:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-repo-edit-release-create-allowed-tools`
- Benign Corpus: `skill-gh-repo-edit-release-create-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC542 / CLAUDE-GH-REPO-TRANSFER-PERMISSION` — Claude settings permissions allow `Bash(gh repo transfer:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-REPO-TRANSFER-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub repository transfer authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh repo transfer:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-repo-transfer-release-upload-permissions`
- Benign Corpus: `claude-settings-gh-repo-transfer-release-upload-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC543 / MD-GH-REPO-TRANSFER-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh repo transfer:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-REPO-TRANSFER-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub repository transfer authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh repo transfer:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-repo-transfer-release-upload-allowed-tools`
- Benign Corpus: `skill-gh-repo-transfer-release-upload-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC544 / CLAUDE-GH-RELEASE-UPLOAD-PERMISSION` — Claude settings permissions allow `Bash(gh release upload:*)` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GH-RELEASE-UPLOAD-PERMISSION`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings for exact GitHub release asset upload authority through `permissions.allow`.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for `Bash(gh release upload:*)` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-gh-repo-transfer-release-upload-permissions`
- Benign Corpus: `claude-settings-gh-repo-transfer-release-upload-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC545 / MD-GH-RELEASE-UPLOAD-ALLOWED-TOOLS` — AI-native markdown frontmatter grants `Bash(gh release upload:*)` tool access

- Provider: `lintai-ai-security`
- Alias: `MD-GH-RELEASE-UPLOAD-ALLOWED-TOOLS`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks AI-native markdown frontmatter for exact GitHub release asset upload authority through `allowed-tools`.
- Deterministic Signal Basis: MarkdownSignals exact frontmatter string detection for `Bash(gh release upload:*)` in allowed-tools entries.
- Malicious Corpus: `skill-gh-repo-transfer-release-upload-allowed-tools`
- Benign Corpus: `skill-gh-repo-transfer-release-upload-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC546 / MCP-AUTOAPPROVE-BASH-WILDCARD` — MCP configuration auto-approves blanket shell execution with `autoApprove: ["Bash(*)"]`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-BASH-WILDCARD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit blanket shell auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-bash-wildcard`
- Benign Corpus: `mcp-autoapprove-bash-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC547 / MCP-AUTOAPPROVE-CURL` — MCP configuration auto-approves `Bash(curl:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-CURL`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit `curl` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(curl:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-curl-wget`
- Benign Corpus: `mcp-autoapprove-curl-wget-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC548 / MCP-AUTOAPPROVE-WGET` — MCP configuration auto-approves `Bash(wget:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-WGET`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit `wget` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(wget:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-curl-wget`
- Benign Corpus: `mcp-autoapprove-curl-wget-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC549 / MCP-AUTOAPPROVE-SUDO` — MCP configuration auto-approves `Bash(sudo:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-SUDO`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `sudo` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(sudo:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-sudo-rm`
- Benign Corpus: `mcp-autoapprove-sudo-rm-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC550 / MCP-AUTOAPPROVE-RM` — MCP configuration auto-approves `Bash(rm:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-RM`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact destructive `rm` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(rm:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-sudo-rm`
- Benign Corpus: `mcp-autoapprove-sudo-rm-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC551 / MCP-AUTOAPPROVE-GIT-PUSH` — MCP configuration auto-approves `Bash(git push)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-PUSH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `git push` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git push)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-push-gh-api-post`
- Benign Corpus: `mcp-autoapprove-git-push-gh-api-post-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC552 / MCP-AUTOAPPROVE-GH-API-POST` — MCP configuration auto-approves `Bash(gh api --method POST:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-API-POST`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact GitHub API POST auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh api --method POST:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-push-gh-api-post`
- Benign Corpus: `mcp-autoapprove-git-push-gh-api-post-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC553 / MCP-AUTOAPPROVE-GIT-CHECKOUT` — MCP configuration auto-approves `Bash(git checkout:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-CHECKOUT`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `git checkout` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git checkout:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-destructive-family`
- Benign Corpus: `mcp-autoapprove-git-destructive-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC554 / MCP-AUTOAPPROVE-GIT-COMMIT` — MCP configuration auto-approves `Bash(git commit:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-COMMIT`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `git commit` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git commit:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-destructive-family`
- Benign Corpus: `mcp-autoapprove-git-destructive-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC555 / MCP-AUTOAPPROVE-GIT-RESET` — MCP configuration auto-approves `Bash(git reset:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-RESET`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `git reset` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git reset:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-destructive-family`
- Benign Corpus: `mcp-autoapprove-git-destructive-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC556 / MCP-AUTOAPPROVE-GIT-CLEAN` — MCP configuration auto-approves `Bash(git clean:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-CLEAN`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `git clean` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git clean:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-destructive-family`
- Benign Corpus: `mcp-autoapprove-git-destructive-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC557 / MCP-AUTOAPPROVE-GH-API-DELETE` — MCP configuration auto-approves `Bash(gh api --method DELETE:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-API-DELETE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact GitHub API DELETE auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh api --method DELETE:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-api-mutation-family`
- Benign Corpus: `mcp-autoapprove-gh-api-mutation-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC558 / MCP-AUTOAPPROVE-GH-API-PATCH` — MCP configuration auto-approves `Bash(gh api --method PATCH:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-API-PATCH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact GitHub API PATCH auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh api --method PATCH:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-api-mutation-family`
- Benign Corpus: `mcp-autoapprove-gh-api-mutation-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC559 / MCP-AUTOAPPROVE-GH-API-PUT` — MCP configuration auto-approves `Bash(gh api --method PUT:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-API-PUT`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact GitHub API PUT auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh api --method PUT:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-api-mutation-family`
- Benign Corpus: `mcp-autoapprove-gh-api-mutation-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC560 / MCP-AUTOAPPROVE-GH-ISSUE-CREATE` — MCP configuration auto-approves `Bash(gh issue create:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-ISSUE-CREATE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh issue create` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh issue create:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-mutation-family`
- Benign Corpus: `mcp-autoapprove-gh-mutation-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC561 / MCP-AUTOAPPROVE-GH-REPO-CREATE` — MCP configuration auto-approves `Bash(gh repo create:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-REPO-CREATE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh repo create` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh repo create:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-mutation-family`
- Benign Corpus: `mcp-autoapprove-gh-mutation-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC562 / MCP-AUTOAPPROVE-GH-REPO-DELETE` — MCP configuration auto-approves `Bash(gh repo delete:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-REPO-DELETE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh repo delete` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh repo delete:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-mutation-family`
- Benign Corpus: `mcp-autoapprove-gh-mutation-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC563 / MCP-AUTOAPPROVE-GH-REPO-EDIT` — MCP configuration auto-approves `Bash(gh repo edit:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-REPO-EDIT`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh repo edit` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh repo edit:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-mutation-family`
- Benign Corpus: `mcp-autoapprove-gh-mutation-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC564 / MCP-AUTOAPPROVE-GH-SECRET-SET` — MCP configuration auto-approves `Bash(gh secret set:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-SECRET-SET`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh secret set` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh secret set:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-mutation-family`
- Benign Corpus: `mcp-autoapprove-gh-mutation-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC565 / MCP-AUTOAPPROVE-GH-VARIABLE-SET` — MCP configuration auto-approves `Bash(gh variable set:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-VARIABLE-SET`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh variable set` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh variable set:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-mutation-family`
- Benign Corpus: `mcp-autoapprove-gh-mutation-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC566 / MCP-AUTOAPPROVE-GH-WORKFLOW-RUN` — MCP configuration auto-approves `Bash(gh workflow run:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-WORKFLOW-RUN`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh workflow run` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh workflow run:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-mutation-family`
- Benign Corpus: `mcp-autoapprove-gh-mutation-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC567 / MCP-AUTOAPPROVE-READ-WILDCARD` — MCP configuration auto-approves `Read(*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-READ-WILDCARD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit `Read(*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Read(*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-wildcard-tool-family`
- Benign Corpus: `mcp-autoapprove-wildcard-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC568 / MCP-AUTOAPPROVE-WRITE-WILDCARD` — MCP configuration auto-approves `Write(*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-WRITE-WILDCARD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit `Write(*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Write(*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-wildcard-tool-family`
- Benign Corpus: `mcp-autoapprove-wildcard-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC569 / MCP-AUTOAPPROVE-EDIT-WILDCARD` — MCP configuration auto-approves `Edit(*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-EDIT-WILDCARD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit `Edit(*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Edit(*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-wildcard-tool-family`
- Benign Corpus: `mcp-autoapprove-wildcard-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC570 / MCP-AUTOAPPROVE-GLOB-WILDCARD` — MCP configuration auto-approves `Glob(*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GLOB-WILDCARD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit `Glob(*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Glob(*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-wildcard-tool-family`
- Benign Corpus: `mcp-autoapprove-wildcard-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC571 / MCP-AUTOAPPROVE-GREP-WILDCARD` — MCP configuration auto-approves `Grep(*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GREP-WILDCARD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit `Grep(*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Grep(*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-wildcard-tool-family`
- Benign Corpus: `mcp-autoapprove-wildcard-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC572 / MCP-AUTOAPPROVE-WEBFETCH-WILDCARD` — MCP configuration auto-approves `WebFetch(*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-WEBFETCH-WILDCARD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit `WebFetch(*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["WebFetch(*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-wildcard-tool-family`
- Benign Corpus: `mcp-autoapprove-wildcard-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC573 / MCP-AUTOAPPROVE-WEBSEARCH-WILDCARD` — MCP configuration auto-approves `WebSearch(*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-WEBSEARCH-WILDCARD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit `WebSearch(*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["WebSearch(*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-wildcard-tool-family`
- Benign Corpus: `mcp-autoapprove-wildcard-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC574 / MCP-AUTOAPPROVE-READ-UNSAFE-PATH` — MCP configuration auto-approves `Read(...)` over an unsafe path through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-READ-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact unsafe-path `Read(...)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item predicate detection for `autoApprove` entries where `Read(...)` targets an absolute, home-relative, parent-traversing, or drive-qualified path.
- Malicious Corpus: `mcp-autoapprove-unsafe-path-family`
- Benign Corpus: `mcp-autoapprove-unsafe-path-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC575 / MCP-AUTOAPPROVE-WRITE-UNSAFE-PATH` — MCP configuration auto-approves `Write(...)` over an unsafe path through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-WRITE-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact unsafe-path `Write(...)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item predicate detection for `autoApprove` entries where `Write(...)` targets an absolute, home-relative, parent-traversing, or drive-qualified path.
- Malicious Corpus: `mcp-autoapprove-unsafe-path-family`
- Benign Corpus: `mcp-autoapprove-unsafe-path-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC576 / MCP-AUTOAPPROVE-EDIT-UNSAFE-PATH` — MCP configuration auto-approves `Edit(...)` over an unsafe path through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-EDIT-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact unsafe-path `Edit(...)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item predicate detection for `autoApprove` entries where `Edit(...)` targets an absolute, home-relative, parent-traversing, or drive-qualified path.
- Malicious Corpus: `mcp-autoapprove-unsafe-path-family`
- Benign Corpus: `mcp-autoapprove-unsafe-path-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC577 / MCP-AUTOAPPROVE-GLOB-UNSAFE-PATH` — MCP configuration auto-approves `Glob(...)` over an unsafe path through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GLOB-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact unsafe-path `Glob(...)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item predicate detection for `autoApprove` entries where `Glob(...)` targets an absolute, home-relative, parent-traversing, or drive-qualified path.
- Malicious Corpus: `mcp-autoapprove-unsafe-path-family`
- Benign Corpus: `mcp-autoapprove-unsafe-path-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC578 / MCP-AUTOAPPROVE-GREP-UNSAFE-PATH` — MCP configuration auto-approves `Grep(...)` over an unsafe path through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GREP-UNSAFE-PATH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact unsafe-path `Grep(...)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item predicate detection for `autoApprove` entries where `Grep(...)` targets an absolute, home-relative, parent-traversing, or drive-qualified path.
- Malicious Corpus: `mcp-autoapprove-unsafe-path-family`
- Benign Corpus: `mcp-autoapprove-unsafe-path-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC579 / MCP-AUTOAPPROVE-GH-SECRET-DELETE` — MCP configuration auto-approves `Bash(gh secret delete:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-SECRET-DELETE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh secret delete` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh secret delete:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-delete-family`
- Benign Corpus: `mcp-autoapprove-gh-delete-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC580 / MCP-AUTOAPPROVE-GH-VARIABLE-DELETE` — MCP configuration auto-approves `Bash(gh variable delete:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-VARIABLE-DELETE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh variable delete` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh variable delete:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-delete-family`
- Benign Corpus: `mcp-autoapprove-gh-delete-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC581 / MCP-AUTOAPPROVE-GH-WORKFLOW-DISABLE` — MCP configuration auto-approves `Bash(gh workflow disable:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-WORKFLOW-DISABLE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh workflow disable` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh workflow disable:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-delete-family`
- Benign Corpus: `mcp-autoapprove-gh-delete-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC582 / MCP-AUTOAPPROVE-GH-REPO-TRANSFER` — MCP configuration auto-approves `Bash(gh repo transfer:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-REPO-TRANSFER`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh repo transfer` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh repo transfer:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-release-transfer-family`
- Benign Corpus: `mcp-autoapprove-gh-release-transfer-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC583 / MCP-AUTOAPPROVE-GH-RELEASE-CREATE` — MCP configuration auto-approves `Bash(gh release create:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-RELEASE-CREATE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh release create` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh release create:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-release-transfer-family`
- Benign Corpus: `mcp-autoapprove-gh-release-transfer-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC584 / MCP-AUTOAPPROVE-GH-RELEASE-DELETE` — MCP configuration auto-approves `Bash(gh release delete:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-RELEASE-DELETE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh release delete` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh release delete:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-release-transfer-family`
- Benign Corpus: `mcp-autoapprove-gh-release-transfer-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC585 / MCP-AUTOAPPROVE-GH-RELEASE-UPLOAD` — MCP configuration auto-approves `Bash(gh release upload:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-RELEASE-UPLOAD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `gh release upload` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh release upload:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-gh-release-transfer-family`
- Benign Corpus: `mcp-autoapprove-gh-release-transfer-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC586 / MCP-AUTOAPPROVE-NPX` — MCP configuration auto-approves `Bash(npx ...)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-NPX`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(npx ...)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(npx ` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-mutable-runner-family`
- Benign Corpus: `mcp-autoapprove-mutable-runner-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC587 / MCP-AUTOAPPROVE-UVX` — MCP configuration auto-approves `Bash(uvx ...)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-UVX`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(uvx ...)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(uvx ` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-mutable-runner-family`
- Benign Corpus: `mcp-autoapprove-mutable-runner-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC588 / MCP-AUTOAPPROVE-NPM-EXEC` — MCP configuration auto-approves `Bash(npm exec ...)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-NPM-EXEC`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(npm exec ...)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(npm exec ` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-mutable-runner-family`
- Benign Corpus: `mcp-autoapprove-mutable-runner-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC589 / MCP-AUTOAPPROVE-BUNX` — MCP configuration auto-approves `Bash(bunx ...)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-BUNX`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(bunx ...)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(bunx ` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-mutable-runner-family`
- Benign Corpus: `mcp-autoapprove-mutable-runner-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC590 / MCP-AUTOAPPROVE-PNPM-DLX` — MCP configuration auto-approves `Bash(pnpm dlx ...)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-PNPM-DLX`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(pnpm dlx ...)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(pnpm dlx ` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-mutable-runner-family`
- Benign Corpus: `mcp-autoapprove-mutable-runner-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC591 / MCP-AUTOAPPROVE-YARN-DLX` — MCP configuration auto-approves `Bash(yarn dlx ...)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-YARN-DLX`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(yarn dlx ...)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(yarn dlx ` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-mutable-runner-family`
- Benign Corpus: `mcp-autoapprove-mutable-runner-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC592 / MCP-AUTOAPPROVE-PIPX-RUN` — MCP configuration auto-approves `Bash(pipx run ...)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-PIPX-RUN`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(pipx run ...)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(pipx run ` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-mutable-runner-family`
- Benign Corpus: `mcp-autoapprove-mutable-runner-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC593 / MCP-AUTOAPPROVE-PACKAGE-INSTALL` — MCP configuration auto-approves package installation commands through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-PACKAGE-INSTALL`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact package installation auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for package installation entries such as `Bash(pip install)` and `Bash(npm install)` inside `autoApprove` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-package-install-family`
- Benign Corpus: `mcp-autoapprove-package-install-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC594 / MCP-AUTOAPPROVE-GIT-CLONE` — MCP configuration auto-approves `Bash(git clone:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-CLONE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git clone:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git clone:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-repo-fetch-family`
- Benign Corpus: `mcp-autoapprove-repo-fetch-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC595 / MCP-AUTOAPPROVE-GIT-FETCH` — MCP configuration auto-approves `Bash(git fetch:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-FETCH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git fetch:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git fetch:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-repo-fetch-family`
- Benign Corpus: `mcp-autoapprove-repo-fetch-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC596 / MCP-AUTOAPPROVE-GIT-LS-REMOTE` — MCP configuration auto-approves `Bash(git ls-remote:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-LS-REMOTE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git ls-remote:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git ls-remote:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-repo-fetch-family`
- Benign Corpus: `mcp-autoapprove-repo-fetch-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC597 / MCP-AUTOAPPROVE-GIT-ADD` — MCP configuration auto-approves `Bash(git add:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-ADD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git add:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git add:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-repo-management-family`
- Benign Corpus: `mcp-autoapprove-repo-management-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC598 / MCP-AUTOAPPROVE-GIT-CONFIG` — MCP configuration auto-approves `Bash(git config:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-CONFIG`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git config:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git config:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-repo-management-family`
- Benign Corpus: `mcp-autoapprove-repo-management-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC599 / MCP-AUTOAPPROVE-GIT-TAG` — MCP configuration auto-approves `Bash(git tag:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-TAG`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git tag:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git tag:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-repo-management-family`
- Benign Corpus: `mcp-autoapprove-repo-management-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC600 / MCP-AUTOAPPROVE-GIT-BRANCH` — MCP configuration auto-approves `Bash(git branch:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-BRANCH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git branch:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git branch:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-repo-management-family`
- Benign Corpus: `mcp-autoapprove-repo-management-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC601 / MCP-AUTOAPPROVE-GH-PR` — MCP configuration auto-approves `Bash(gh pr:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GH-PR`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(gh pr:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(gh pr:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-repo-management-family`
- Benign Corpus: `mcp-autoapprove-repo-management-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC602 / MCP-AUTOAPPROVE-GIT-STASH` — MCP configuration auto-approves `Bash(git stash:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-STASH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git stash:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git stash:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-history-family`
- Benign Corpus: `mcp-autoapprove-git-history-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC603 / MCP-AUTOAPPROVE-GIT-RESTORE` — MCP configuration auto-approves `Bash(git restore:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-RESTORE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git restore:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git restore:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-history-family`
- Benign Corpus: `mcp-autoapprove-git-history-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC604 / MCP-AUTOAPPROVE-GIT-REBASE` — MCP configuration auto-approves `Bash(git rebase:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-REBASE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git rebase:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git rebase:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-history-family`
- Benign Corpus: `mcp-autoapprove-git-history-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC605 / MCP-AUTOAPPROVE-GIT-MERGE` — MCP configuration auto-approves `Bash(git merge:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-MERGE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git merge:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git merge:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-history-family`
- Benign Corpus: `mcp-autoapprove-git-history-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC606 / MCP-AUTOAPPROVE-GIT-CHERRY-PICK` — MCP configuration auto-approves `Bash(git cherry-pick:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-CHERRY-PICK`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git cherry-pick:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git cherry-pick:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-history-family`
- Benign Corpus: `mcp-autoapprove-git-history-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC607 / MCP-AUTOAPPROVE-GIT-APPLY` — MCP configuration auto-approves `Bash(git apply:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-APPLY`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git apply:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git apply:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-history-family`
- Benign Corpus: `mcp-autoapprove-git-history-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC608 / MCP-AUTOAPPROVE-GIT-AM` — MCP configuration auto-approves `Bash(git am:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GIT-AM`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(git am:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(git am:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-git-history-family`
- Benign Corpus: `mcp-autoapprove-git-history-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC609 / MCP-AUTOAPPROVE-CRONTAB` — MCP configuration auto-approves `Bash(crontab:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-CRONTAB`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(crontab:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(crontab:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-persistence-family`
- Benign Corpus: `mcp-autoapprove-persistence-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC610 / MCP-AUTOAPPROVE-SYSTEMCTL-ENABLE` — MCP configuration auto-approves `Bash(systemctl enable:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-SYSTEMCTL-ENABLE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(systemctl enable:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(systemctl enable:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-persistence-family`
- Benign Corpus: `mcp-autoapprove-persistence-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC611 / MCP-AUTOAPPROVE-LAUNCHCTL-LOAD` — MCP configuration auto-approves `Bash(launchctl load:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-LAUNCHCTL-LOAD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(launchctl load:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(launchctl load:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-persistence-family`
- Benign Corpus: `mcp-autoapprove-persistence-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC612 / MCP-AUTOAPPROVE-LAUNCHCTL-BOOTSTRAP` — MCP configuration auto-approves `Bash(launchctl bootstrap:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-LAUNCHCTL-BOOTSTRAP`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(launchctl bootstrap:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(launchctl bootstrap:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-persistence-family`
- Benign Corpus: `mcp-autoapprove-persistence-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC613 / MCP-AUTOAPPROVE-CHMOD` — MCP configuration auto-approves `Bash(chmod:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-CHMOD`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(chmod:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(chmod:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-privileged-shell-family`
- Benign Corpus: `mcp-autoapprove-privileged-shell-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC614 / MCP-AUTOAPPROVE-CHOWN` — MCP configuration auto-approves `Bash(chown:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-CHOWN`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(chown:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(chown:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-privileged-shell-family`
- Benign Corpus: `mcp-autoapprove-privileged-shell-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC615 / MCP-AUTOAPPROVE-CHGRP` — MCP configuration auto-approves `Bash(chgrp:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-CHGRP`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(chgrp:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(chgrp:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-privileged-shell-family`
- Benign Corpus: `mcp-autoapprove-privileged-shell-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC616 / MCP-AUTOAPPROVE-SU` — MCP configuration auto-approves `Bash(su:*)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-SU`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact `Bash(su:*)` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash(su:*)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-privileged-shell-family`
- Benign Corpus: `mcp-autoapprove-privileged-shell-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC617 / MCP-AUTOAPPROVE-WEBFETCH-RAW-GITHUB` — MCP configuration auto-approves `WebFetch(domain:raw.githubusercontent.com)` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-WEBFETCH-RAW-GITHUB`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact raw GitHub WebFetch auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["WebFetch(domain:raw.githubusercontent.com)"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-webfetch-raw-github`
- Benign Corpus: `mcp-autoapprove-webfetch-raw-github-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC618 / MCP-AUTOAPPROVE-READ` — MCP configuration auto-approves bare `Read` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-READ`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact bare `Read` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for bare `Read` in parsed `autoApprove` entries.
- Malicious Corpus: `mcp-autoapprove-unscoped-tool-family`
- Benign Corpus: `mcp-autoapprove-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC619 / MCP-AUTOAPPROVE-WRITE` — MCP configuration auto-approves bare `Write` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-WRITE`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact bare `Write` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for bare `Write` in parsed `autoApprove` entries.
- Malicious Corpus: `mcp-autoapprove-unscoped-tool-family`
- Benign Corpus: `mcp-autoapprove-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC620 / MCP-AUTOAPPROVE-EDIT` — MCP configuration auto-approves bare `Edit` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-EDIT`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact bare `Edit` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for bare `Edit` in parsed `autoApprove` entries.
- Malicious Corpus: `mcp-autoapprove-unscoped-tool-family`
- Benign Corpus: `mcp-autoapprove-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC621 / MCP-AUTOAPPROVE-GLOB` — MCP configuration auto-approves bare `Glob` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GLOB`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact bare `Glob` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for bare `Glob` in parsed `autoApprove` entries.
- Malicious Corpus: `mcp-autoapprove-unscoped-tool-family`
- Benign Corpus: `mcp-autoapprove-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC622 / MCP-AUTOAPPROVE-GREP` — MCP configuration auto-approves bare `Grep` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-GREP`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact bare `Grep` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for bare `Grep` in parsed `autoApprove` entries.
- Malicious Corpus: `mcp-autoapprove-unscoped-tool-family`
- Benign Corpus: `mcp-autoapprove-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC623 / MCP-AUTOAPPROVE-WEBFETCH` — MCP configuration auto-approves bare `WebFetch` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-WEBFETCH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact bare `WebFetch` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for bare `WebFetch` in parsed `autoApprove` entries.
- Malicious Corpus: `mcp-autoapprove-unscoped-tool-family`
- Benign Corpus: `mcp-autoapprove-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC624 / MCP-AUTOAPPROVE-WEBSEARCH` — MCP configuration auto-approves bare `WebSearch` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-WEBSEARCH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact bare `WebSearch` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for bare `WebSearch` in parsed `autoApprove` entries.
- Malicious Corpus: `mcp-autoapprove-unscoped-tool-family`
- Benign Corpus: `mcp-autoapprove-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC625 / MCP-AUTOAPPROVE-BASH` — MCP configuration auto-approves bare `Bash` through `autoApprove`

- Provider: `lintai-ai-security`
- Alias: `MCP-AUTOAPPROVE-BASH`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches exact bare `Bash` auto-approval in MCP client config.
- Deterministic Signal Basis: JsonSignals exact array-item detection for `autoApprove: ["Bash"]` on parsed MCP configuration.
- Malicious Corpus: `mcp-autoapprove-unscoped-tool-family`
- Benign Corpus: `mcp-autoapprove-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC626 / CLAUDE-BASH` — Claude settings permissions allow bare `Bash` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-BASH`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for exact bare `Bash` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for bare `Bash` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-bash-wildcard`
- Benign Corpus: `claude-settings-bash-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC627 / CLAUDE-READ` — Claude settings permissions allow bare `Read` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-READ`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for exact bare `Read` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for bare `Read` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-unscoped-tool-family`
- Benign Corpus: `claude-settings-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC628 / CLAUDE-WRITE` — Claude settings permissions allow bare `Write` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WRITE`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for exact bare `Write` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for bare `Write` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-unscoped-tool-family`
- Benign Corpus: `claude-settings-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC629 / CLAUDE-EDIT` — Claude settings permissions allow bare `Edit` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-EDIT`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for exact bare `Edit` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for bare `Edit` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-unscoped-tool-family`
- Benign Corpus: `claude-settings-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC630 / CLAUDE-GLOB` — Claude settings permissions allow bare `Glob` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GLOB`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for exact bare `Glob` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for bare `Glob` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-unscoped-tool-family`
- Benign Corpus: `claude-settings-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC631 / CLAUDE-GREP` — Claude settings permissions allow bare `Grep` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-GREP`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for exact bare `Grep` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for bare `Grep` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-unscoped-tool-family`
- Benign Corpus: `claude-settings-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC632 / CLAUDE-WEBFETCH` — Claude settings permissions allow bare `WebFetch` in a shared committed config

- Provider: `lintai-ai-security`
- Alias: `CLAUDE-WEBFETCH`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `governance`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `governance`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks shared Claude settings permissions for exact bare `WebFetch` grants.
- Deterministic Signal Basis: ClaudeSettingsSignals exact string detection for bare `WebFetch` inside permissions.allow on parsed Claude settings JSON.
- Malicious Corpus: `claude-settings-unscoped-tool-family`
- Benign Corpus: `claude-settings-unscoped-tool-family-specific-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC633` — Hook script attempts destructive root deletion

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit `rm`-style destructive root deletion payloads in executable hook lines.
- Deterministic Signal Basis: HookSignals shell-token analysis over non-comment hook lines for `rm` with recursive+force flags targeting `/` or using `--no-preserve-root`.
- Malicious Corpus: `hook-persistence-escalation`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC634` — Hook script accesses a sensitive system password file

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches direct access to sensitive password and sudo policy files in executable hook lines.
- Deterministic Signal Basis: HookSignals path detection over non-comment hook lines for `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/gshadow`, or `/etc/master.passwd`.
- Malicious Corpus: `hook-persistence-escalation`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC635` — Hook script writes to a shell profile startup file

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit shell startup profile modification in executable hook lines.
- Deterministic Signal Basis: HookSignals redirection-or-tee detection over `.bashrc`, `.bash_profile`, `.zshrc`, or `.profile` targets in non-comment hook lines.
- Malicious Corpus: `hook-persistence-escalation`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC636` — Hook script writes to SSH authorized_keys

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit writes to SSH `authorized_keys` in executable hook lines.
- Deterministic Signal Basis: HookSignals redirection-or-tee detection for `authorized_keys` targets in non-comment hook lines.
- Malicious Corpus: `hook-persistence-escalation`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC637` — MCP configuration command attempts destructive root deletion

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit `rm`-style destructive root deletion payloads.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `rm` with recursive+force flags targeting `/` or using `--no-preserve-root`.
- Malicious Corpus: `mcp-command-persistence-escalation`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC638` — MCP configuration command accesses a sensitive system password file

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for direct access to sensitive password and sudo policy files.
- Deterministic Signal Basis: JsonSignals command-plus-args path detection over ArtifactKind::McpConfig for `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/gshadow`, or `/etc/master.passwd`.
- Malicious Corpus: `mcp-command-persistence-escalation`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC639` — MCP configuration command writes to a shell profile startup file

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit writes to shell startup profile files.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig using redirection-or-tee targeting of `.bashrc`, `.bash_profile`, `.zshrc`, or `.profile`.
- Malicious Corpus: `mcp-command-persistence-escalation`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC640` — MCP configuration command writes to SSH authorized_keys

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit writes to SSH `authorized_keys`.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig using redirection-or-tee targeting of `authorized_keys`.
- Malicious Corpus: `mcp-command-persistence-escalation`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC641` — Claude settings command hook attempts destructive root deletion

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit `rm`-style destructive root deletion payloads.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `rm` with recursive+force flags targeting `/` or using `--no-preserve-root`.
- Malicious Corpus: `claude-settings-hook-persistence-escalation`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC642` — Claude settings command hook accesses a sensitive system password file

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for direct access to sensitive password and sudo policy files.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook path detection over committed hook entries with type == command for `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/gshadow`, or `/etc/master.passwd`.
- Malicious Corpus: `claude-settings-hook-persistence-escalation`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC643` — Claude settings command hook writes to a shell profile startup file

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit writes to shell startup profile files.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook analysis over committed hook entries with type == command using redirection-or-tee targeting of `.bashrc`, `.bash_profile`, `.zshrc`, or `.profile`.
- Malicious Corpus: `claude-settings-hook-persistence-escalation`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC644` — Claude settings command hook writes to SSH authorized_keys

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit writes to SSH `authorized_keys`.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook analysis over committed hook entries with type == command using redirection-or-tee targeting of `authorized_keys`.
- Malicious Corpus: `claude-settings-hook-persistence-escalation`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC645` — Plugin hook command attempts destructive root deletion

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit `rm`-style destructive root deletion payloads.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `rm` with recursive+force flags targeting `/` or using `--no-preserve-root`.
- Malicious Corpus: `plugin-hook-command-persistence-escalation`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC646` — Plugin hook command accesses a sensitive system password file

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for direct access to sensitive password and sudo policy files.
- Deterministic Signal Basis: JsonSignals command-string path detection over ArtifactKind::CursorPluginHooks for `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/gshadow`, or `/etc/master.passwd`.
- Malicious Corpus: `plugin-hook-command-persistence-escalation`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC647` — Plugin hook command writes to a shell profile startup file

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit writes to shell startup profile files.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks using redirection-or-tee targeting of `.bashrc`, `.bash_profile`, `.zshrc`, or `.profile`.
- Malicious Corpus: `plugin-hook-command-persistence-escalation`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC648` — Plugin hook command writes to SSH authorized_keys

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit writes to SSH `authorized_keys`.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks using redirection-or-tee targeting of `authorized_keys`.
- Malicious Corpus: `plugin-hook-command-persistence-escalation`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC649` — Hook script manipulates cron persistence

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit cron manipulation or cron file writes in executable hook lines.
- Deterministic Signal Basis: HookSignals command-or-write-target detection over non-comment hook lines for `crontab` mutation or writes to `/etc/cron*` and `/var/spool/cron`.
- Malicious Corpus: `hook-service-persistence`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC650` — Hook script registers a systemd service or unit for persistence

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit systemd service registration or unit-file writes in executable hook lines.
- Deterministic Signal Basis: HookSignals command-or-write-target detection over non-comment hook lines for `systemctl enable|link` or writes to systemd unit paths.
- Malicious Corpus: `hook-service-persistence`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC651` — Hook script registers a launchd plist for persistence

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit launchd registration or LaunchAgents/LaunchDaemons plist writes in executable hook lines.
- Deterministic Signal Basis: HookSignals command-or-write-target detection over non-comment hook lines for `launchctl load|bootstrap` or writes to LaunchAgents/LaunchDaemons plist paths.
- Malicious Corpus: `hook-service-persistence`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC652` — MCP configuration command manipulates cron persistence

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit cron persistence setup.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `crontab` mutation or writes to cron persistence paths.
- Malicious Corpus: `mcp-command-service-persistence`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC653` — MCP configuration command registers a systemd service or unit for persistence

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit systemd service registration or unit-file writes.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `systemctl enable|link` or writes to systemd unit paths.
- Malicious Corpus: `mcp-command-service-persistence`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC654` — MCP configuration command registers a launchd plist for persistence

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit launchd registration or LaunchAgents/LaunchDaemons plist writes.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `launchctl load|bootstrap` or writes to LaunchAgents/LaunchDaemons plist paths.
- Malicious Corpus: `mcp-command-service-persistence`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC655` — Claude settings command hook manipulates cron persistence

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit cron persistence setup.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `crontab` mutation or writes to cron persistence paths.
- Malicious Corpus: `claude-settings-hook-service-persistence`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC656` — Claude settings command hook registers a systemd service or unit for persistence

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit systemd service registration or unit-file writes.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `systemctl enable|link` or writes to systemd unit paths.
- Malicious Corpus: `claude-settings-hook-service-persistence`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC657` — Claude settings command hook registers a launchd plist for persistence

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit launchd registration or LaunchAgents/LaunchDaemons plist writes.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `launchctl load|bootstrap` or writes to LaunchAgents/LaunchDaemons plist paths.
- Malicious Corpus: `claude-settings-hook-service-persistence`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC658` — Plugin hook command manipulates cron persistence

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit cron persistence setup.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `crontab` mutation or writes to cron persistence paths.
- Malicious Corpus: `plugin-hook-command-service-persistence`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC659` — Plugin hook command registers a systemd service or unit for persistence

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit systemd service registration or unit-file writes.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `systemctl enable|link` or writes to systemd unit paths.
- Malicious Corpus: `plugin-hook-command-service-persistence`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC660` — Plugin hook command registers a launchd plist for persistence

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit launchd registration or LaunchAgents/LaunchDaemons plist writes.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `launchctl load|bootstrap` or writes to LaunchAgents/LaunchDaemons plist paths.
- Malicious Corpus: `plugin-hook-command-service-persistence`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC661` — Hook script performs an insecure permission change

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit insecure chmod payloads in executable hook lines.
- Deterministic Signal Basis: HookSignals shell-token analysis over non-comment hook lines for `chmod 777`, `chmod 0777`, or symbolic world-writable modes such as `a+rwx`.
- Malicious Corpus: `hook-privilege-escalation-payloads`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC662` — Hook script manipulates setuid or setgid permissions

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit setuid or setgid chmod payloads in executable hook lines.
- Deterministic Signal Basis: HookSignals shell-token analysis over non-comment hook lines for chmod octal modes with setuid/setgid bits or symbolic modes such as `u+s` and `g+s`.
- Malicious Corpus: `hook-privilege-escalation-payloads`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC663` — Hook script manipulates Linux capabilities

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit Linux capability manipulation payloads in executable hook lines.
- Deterministic Signal Basis: HookSignals shell-token analysis over non-comment hook lines for `setcap` or dangerous Linux capability tokens such as `cap_setuid` and `cap_sys_admin`.
- Malicious Corpus: `hook-privilege-escalation-payloads`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC664` — MCP configuration command performs an insecure permission change

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit insecure chmod payloads.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `chmod 777`, `chmod 0777`, or symbolic world-writable modes such as `a+rwx`.
- Malicious Corpus: `mcp-command-privilege-escalation-payloads`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC665` — MCP configuration command manipulates setuid or setgid permissions

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit setuid or setgid chmod payloads.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for chmod octal modes with setuid/setgid bits or symbolic modes such as `u+s` and `g+s`.
- Malicious Corpus: `mcp-command-privilege-escalation-payloads`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC666` — MCP configuration command manipulates Linux capabilities

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit Linux capability manipulation payloads.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `setcap` or dangerous Linux capability tokens such as `cap_setuid` and `cap_sys_admin`.
- Malicious Corpus: `mcp-command-privilege-escalation-payloads`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC667` — Claude settings command hook performs an insecure permission change

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit insecure chmod payloads.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `chmod 777`, `chmod 0777`, or symbolic world-writable modes such as `a+rwx`.
- Malicious Corpus: `claude-settings-hook-privilege-escalation-payloads`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC668` — Claude settings command hook manipulates setuid or setgid permissions

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit setuid or setgid chmod payloads.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for chmod octal modes with setuid/setgid bits or symbolic modes such as `u+s` and `g+s`.
- Malicious Corpus: `claude-settings-hook-privilege-escalation-payloads`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC669` — Claude settings command hook manipulates Linux capabilities

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit Linux capability manipulation payloads.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `setcap` or dangerous Linux capability tokens such as `cap_setuid` and `cap_sys_admin`.
- Malicious Corpus: `claude-settings-hook-privilege-escalation-payloads`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC670` — Plugin hook command performs an insecure permission change

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit insecure chmod payloads.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `chmod 777`, `chmod 0777`, or symbolic world-writable modes such as `a+rwx`.
- Malicious Corpus: `plugin-hook-command-privilege-escalation-payloads`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC671` — Plugin hook command manipulates setuid or setgid permissions

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit setuid or setgid chmod payloads.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for chmod octal modes with setuid/setgid bits or symbolic modes such as `u+s` and `g+s`.
- Malicious Corpus: `plugin-hook-command-privilege-escalation-payloads`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC672` — Plugin hook command manipulates Linux capabilities

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit Linux capability manipulation payloads.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `setcap` or dangerous Linux capability tokens such as `cap_setuid` and `cap_sys_admin`.
- Malicious Corpus: `plugin-hook-command-privilege-escalation-payloads`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC673` — Hook script posts secret material to a webhook endpoint

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit secret-bearing posts to well-known webhook endpoints in executable hook lines.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for secret markers plus webhook endpoint markers such as `hooks.slack.com/services/` or `discord.com/api/webhooks/`.
- Malicious Corpus: `hook-webhook-secret-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC674` — MCP configuration command appears to send secret material over the network

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit secret-bearing network exfil payloads.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for secret markers combined with network-capable command context.
- Malicious Corpus: `mcp-command-secret-exfil-payloads`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC675` — MCP configuration command sends secret material to an insecure http:// endpoint

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for secret-bearing exfil over insecure HTTP.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `http://` endpoints gated by concurrent secret markers in a network-capable command path.
- Malicious Corpus: `mcp-command-secret-exfil-payloads`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC676` — MCP configuration command posts secret material to a webhook endpoint

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for secret-bearing posts to webhook endpoints.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for secret markers plus webhook endpoint markers such as `hooks.slack.com/services/` or `discord.com/api/webhooks/`.
- Malicious Corpus: `mcp-command-secret-exfil-payloads`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC677` — Claude settings command hook appears to send secret material over the network

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit secret-bearing network exfil payloads.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for secret markers combined with network-capable command context.
- Malicious Corpus: `claude-settings-hook-secret-exfil-payloads`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC678` — Claude settings command hook sends secret material to an insecure http:// endpoint

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for secret-bearing exfil over insecure HTTP.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `http://` endpoints gated by concurrent secret markers in a network-capable command path.
- Malicious Corpus: `claude-settings-hook-secret-exfil-payloads`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC679` — Claude settings command hook posts secret material to a webhook endpoint

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for secret-bearing posts to webhook endpoints.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for secret markers plus webhook endpoint markers such as `hooks.slack.com/services/` or `discord.com/api/webhooks/`.
- Malicious Corpus: `claude-settings-hook-secret-exfil-payloads`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC680` — Plugin hook command appears to send secret material over the network

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit secret-bearing network exfil payloads.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for secret markers combined with network-capable command context.
- Malicious Corpus: `plugin-hook-command-secret-exfil-payloads`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC681` — Plugin hook command sends secret material to an insecure http:// endpoint

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for secret-bearing exfil over insecure HTTP.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `http://` endpoints gated by concurrent secret markers in a network-capable command path.
- Malicious Corpus: `plugin-hook-command-secret-exfil-payloads`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC682` — Plugin hook command posts secret material to a webhook endpoint

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for secret-bearing posts to webhook endpoints.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for secret markers plus webhook endpoint markers such as `hooks.slack.com/services/` or `discord.com/api/webhooks/`.
- Malicious Corpus: `plugin-hook-command-secret-exfil-payloads`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC683` — Hook script transfers a sensitive credential file to a remote destination

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit transfer of sensitive credential files to remote network or cloud-storage destinations in executable hook lines.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for sensitive file paths such as `.env`, `.aws/credentials`, `.ssh/id_rsa`, or `.kube/config` combined with transfer commands like `scp`, `sftp`, `rsync`, `curl`, `aws s3 cp`, `gsutil cp`, or `rclone copy`.
- Malicious Corpus: `hook-sensitive-file-exfil`, `hook-sensitive-file-rclone-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC684` — MCP configuration command transfers a sensitive credential file to a remote destination

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit transfer of sensitive credential files to remote destinations.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for sensitive file paths such as `.env`, `.aws/credentials`, `.ssh/id_rsa`, or `.kube/config` combined with transfer commands like `scp`, `sftp`, `rsync`, `curl`, `aws s3 cp`, `gsutil cp`, or `rclone copy`.
- Malicious Corpus: `mcp-command-sensitive-file-exfil`, `mcp-command-sensitive-file-rclone-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC685` — Claude settings command hook transfers a sensitive credential file to a remote destination

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit transfer of sensitive credential files to remote destinations.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for sensitive file paths such as `.env`, `.aws/credentials`, `.ssh/id_rsa`, or `.kube/config` combined with transfer commands like `scp`, `sftp`, `rsync`, `curl`, `aws s3 cp`, `gsutil cp`, or `rclone copy`.
- Malicious Corpus: `claude-settings-hook-sensitive-file-exfil`, `claude-settings-hook-sensitive-file-rclone-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC686` — Plugin hook command transfers a sensitive credential file to a remote destination

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit transfer of sensitive credential files to remote destinations.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for sensitive file paths such as `.env`, `.aws/credentials`, `.ssh/id_rsa`, or `.kube/config` combined with transfer commands like `scp`, `sftp`, `rsync`, `curl`, `aws s3 cp`, `gsutil cp`, or `rclone copy`.
- Malicious Corpus: `plugin-hook-command-sensitive-file-exfil`, `plugin-hook-command-sensitive-file-rclone-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC687` — Hook script reads local clipboard contents

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit clipboard-reading commands in executable hook lines.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard`.
- Malicious Corpus: `hook-local-data-theft`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC688` — Hook script accesses browser credential or cookie stores

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches direct access to browser credential or cookie storage files in executable hook lines.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`.
- Malicious Corpus: `hook-local-data-theft`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC689` — MCP configuration command reads local clipboard contents

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for clipboard-reading commands that can extract local user data.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard`.
- Malicious Corpus: `mcp-command-local-data-theft`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC690` — MCP configuration command accesses browser credential or cookie stores

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for direct access to browser credential or cookie storage files.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`.
- Malicious Corpus: `mcp-command-local-data-theft`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC691` — Claude settings command hook reads local clipboard contents

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for clipboard-reading behavior that can extract local user data.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard`.
- Malicious Corpus: `claude-settings-hook-local-data-theft`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC692` — Claude settings command hook accesses browser credential or cookie stores

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for direct access to browser credential or cookie storage files.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`.
- Malicious Corpus: `claude-settings-hook-local-data-theft`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC693` — Plugin hook command reads local clipboard contents

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for clipboard-reading behavior that can extract local user data.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard`.
- Malicious Corpus: `plugin-hook-command-local-data-theft`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC694` — Plugin hook command accesses browser credential or cookie stores

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for direct access to browser credential or cookie storage files.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`.
- Malicious Corpus: `plugin-hook-command-local-data-theft`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC695` — Hook script exfiltrates clipboard contents over the network

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches clipboard-reading commands that also transmit data to remote network endpoints in executable hook lines.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard` combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `hook-local-data-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC696` — Hook script exfiltrates browser credential or cookie store data

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches direct access to browser credential or cookie storage files combined with remote transfer behavior in executable hook lines.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `hook-local-data-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC697` — MCP configuration command exfiltrates clipboard contents over the network

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for clipboard-reading commands that also transmit captured data to remote destinations.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard` combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `mcp-command-local-data-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC698` — MCP configuration command exfiltrates browser credential or cookie store data

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for direct access to browser credential or cookie storage files combined with remote transfer behavior.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `mcp-command-local-data-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC699` — Claude settings command hook exfiltrates clipboard contents over the network

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for clipboard-reading behavior that also transmits captured data to remote destinations.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard` combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `claude-settings-hook-local-data-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC700` — Claude settings command hook exfiltrates browser credential or cookie store data

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for direct access to browser credential or cookie storage files combined with remote transfer behavior.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `claude-settings-hook-local-data-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC701` — Plugin hook command exfiltrates clipboard contents over the network

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for clipboard reads that also transmit captured data to remote destinations.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard` combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `plugin-hook-command-local-data-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC702` — Plugin hook command exfiltrates browser credential or cookie store data

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for direct access to browser credential or cookie storage files combined with remote transfer behavior.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `plugin-hook-command-local-data-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC703` — Hook script captures a screenshot or desktop image

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit screen capture utilities in executable hook lines.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`.
- Malicious Corpus: `hook-screen-capture`, `hook-screen-capture-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC704` — Hook script captures and exfiltrates a screenshot or desktop image

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit screen capture utilities combined with remote transfer behavior in executable hook lines.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `hook-screen-capture-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC705` — MCP configuration command captures a screenshot or desktop image

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit screen capture utilities.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`.
- Malicious Corpus: `mcp-command-screen-capture`, `mcp-command-screen-capture-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC706` — MCP configuration command captures and exfiltrates a screenshot or desktop image

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit screen capture utilities combined with remote transfer behavior.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `mcp-command-screen-capture-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC707` — Claude settings command hook captures a screenshot or desktop image

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit screen capture utilities.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`.
- Malicious Corpus: `claude-settings-hook-screen-capture`, `claude-settings-hook-screen-capture-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC708` — Claude settings command hook captures and exfiltrates a screenshot or desktop image

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit screen capture utilities combined with remote transfer behavior.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `claude-settings-hook-screen-capture-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC709` — Plugin hook command captures a screenshot or desktop image

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit screen capture utilities.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`.
- Malicious Corpus: `plugin-hook-command-screen-capture`, `plugin-hook-command-screen-capture-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC710` — Plugin hook command captures and exfiltrates a screenshot or desktop image

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit screen capture utilities combined with remote transfer behavior.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `plugin-hook-command-screen-capture-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC711` — Hook script captures a camera image or webcam stream

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit camera or webcam capture utilities in executable hook lines.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera or video device selectors.
- Malicious Corpus: `hook-device-capture`, `hook-device-capture-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC712` — Hook script records microphone or audio input

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit microphone or audio-recording utilities in executable hook lines.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for explicit audio capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with microphone or audio device selectors.
- Malicious Corpus: `hook-device-capture`, `hook-device-capture-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC713` — Hook script captures and exfiltrates camera or webcam data

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit camera or webcam capture utilities combined with remote transfer behavior in executable hook lines.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera or video device selectors, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `hook-device-capture-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC714` — Hook script records and exfiltrates microphone or audio input

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit microphone or audio-recording utilities combined with remote transfer behavior in executable hook lines.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for explicit audio capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with microphone or audio device selectors, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `hook-device-capture-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC715` — MCP configuration command captures a webcam or camera image

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit webcam or camera capture utilities.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera-oriented selectors like `video=`, `/dev/video`, `-f v4l2`, `-f video4linux2`, `webcam`, or `camera`.
- Malicious Corpus: `mcp-command-device-capture`, `mcp-command-device-capture-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC716` — MCP configuration command captures microphone audio

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit microphone recording utilities.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit microphone capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with audio-oriented selectors like `audio=`, `-f alsa`, `-f pulse`, `microphone`, or ` mic`.
- Malicious Corpus: `mcp-command-device-capture`, `mcp-command-device-capture-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC717` — MCP configuration command captures and exfiltrates webcam or camera data

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit webcam or camera capture utilities combined with remote transfer behavior.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera-oriented selectors like `video=`, `/dev/video`, `-f v4l2`, `-f video4linux2`, `webcam`, or `camera`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `mcp-command-device-capture-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC718` — MCP configuration command captures and exfiltrates microphone audio

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit microphone recording utilities combined with remote transfer behavior.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit microphone capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with audio-oriented selectors like `audio=`, `-f alsa`, `-f pulse`, `microphone`, or ` mic`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `mcp-command-device-capture-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC719` — Claude settings command hook captures a webcam or camera image

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit webcam or camera capture utilities.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera-oriented selectors like `video=`, `/dev/video`, `-f v4l2`, `-f video4linux2`, `webcam`, or `camera`.
- Malicious Corpus: `claude-settings-hook-device-capture`, `claude-settings-hook-device-capture-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC720` — Claude settings command hook captures microphone audio

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit microphone recording utilities.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit microphone capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with audio-oriented selectors like `audio=`, `-f alsa`, `-f pulse`, `microphone`, or ` mic`.
- Malicious Corpus: `claude-settings-hook-device-capture`, `claude-settings-hook-device-capture-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC721` — Claude settings command hook captures and exfiltrates webcam or camera data

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit webcam or camera capture utilities combined with remote transfer behavior.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera-oriented selectors like `video=`, `/dev/video`, `-f v4l2`, `-f video4linux2`, `webcam`, or `camera`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `claude-settings-hook-device-capture-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC722` — Claude settings command hook captures and exfiltrates microphone audio

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit microphone recording utilities combined with remote transfer behavior.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit microphone capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with audio-oriented selectors like `audio=`, `-f alsa`, `-f pulse`, `microphone`, or ` mic`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `claude-settings-hook-device-capture-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC723` — Plugin hook command captures a webcam or camera image

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit webcam or camera capture utilities.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera-oriented selectors like `video=`, `/dev/video`, `-f v4l2`, `-f video4linux2`, `webcam`, or `camera`.
- Malicious Corpus: `plugin-hook-command-device-capture`, `plugin-hook-command-device-capture-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC724` — Plugin hook command captures microphone audio

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit microphone recording utilities.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit microphone capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with audio-oriented selectors like `audio=`, `-f alsa`, `-f pulse`, `microphone`, or ` mic`.
- Malicious Corpus: `plugin-hook-command-device-capture`, `plugin-hook-command-device-capture-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC725` — Plugin hook command captures and exfiltrates webcam or camera data

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit webcam or camera capture utilities combined with remote transfer behavior.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera-oriented selectors like `video=`, `/dev/video`, `-f v4l2`, `-f video4linux2`, `webcam`, or `camera`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `plugin-hook-command-device-capture-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC726` — Plugin hook command captures and exfiltrates microphone audio

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit microphone recording utilities combined with remote transfer behavior.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit microphone capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with audio-oriented selectors like `audio=`, `-f alsa`, `-f pulse`, `microphone`, or ` mic`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `plugin-hook-command-device-capture-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC727` — Hook script captures keystrokes or keyboard input

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks hook shell lines for explicit keystroke capture utilities or keylogger markers.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`.
- Malicious Corpus: `hook-keylogger`, `hook-keylogger-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC728` — Hook script captures and exfiltrates keystrokes or keyboard input

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks hook shell lines for explicit keystroke capture utilities or keylogger markers combined with remote transfer behavior.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `hook-keylogger-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC729` — MCP configuration command captures keystrokes or keyboard input

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit keystroke capture utilities or keylogger markers.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`.
- Malicious Corpus: `mcp-command-keylogger`, `mcp-command-keylogger-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC730` — MCP configuration command captures and exfiltrates keystrokes or keyboard input

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit keystroke capture utilities or keylogger markers combined with remote transfer behavior.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `mcp-command-keylogger-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC731` — Claude settings command hook captures keystrokes or keyboard input

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit keystroke capture utilities or keylogger markers.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`.
- Malicious Corpus: `claude-settings-hook-keylogger`, `claude-settings-hook-keylogger-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC732` — Claude settings command hook captures and exfiltrates keystrokes or keyboard input

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit keystroke capture utilities or keylogger markers combined with remote transfer behavior.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `claude-settings-hook-keylogger-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC733` — Plugin hook command captures keystrokes or keyboard input

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit keystroke capture utilities or keylogger markers.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`.
- Malicious Corpus: `plugin-hook-command-keylogger`, `plugin-hook-command-keylogger-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC734` — Plugin hook command captures and exfiltrates keystrokes or keyboard input

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit keystroke capture utilities or keylogger markers combined with remote transfer behavior.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.
- Malicious Corpus: `plugin-hook-command-keylogger-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC735` — Hook script dumps environment variables or shell state

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks hook shell lines for explicit environment or shell-state enumeration commands.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`.
- Malicious Corpus: `hook-env-dump`, `hook-env-dump-exfil`, `hook-env-dump-cloud-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC736` — Hook script dumps and exfiltrates environment variables or shell state

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks hook shell lines for explicit environment or shell-state enumeration commands combined with remote transfer behavior.
- Deterministic Signal Basis: HookSignals command-line analysis over non-comment hook lines for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`, combined with remote sinks such as `curl`, `wget`, `scp`, `sftp`, `rsync`, `nc`, `aws s3 cp`, `gsutil cp`, `rclone copy`, or HTTP(S) endpoints.
- Malicious Corpus: `hook-env-dump-exfil`, `hook-env-dump-cloud-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC737` — MCP configuration command dumps environment variables or shell state

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit environment or shell-state enumeration commands.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`.
- Malicious Corpus: `mcp-command-env-dump`, `mcp-command-env-dump-exfil`, `mcp-command-env-dump-cloud-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC738` — MCP configuration command dumps and exfiltrates environment variables or shell state

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP launch paths for explicit environment or shell-state enumeration commands combined with remote transfer behavior.
- Deterministic Signal Basis: JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`, combined with remote sinks such as `curl`, `wget`, `scp`, `sftp`, `rsync`, `nc`, `aws s3 cp`, `gsutil cp`, `rclone copy`, or HTTP(S) endpoints.
- Malicious Corpus: `mcp-command-env-dump-exfil`, `mcp-command-env-dump-cloud-exfil`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC739` — Claude settings command hook dumps environment variables or shell state

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit environment or shell-state enumeration commands.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`.
- Malicious Corpus: `claude-settings-hook-env-dump`, `claude-settings-hook-env-dump-exfil`, `claude-settings-hook-env-dump-cloud-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC740` — Claude settings command hook dumps and exfiltrates environment variables or shell state

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `claude`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit environment or shell-state enumeration commands combined with remote transfer behavior.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`, combined with remote sinks such as `curl`, `wget`, `scp`, `sftp`, `rsync`, `nc`, `aws s3 cp`, `gsutil cp`, `rclone copy`, or HTTP(S) endpoints.
- Malicious Corpus: `claude-settings-hook-env-dump-exfil`, `claude-settings-hook-env-dump-cloud-exfil`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC741` — Plugin hook command dumps environment variables or shell state

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit environment or shell-state enumeration commands.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`.
- Malicious Corpus: `plugin-hook-command-env-dump`, `plugin-hook-command-env-dump-exfil`, `plugin-hook-command-env-dump-cloud-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC742` — Plugin hook command dumps and exfiltrates environment variables or shell state

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`, `mcp`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit environment or shell-state enumeration commands combined with remote transfer behavior.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`, combined with remote sinks such as `curl`, `wget`, `scp`, `sftp`, `rsync`, `nc`, `aws s3 cp`, `gsutil cp`, `rclone copy`, or HTTP(S) endpoints.
- Malicious Corpus: `plugin-hook-command-env-dump-exfil`, `plugin-hook-command-env-dump-cloud-exfil`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC743` — package.json defines a dangerous install-time lifecycle script

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed package.json install-time lifecycle hooks for explicit download-exec, eval, or npm-explore shell behavior.
- Deterministic Signal Basis: JsonSignals package manifest analysis over `scripts.preinstall|install|postinstall|prepare` values for download-exec patterns, `eval`, or `npm explore` shell execution.
- Malicious Corpus: `package-manifest-dangerous-lifecycle-script`
- Benign Corpus: `package-manifest-safe-lifecycle-script`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC744` — package.json installs a dependency from a git or forge shortcut source

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed package.json dependency sections for direct git or forge shortcut sources that bypass the normal registry release path.
- Deterministic Signal Basis: JsonSignals package manifest analysis over dependency sections for specs starting with `git://`, `git+https://`, `git+ssh://`, `github:`, `gitlab:`, or `bitbucket:`.
- Malicious Corpus: `package-manifest-git-url-dependency`
- Benign Corpus: `package-manifest-registry-dependency-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC745` — package.json uses an unbounded dependency version like * or latest

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed package.json dependency sections for unbounded or mutable selectors that undermine reproducibility.
- Deterministic Signal Basis: JsonSignals package manifest analysis over dependency sections for exact specs equal to `*` or `latest`.
- Malicious Corpus: `package-manifest-unbounded-dependency`
- Benign Corpus: `package-manifest-pinned-dependency-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC746` — Dockerfile RUN downloads remote code and executes it

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `dockerfile`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Dockerfiles for RUN instructions that fetch remote content and pipe it into a shell.
- Deterministic Signal Basis: DockerfileSignals line analysis over `RUN` instructions for download-exec patterns such as `curl` or `wget` piped to `sh` or `bash`.
- Malicious Corpus: `dockerfile-run-download-exec`
- Benign Corpus: `dockerfile-safe-run`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC747` — Dockerfile final stage explicitly runs as root

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `dockerfile`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks the final Dockerfile stage for an explicit root runtime user while ignoring earlier build stages that later drop privileges.
- Deterministic Signal Basis: DockerfileSignals tracks `FROM` stage boundaries and the effective explicit `USER` in the final stage, flagging only `root`, `root:*`, `0`, or `0:*` in the last stage.
- Malicious Corpus: `dockerfile-final-stage-root-user`
- Benign Corpus: `dockerfile-final-stage-nonroot-user`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC748` — Docker Compose service enables privileged container runtime or host namespace access

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `docker-compose`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Docker Compose service definitions for overt host-integrated runtime controls such as privileged mode, dangerous capability grants, or host namespace access.
- Deterministic Signal Basis: DockerComposeSignals combines semantic confirmation of a Compose `services` map with indentation-aware line matching for `privileged: true`, `cap_add: [ALL|SYS_ADMIN]`, and `network_mode`/`pid`/`ipc: host` inside service blocks.
- Malicious Corpus: `docker-compose-privileged-runtime`
- Benign Corpus: `docker-compose-safe-runtime`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC749` — Dockerfile FROM uses a mutable registry image without a digest pin

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `dockerfile`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Dockerfiles for registry-distributed base images that are not digest pinned.
- Deterministic Signal Basis: DockerfileSignals exact `FROM` token analysis with conservative registry-image matching and digest-pin detection on the selected image token.
- Malicious Corpus: `dockerfile-mutable-base-image`
- Benign Corpus: `dockerfile-digest-pinned-base-image`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC750` — Docker Compose service image uses a mutable registry reference without a digest pin

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `docker-compose`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Docker Compose services for registry-distributed image references that are not digest pinned.
- Deterministic Signal Basis: DockerComposeSignals combines semantic confirmation of `services.*.image` values with indentation-aware line matching and conservative registry-image plus digest-pin detection.
- Malicious Corpus: `docker-compose-mutable-image`
- Benign Corpus: `docker-compose-digest-pinned-image`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC751` — Dockerfile FROM uses a latest or implicit-latest image tag

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `dockerfile`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Dockerfiles for base images that rely on `latest` or the implicit default latest tag.
- Deterministic Signal Basis: DockerfileSignals exact `FROM` token analysis with prior-stage alias tracking plus deterministic detection of explicit `:latest` tags or missing tags on non-digest image references.
- Malicious Corpus: `dockerfile-latest-base-image`
- Benign Corpus: `dockerfile-tagged-base-image-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC752` — Docker Compose service image uses a latest or implicit-latest tag

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `docker-compose`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Docker Compose services for images that rely on `latest` or the implicit default latest tag.
- Deterministic Signal Basis: DockerComposeSignals semantic `services.*.image` detection combined with indentation-aware line matching and deterministic detection of explicit `:latest` tags or missing tags on non-digest image references.
- Malicious Corpus: `docker-compose-latest-image`
- Benign Corpus: `docker-compose-tagged-image-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC753` — package.json installs a dependency from a direct archive URL source

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `supply-chain`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `supply-chain`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed package.json dependency sections for direct archive URL sources that bypass the normal registry release path.
- Deterministic Signal Basis: JsonSignals package manifest analysis over dependency sections for direct `http://` or `https://` archive-like specs ending in `.tgz`, `.tar.gz`, `.tar`, `.zip`, or containing `/tarball/`.
- Malicious Corpus: `package-manifest-direct-url-dependency`
- Benign Corpus: `package-manifest-registry-archive-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC754` — Devcontainer config defines a host-side initializeCommand

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `devcontainer`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed devcontainer configs for explicit host-side execution via non-empty `initializeCommand`, which runs on the local host before container startup.
- Deterministic Signal Basis: DevcontainerSignals semantic JSON parsing plus exact value-span resolution for a non-empty top-level `initializeCommand` in `.devcontainer.json` or `.devcontainer/devcontainer.json`.
- Malicious Corpus: `devcontainer-initialize-command-host`
- Benign Corpus: `devcontainer-no-initialize-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

### `SEC755` — Devcontainer config bind-mounts sensitive local host material

- Provider: `lintai-ai-security`
- Alias: `none`
- Scope: `per_file`
- Surface: `devcontainer`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `threat-review`
- Default Confidence: `High`
- Tier: `Stable`
- Default Presets: `threat-review`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed devcontainer configs for explicit host-exposure through bind mounts of sensitive local material such as SSH keys, cloud credentials, kubeconfig, or docker.sock.
- Deterministic Signal Basis: DevcontainerSignals semantic JSON parsing plus exact value-span resolution for sensitive bind mounts in `workspaceMount`, `mounts`, or Docker-style `runArgs` mount flags.
- Malicious Corpus: `devcontainer-sensitive-bind-mount`
- Benign Corpus: `devcontainer-safe-workspace-mount`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as an explicit threat-review control: high-signal malicious, credential-bearing, or spyware-like behavior that stays opt-in rather than shaping the quiet default.

## Provider: `lintai-policy-mismatch`

### `SEC401 / POLICY-EXEC-MISMATCH` — Project policy forbids execution, but repository contains executable behavior

- Provider: `lintai-policy-mismatch`
- Alias: `POLICY-EXEC-MISMATCH`
- Scope: `workspace`
- Surface: `workspace`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `compat`
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
- Public Lane: `compat`
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
- Public Lane: `compat`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `compat`
- Remediation: `none`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Needs workspace-level capability-conflict precision review and linked graduation corpus before promotion to Stable.
- Promotion Requirements: Needs workspace precision review, linked benign/malicious corpus proof, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

## Provider: `lintai-dep-vulns`

### `SEC756` — Installed npm dependency version matches an offline vulnerability advisory

- Provider: `lintai-dep-vulns`
- Alias: `none`
- Scope: `workspace`
- Surface: `workspace`
- Detection: `structural`
- Default Severity: `Warn`
- Public Lane: `advisory`
- Default Confidence: `High`
- Tier: `Preview`
- Default Presets: `advisory`
- Remediation: `suggestion`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Initial advisory snapshot coverage is intentionally small in the first release and needs broader snapshot discipline before Stable.
- Promotion Requirements: Needs larger advisory snapshot coverage, cross-lockfile corpus proof, and stable review of package/version matching before promotion to Stable.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.
