# Security Rules Catalog

> Generated file. Do not edit by hand.
> Source: `lintai-cli` shipped rule inventory aggregated from provider catalogs.

Canonical catalog for the shipped security rules currently exposed by:
- `lintai-ai-security`
- `lintai-policy-mismatch`

## Summary

| Code | Summary | Tier | Lifecycle | Severity | Scope | Surface | Detection | Remediation |
|---|---|---|---|---|---|---|---|---|
| `SEC101` | Hidden HTML comment contains dangerous agent instructions | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `safe_fix` |
| `SEC102` | Markdown contains remote download-and-execute instruction outside code blocks | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `suggestion` |
| `SEC103` | Hidden HTML comment contains remote download-and-execute instruction | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `safe_fix` |
| `SEC104` | Markdown contains a base64-decoded executable payload outside code blocks | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` |
| `SEC105` | Markdown instructions reference parent-directory traversal for file access | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` |
| `SEC201` | Hook script downloads remote code and executes it | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `suggestion` |
| `SEC202` | Hook script appears to exfiltrate secrets through a network call | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `suggestion` |
| `SEC203` | Hook script sends secret material to an insecure http:// endpoint | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `suggestion` |
| `SEC204` | Hook script disables TLS or certificate verification for a network call | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` |
| `SEC205` | Hook script embeds static authentication material in a network call | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `message_only` |
| `SEC206` | Hook script decodes a base64 payload and executes it | Stable | `stable_gated` | Deny | `per_file` | `hook` | `structural` | `suggestion` |
| `SEC301` | MCP configuration shells out through sh -c or bash -c | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC302` | Configuration contains an insecure http:// endpoint | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `suggestion` |
| `SEC303` | MCP configuration passes through credential environment variables | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC304` | Configuration disables TLS or certificate verification | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC305` | Configuration embeds static authentication material in a connection or auth value | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC306` | JSON configuration description contains override-style hidden instructions | Preview | `preview_blocked` | Warn | `per_file` | `json` | `heuristic` | `message_only` |
| `SEC307` | Configuration forwards sensitive environment variable references | Preview | `preview_blocked` | Warn | `per_file` | `json` | `heuristic` | `message_only` |
| `SEC308` | Configuration points at a suspicious remote endpoint | Preview | `preview_blocked` | Warn | `per_file` | `json` | `heuristic` | `message_only` |
| `SEC309` | Configuration commits literal secret material in env, auth, or header values | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC310` | Configuration endpoint targets a metadata or private-network host literal | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC311` | Cursor plugin manifest contains an unsafe absolute or parent-traversing path | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC312` | Markdown contains committed private key material | Stable | `stable_gated` | Warn | `per_file` | `markdown` | `structural` | `message_only` |
| `SEC313` | Fenced shell example pipes remote content directly into a shell | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` |
| `SEC314` | MCP-style tool descriptor is missing required machine fields | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` |
| `SEC315` | MCP-style tool descriptor collection contains duplicate tool names | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` |
| `SEC316` | OpenAI strict tool schema omits recursive additionalProperties: false | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` |
| `SEC317` | OpenAI strict tool schema does not require every declared property | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` |
| `SEC318` | Anthropic strict tool input schema omits additionalProperties: false | Stable | `stable_gated` | Warn | `per_file` | `tool_json` | `structural` | `message_only` |
| `SEC319` | server.json remotes entry uses an insecure or non-public remote URL | Stable | `stable_gated` | Warn | `per_file` | `server_json` | `structural` | `message_only` |
| `SEC320` | server.json remotes URL references an undefined template variable | Stable | `stable_gated` | Warn | `per_file` | `server_json` | `structural` | `message_only` |
| `SEC321` | server.json remotes header commits literal authentication material | Stable | `stable_gated` | Warn | `per_file` | `server_json` | `structural` | `message_only` |
| `SEC322` | server.json remotes header value references an undefined template variable | Stable | `stable_gated` | Warn | `per_file` | `server_json` | `structural` | `message_only` |
| `SEC323` | server.json auth header carries material without an explicit secret flag | Preview | `preview_blocked` | Warn | `per_file` | `server_json` | `structural` | `message_only` |
| `SEC324` | GitHub Actions workflow uses a third-party action that is not pinned to a full commit SHA | Stable | `stable_gated` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` |
| `SEC325` | GitHub Actions workflow interpolates untrusted expression data directly inside a run command | Preview | `preview_blocked` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` |
| `SEC326` | GitHub Actions pull_request_target workflow checks out untrusted pull request head content | Stable | `stable_gated` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` |
| `SEC327` | GitHub Actions workflow grants GITHUB_TOKEN write-all permissions | Stable | `stable_gated` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` |
| `SEC328` | GitHub Actions workflow combines explicit write-capable permissions with a third-party action | Preview | `preview_blocked` | Warn | `per_file` | `github_workflow` | `structural` | `message_only` |
| `SEC329` | MCP configuration launches tooling through a mutable package runner | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC330` | MCP configuration command downloads remote content and pipes it into a shell | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC331` | MCP configuration command disables TLS verification in a network-capable execution path | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC335` | AI-native markdown contains a direct cloud metadata-service access example | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` |
| `SEC336` | Repo-local MCP client config loads a broad dotenv-style envFile | Preview | `preview_blocked` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC337` | MCP configuration launches Docker with an image reference that is not digest-pinned | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC338` | MCP configuration launches Docker with a bind mount of sensitive host material | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC339` | MCP configuration launches Docker with a host-escape or privileged runtime flag | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC340` | Claude settings command hook uses a mutable package launcher | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` |
| `SEC341` | Claude settings command hook downloads remote content and pipes it into a shell | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` |
| `SEC342` | Claude settings command hook disables TLS verification in a network-capable execution path | Stable | `stable_gated` | Warn | `per_file` | `claude_settings` | `structural` | `message_only` |
| `SEC343` | Plugin hook command uses a mutable package launcher | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC344` | Plugin hook command downloads remote content and pipes it into a shell | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC345` | Plugin hook command disables TLS verification in a network-capable execution path | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC346` | MCP configuration forces Docker to refresh from a mutable registry source | Stable | `stable_gated` | Warn | `per_file` | `json` | `structural` | `message_only` |
| `SEC347` | AI-native markdown example launches MCP through a mutable package runner | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` |
| `SEC348` | AI-native markdown Docker example uses a mutable registry image | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` |
| `SEC349` | AI-native markdown Docker example uses a host-escape or privileged runtime pattern | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `structural` | `message_only` |
| `SEC350` | Instruction markdown promotes untrusted external content to developer/system-level instructions | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` |
| `SEC351` | AI-native instruction explicitly disables user approval or confirmation | Preview | `preview_blocked` | Warn | `per_file` | `markdown` | `heuristic` | `message_only` |
| `SEC401` | Project policy forbids execution, but repository contains executable behavior | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` |
| `SEC402` | Project policy forbids network access, but repository contains network behavior | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` |
| `SEC403` | Skill frontmatter capabilities conflict with project policy | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` |

## Top-Important AI Security Rules (2026-03-29)

### Обновлённый top-3 приоритизации

Если поднимать только три новых AI/MCP/agent-skills правила в ближайший top-3, приоритет должен быть таким:

| Rank | Rule | Axis | Почему поднимать сейчас | Уверенность | Надёжность |
|---|---|---|---|---:|---:|
| 1 | `SEC:ai-trusted-context-boundary` | Trust boundary | Закрывает базовую ошибку класса agentic systems: tool output, MCP metadata, RAG content и plugin responses не должны становиться system/developer instructions. Это наиболее общий и самый частый confused-deputy/prompt-injection boundary, который бьёт сразу по skills, MCP и plugin surfaces. | `10/10` | `10/10` |
| 2 | `SEC:ai-manifest-integrity` | Manifest integrity | Без проверки подписи, digest/hash pinning и происхождения skill/plugin/tool manifests любой последующий schema- или policy-check можно обойти подменой артефакта до загрузки. Это прямой supply-chain choke point. | `10/10` | `9/10` |
| 3 | `SEC:ai-tool-intent-gate` | Runtime control | На рантайме нужен deny-by-default слой: сверка цели, scope, destructive action policy, cost/rate limits и explicit approval перед tool execution. Это сдерживает blast radius даже когда boundary и manifest уже частично обойдены. | `9/10` | `9/10` |

### Rationale

- `SEC:ai-trusted-context-boundary` стоит первым, потому что это первичный барьер между недоверенным контентом и управляющими инструкциями; без него остальные контроли слишком легко обходятся через reinterpretation attack surface.
- `SEC:ai-manifest-integrity` стоит вторым, потому что защищает точку входа артефакта до выполнения: если манифест или descriptor подменён, trust model уже сломана до старта runtime.
- `SEC:ai-tool-intent-gate` стоит третьим, потому что это лучший прикладной runtime control для v0.1/v0.2: он ограничивает реальные действия, а не только их аудит post factum.

### Почему не `SEC:ai-runtime-provenance` в top-3

- `SEC:ai-runtime-provenance` важен, но для ближайшего top-3 он слабее как immediate control: provenance и attestation чаще улучшают расследование, доверие и policy enforcement, чем напрямую режут execution blast radius в момент вызова.
- Поэтому оптимальный порядок сейчас: boundary first, artifact integrity second, execution control third; provenance идёт сразу следом как top-4 кандидат. Уверенность: `9/10`, Надёжность: `9/10`.

## Provider: `lintai-ai-security`

### `SEC101` — Hidden HTML comment contains dangerous agent instructions

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `safe_fix`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on suspicious phrase heuristics inside hidden HTML comments.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC102` — Markdown contains remote download-and-execute instruction outside code blocks

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `suggestion`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on prose command heuristics outside code blocks.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC103` — Hidden HTML comment contains remote download-and-execute instruction

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `safe_fix`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on hidden-comment command heuristics rather than a structural execution model.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC104` — Markdown contains a base64-decoded executable payload outside code blocks

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on prose base64-and-exec text heuristics.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC105` — Markdown instructions reference parent-directory traversal for file access

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on prose path-traversal and access-verb heuristics.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC201` — Hook script downloads remote code and executes it

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit remote download-and-execute behavior in hook shell lines, not prose text.
- Deterministic Signal Basis: HookSignals download-and-execute observation over non-comment hook lines.
- Malicious Corpus: `hook-download-exec`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC202` — Hook script appears to exfiltrate secrets through a network call

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches secret-bearing network exfil behavior in executable hook lines.
- Deterministic Signal Basis: HookSignals secret exfil observation from network markers plus secret markers on non-comment lines.
- Malicious Corpus: `hook-secret-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC203` — Hook script sends secret material to an insecure http:// endpoint

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches insecure HTTP transport on a secret-bearing hook exfil path.
- Deterministic Signal Basis: HookSignals precise http:// span observation gated by concurrent secret exfil markers.
- Malicious Corpus: `hook-plain-http-secret-exfil`
- Benign Corpus: `cursor-plugin-clean-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC204` — Hook script disables TLS or certificate verification for a network call

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit TLS verification bypass tokens in executable hook network context.
- Deterministic Signal Basis: HookSignals TLS-bypass token observation over parsed hook line tokens and network context.
- Malicious Corpus: `hook-tls-bypass`
- Benign Corpus: `cursor-plugin-tls-verified-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC205` — Hook script embeds static authentication material in a network call

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches literal static auth material in hook URLs or authorization headers.
- Deterministic Signal Basis: HookSignals userinfo/header literal extraction excluding dynamic references.
- Malicious Corpus: `hook-static-auth-userinfo`
- Benign Corpus: `hook-auth-dynamic-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC206` — Hook script decodes a base64 payload and executes it

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `hook`
- Detection: `structural`
- Default Severity: `Deny`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit base64 decode-and-execute behavior in executable hook lines.
- Deterministic Signal Basis: HookSignals base64-decode plus exec observation over non-comment hook lines.
- Malicious Corpus: `hook-base64-exec`
- Benign Corpus: `hook-base64-decode-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC301` — MCP configuration shells out through sh -c or bash -c

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit shell-wrapper command structure in JSON config.
- Deterministic Signal Basis: JsonSignals command and args structure observation for sh -c or bash -c wrappers.
- Malicious Corpus: `mcp-shell-wrapper`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC302` — Configuration contains an insecure http:// endpoint

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `suggestion`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit insecure http:// endpoints in configuration values.
- Deterministic Signal Basis: JsonSignals precise http:// endpoint span resolution from parsed JSON location map.
- Malicious Corpus: `mcp-plain-http`
- Benign Corpus: `mcp-trusted-endpoint-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC303` — MCP configuration passes through credential environment variables

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit credential env passthrough by key inside configuration env maps.
- Deterministic Signal Basis: JsonSignals env-map key observation for credential passthrough keys.
- Malicious Corpus: `mcp-credential-env-passthrough`
- Benign Corpus: `mcp-safe-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC304` — Configuration disables TLS or certificate verification

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit TLS or certificate verification disable flags in configuration.
- Deterministic Signal Basis: JsonSignals boolean and key observation for trust-verification disable settings.
- Malicious Corpus: `mcp-trust-verification-disabled`
- Benign Corpus: `mcp-trust-verified-basic`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC305` — Configuration embeds static authentication material in a connection or auth value

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches literal static auth material embedded directly in configuration values.
- Deterministic Signal Basis: JsonSignals literal authorization or userinfo span extraction excluding dynamic placeholders.
- Malicious Corpus: `mcp-static-authorization`
- Benign Corpus: `mcp-authorization-placeholder-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC306` — JSON configuration description contains override-style hidden instructions

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on descriptive-field phrase heuristics in JSON text.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC307` — Configuration forwards sensitive environment variable references

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on sensitive env-name heuristics in forwarded references.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC308` — Configuration points at a suspicious remote endpoint

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on suspicious host-marker heuristics for remote endpoints.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC309` — Configuration commits literal secret material in env, auth, or header values

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches literal secret material committed into env, header, or auth-like JSON fields.
- Deterministic Signal Basis: JsonSignals literal secret observation over env, header, and auth-like keys excluding dynamic placeholders.
- Malicious Corpus: `mcp-literal-secret-config`
- Benign Corpus: `mcp-secret-placeholder-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC310` — Configuration endpoint targets a metadata or private-network host literal

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit metadata-service or private-network host literals in endpoint-like configuration values.
- Deterministic Signal Basis: JsonSignals endpoint-host extraction over URL-like endpoint fields with metadata/private-host classification.
- Malicious Corpus: `mcp-metadata-host-literal`
- Benign Corpus: `mcp-public-endpoint-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC311` — Cursor plugin manifest contains an unsafe absolute or parent-traversing path

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches absolute or parent-traversing paths in committed Cursor plugin manifest path fields.
- Deterministic Signal Basis: JsonSignals plugin-manifest path observation limited to known plugin path fields.
- Malicious Corpus: `cursor-plugin-unsafe-path`
- Benign Corpus: `cursor-plugin-safe-paths`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC312` — Markdown contains committed private key material

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Matches explicit committed private-key PEM markers inside agent markdown surfaces.
- Deterministic Signal Basis: MarkdownSignals private-key marker observation across parsed markdown regions excluding placeholder examples.
- Malicious Corpus: `skill-private-key-pem`
- Benign Corpus: `skill-public-key-pem-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC313` — Fenced shell example pipes remote content directly into a shell

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Depends on fenced shell-example command heuristics and still needs broader external precision review.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC314` — MCP-style tool descriptor is missing required machine fields

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `tool_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks unambiguous MCP-style tool descriptors for missing machine fields instead of relying on prose heuristics.
- Deterministic Signal Basis: ToolJsonSignals MCP collection analysis over parsed tool descriptor JSON.
- Malicious Corpus: `tool-json-mcp-missing-machine-fields`
- Benign Corpus: `tool-json-mcp-valid-tool`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC315` — MCP-style tool descriptor collection contains duplicate tool names

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `tool_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks structured MCP-style tool collections for duplicate names that can shadow one another.
- Deterministic Signal Basis: ToolJsonSignals duplicate-name detection over MCP-style tool collections.
- Malicious Corpus: `tool-json-duplicate-tool-names`
- Benign Corpus: `tool-json-unique-tool-names`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC316` — OpenAI strict tool schema omits recursive additionalProperties: false

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `tool_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks OpenAI strict tool schemas for recursive object locking with additionalProperties: false.
- Deterministic Signal Basis: ToolJsonSignals recursive schema walk over OpenAI function.parameters when strict mode is enabled.
- Malicious Corpus: `tool-json-openai-strict-additional-properties`
- Benign Corpus: `tool-json-openai-strict-locked`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC317` — OpenAI strict tool schema does not require every declared property

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `tool_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks OpenAI strict tool schemas for full required coverage of declared properties.
- Deterministic Signal Basis: ToolJsonSignals recursive required-versus-properties comparison over strict OpenAI schemas.
- Malicious Corpus: `tool-json-openai-strict-required-coverage`
- Benign Corpus: `tool-json-openai-strict-required-complete`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC318` — Anthropic strict tool input schema omits additionalProperties: false

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `tool_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks Anthropic strict tool input_schema objects for explicit additionalProperties: false.
- Deterministic Signal Basis: ToolJsonSignals recursive schema walk over Anthropic input_schema when strict mode is enabled.
- Malicious Corpus: `tool-json-anthropic-strict-open-schema`
- Benign Corpus: `tool-json-anthropic-strict-locked`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC319` — server.json remotes entry uses an insecure or non-public remote URL

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `server_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks MCP registry remotes[] URLs for insecure HTTP and non-public host literals without inspecting local package transport URLs.
- Deterministic Signal Basis: ServerJsonSignals remotes[] URL analysis limited to streamable-http and sse entries.
- Malicious Corpus: `server-json-insecure-remote-url`
- Benign Corpus: `server-json-loopback-package-transport-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC320` — server.json remotes URL references an undefined template variable

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `server_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks server.json remotes[] URL templates against variables defined on the same remote entry.
- Deterministic Signal Basis: ServerJsonSignals placeholder extraction over remotes[] URLs compared with remotes[].variables keys.
- Malicious Corpus: `server-json-unresolved-remote-variable`
- Benign Corpus: `server-json-remote-variable-defined`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC321` — server.json remotes header commits literal authentication material

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `server_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks remotes[].headers[] auth-like values for literal bearer/basic material or literal API key style values.
- Deterministic Signal Basis: ServerJsonSignals inspects remotes[].headers[] auth-like names and value literals without looking at packages[].transport.
- Malicious Corpus: `server-json-literal-auth-header`
- Benign Corpus: `server-json-auth-header-placeholder-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC322` — server.json remotes header value references an undefined template variable

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `server_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks auth-like remotes[].headers[].value placeholders against variables defined on the same header object.
- Deterministic Signal Basis: ServerJsonSignals placeholder extraction over remotes[].headers[].value compared with headers[].variables keys.
- Malicious Corpus: `server-json-unresolved-header-variable`
- Benign Corpus: `server-json-header-variable-defined`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC323` — server.json auth header carries material without an explicit secret flag

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `server_json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Secret policy expectations can vary across registry producers, so the first release keeps this as guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC324` — GitHub Actions workflow uses a third-party action that is not pinned to a full commit SHA

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks workflow uses: entries for third-party actions that rely on mutable refs instead of immutable commit SHAs; positioned as a supply-chain hardening control rather than a direct exploit claim.
- Deterministic Signal Basis: GithubWorkflowSignals line-level uses: extraction gated by semantically confirmed workflow YAML.
- Malicious Corpus: `github-workflow-third-party-unpinned-action`
- Benign Corpus: `github-workflow-pinned-third-party-action`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.

### `SEC325` — GitHub Actions workflow interpolates untrusted expression data directly inside a run command

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Shell safety depends on how the interpolated expression is consumed inside the run command.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC326` — GitHub Actions pull_request_target workflow checks out untrusted pull request head content

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks pull_request_target workflows for actions/checkout steps that explicitly pull untrusted pull request head refs instead of the safer default merge context.
- Deterministic Signal Basis: GithubWorkflowSignals event gating plus line-level checkout ref extraction for pull_request_target workflows.
- Malicious Corpus: `github-workflow-pull-request-target-head-checkout`
- Benign Corpus: `github-workflow-pull-request-target-safe-checkout`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC327` — GitHub Actions workflow grants GITHUB_TOKEN write-all permissions

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks workflow permissions for the explicit write-all shortcut, which exceeds least-privilege guidance for GITHUB_TOKEN.
- Deterministic Signal Basis: GithubWorkflowSignals line-level permissions extraction for semantically confirmed workflow YAML.
- Malicious Corpus: `github-workflow-write-all-permissions`
- Benign Corpus: `github-workflow-read-only-permissions`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC328` — GitHub Actions workflow combines explicit write-capable permissions with a third-party action

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `github_workflow`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Write-capable token scopes and third-party action usage are compositional and need more corpus-backed precision review before a stable launch.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC329` — MCP configuration launches tooling through a mutable package runner

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config command launchers for mutable package-runner forms such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.
- Deterministic Signal Basis: JsonSignals command/args analysis over ArtifactKind::McpConfig objects with launcher-specific argument gating.
- Malicious Corpus: `mcp-mutable-launcher`
- Benign Corpus: `mcp-pinned-launcher-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC330` — MCP configuration command downloads remote content and pipes it into a shell

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config command and args values for explicit curl|shell or wget|shell execution chains.
- Deterministic Signal Basis: JsonSignals command/args string analysis over ArtifactKind::McpConfig objects, limited to explicit download-pipe-shell patterns.
- Malicious Corpus: `mcp-inline-download-exec`
- Benign Corpus: `mcp-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC331` — MCP configuration command disables TLS verification in a network-capable execution path

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config command and args values for explicit TLS-bypass tokens in a network-capable execution context.
- Deterministic Signal Basis: JsonSignals command/args string analysis over ArtifactKind::McpConfig objects gated by network markers plus TLS-bypass tokens.
- Malicious Corpus: `mcp-command-tls-bypass`
- Benign Corpus: `mcp-network-tls-verified-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC335` — AI-native markdown contains a direct cloud metadata-service access example

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Metadata-service examples can appear in legitimate security training content, so the first release stays guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC336` — Repo-local MCP client config loads a broad dotenv-style envFile

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Broad envFile loading is useful review signal, but whether it is materially risky still depends on repo-local review policy and env contents.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC337` — MCP configuration launches Docker with an image reference that is not digest-pinned

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config Docker launch paths for image references that are not pinned by digest, including tag-only refs such as :latest or :1.2.3.
- Deterministic Signal Basis: JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to command == docker plus args beginning with run.
- Malicious Corpus: `mcp-docker-unpinned-image`
- Benign Corpus: `mcp-docker-digest-pinned-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC338` — MCP configuration launches Docker with a bind mount of sensitive host material

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config Docker launch paths for bind mounts of sensitive host sources such as docker.sock, SSH material, cloud credentials, and kubeconfig directories.
- Deterministic Signal Basis: JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to -v/--volume and --mount bind forms with sensitive host-path markers.
- Malicious Corpus: `mcp-docker-sensitive-mount`
- Benign Corpus: `mcp-docker-named-volume-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC339` — MCP configuration launches Docker with a host-escape or privileged runtime flag

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config Docker launch paths for privileged or host-escape runtime flags such as --privileged, --network host, --pid host, and --ipc host.
- Deterministic Signal Basis: JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to explicit privileged and host namespace flags.
- Malicious Corpus: `mcp-docker-host-escape`
- Benign Corpus: `mcp-docker-safe-run`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC340` — Claude settings command hook uses a mutable package launcher

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for mutable package launcher forms such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook analysis over committed .claude/settings.json or claude/settings.json objects with type == command under hooks.
- Malicious Corpus: `claude-settings-mutable-launcher`
- Benign Corpus: `claude-settings-pinned-launcher-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC341` — Claude settings command hook downloads remote content and pipes it into a shell

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit curl|shell or wget|shell execution chains.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command, limited to explicit download-pipe-shell patterns.
- Malicious Corpus: `claude-settings-inline-download-exec`
- Benign Corpus: `claude-settings-network-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC342` — Claude settings command hook disables TLS verification in a network-capable execution path

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `claude_settings`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed Claude settings command hooks for explicit TLS-bypass tokens in a network-capable execution context.
- Deterministic Signal Basis: ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command, gated by network markers plus TLS-bypass tokens.
- Malicious Corpus: `claude-settings-command-tls-bypass`
- Benign Corpus: `claude-settings-network-tls-verified-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC343` — Plugin hook command uses a mutable package launcher

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for mutable package launchers such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects limited to actual hook command values.
- Malicious Corpus: `plugin-hook-command-mutable-launcher`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC344` — Plugin hook command downloads remote content and pipes it into a shell

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit curl|shell or wget|shell execution chains.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects, limited to explicit download-pipe-shell patterns.
- Malicious Corpus: `plugin-hook-command-inline-download-exec`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC345` — Plugin hook command disables TLS verification in a network-capable execution path

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed plugin hook command values for explicit TLS-bypass tokens in a network-capable execution context.
- Deterministic Signal Basis: JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects gated by network markers plus TLS-bypass tokens.
- Malicious Corpus: `plugin-hook-command-tls-bypass`
- Benign Corpus: `plugin-hook-command-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC346` — MCP configuration forces Docker to refresh from a mutable registry source

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `json`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Stable`
- Remediation: `message_only`
- Lifecycle: `stable_gated`
- Graduation Rationale: Checks committed MCP config Docker launch paths for explicit --pull always refresh policies that force a mutable registry fetch at runtime.
- Deterministic Signal Basis: JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to explicit --pull=always or --pull always forms.
- Malicious Corpus: `gemini-mcp-docker-pull-always`
- Benign Corpus: `gemini-mcp-docker-digest-pinned-safe`
- Structured Evidence Required: `true`
- Remediation Reviewed: `true`
- Canonical Note: Structural stable rule intended as a high-precision check with deterministic evidence.

### `SEC347` — AI-native markdown example launches MCP through a mutable package runner

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Mutable MCP launcher examples in markdown can be legitimate setup guidance, so the first release stays guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC348` — AI-native markdown Docker example uses a mutable registry image

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Mutable Docker image examples in markdown can be legitimate setup guidance, so the first release stays guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC349` — AI-native markdown Docker example uses a host-escape or privileged runtime pattern

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Docker host-escape examples in markdown can be legitimate ops guidance, so the first release stays guidance-only.
- Promotion Requirements: Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC350` — Instruction markdown promotes untrusted external content to developer/system-level instructions

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Instruction-boundary promotion in markdown is prose-aware and needs external usefulness review before any stronger posture.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

### `SEC351` — AI-native instruction explicitly disables user approval or confirmation

- Provider: `lintai-ai-security`
- Scope: `per_file`
- Surface: `markdown`
- Detection: `heuristic`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `message_only`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Approval-bypass guidance in markdown is prose-aware and needs external usefulness review before any stronger posture.
- Promotion Requirements: Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.
- Canonical Note: Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves.

## Provider: `lintai-policy-mismatch`

### `SEC401` — Project policy forbids execution, but repository contains executable behavior

- Provider: `lintai-policy-mismatch`
- Scope: `workspace`
- Surface: `workspace`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `none`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Needs workspace-level precision review and linked graduation corpus before promotion to Stable.
- Promotion Requirements: Needs workspace precision review, linked benign/malicious corpus proof, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC402` — Project policy forbids network access, but repository contains network behavior

- Provider: `lintai-policy-mismatch`
- Scope: `workspace`
- Surface: `workspace`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `none`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Needs workspace-level network precision review and linked graduation corpus before promotion to Stable.
- Promotion Requirements: Needs workspace precision review, linked benign/malicious corpus proof, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.

### `SEC403` — Skill frontmatter capabilities conflict with project policy

- Provider: `lintai-policy-mismatch`
- Scope: `workspace`
- Surface: `workspace`
- Detection: `structural`
- Default Severity: `Warn`
- Default Confidence: `High`
- Tier: `Preview`
- Remediation: `none`
- Lifecycle: `preview_blocked`
- Promotion Blocker: Needs workspace-level capability-conflict precision review and linked graduation corpus before promotion to Stable.
- Promotion Requirements: Needs workspace precision review, linked benign/malicious corpus proof, and completed stable checklist metadata.
- Canonical Note: Structural preview rule; deterministic today, but the preview contract may still evolve.
