# Security Rules Catalog

> Generated file. Do not edit by hand.
> Source: `lintai-ai-security` native rule specs and policy rule specs.

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
| `SEC401` | Project policy forbids execution, but repository contains executable behavior | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` |
| `SEC402` | Project policy forbids network access, but repository contains network behavior | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` |
| `SEC403` | Skill frontmatter capabilities conflict with project policy | Preview | `preview_blocked` | Warn | `workspace` | `workspace` | `structural` | `none` |

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
