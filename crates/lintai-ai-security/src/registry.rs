use lintai_api::{
    Applicability, ArtifactKind, Category, Confidence, Finding, Fix, RuleMetadata, RuleTier,
    ScanContext, Severity, Suggestion, declare_rule,
};

use crate::hook_rules::{
    check_hook_base64_exec, check_hook_download_exec, check_hook_plain_http_exfil,
    check_hook_secret_exfil, check_hook_static_auth_exposure, check_hook_tls_bypass,
};
use crate::json_rules::{
    check_json_dangerous_endpoint_host, check_json_hidden_instruction, check_json_literal_secret,
    check_json_sensitive_env_reference, check_json_suspicious_remote_endpoint,
    check_json_unsafe_plugin_path, check_mcp_credential_env_passthrough, check_mcp_shell_wrapper,
    check_plain_http_config, check_static_auth_exposure_config,
    check_trust_verification_disabled_config,
};
use crate::markdown_rules::{
    check_html_comment_directive, check_html_comment_download_exec, check_markdown_base64_exec,
    check_markdown_download_exec, check_markdown_fenced_pipe_shell, check_markdown_path_traversal,
    check_markdown_private_key_pem,
};
use crate::server_json_rules::{
    check_server_json_insecure_remote_url, check_server_json_unresolved_remote_variable,
};
use crate::signals::ArtifactSignals;
use crate::tool_json_rules::{
    check_tool_json_anthropic_strict_locked_input_schema, check_tool_json_duplicate_mcp_tool_names,
    check_tool_json_mcp_missing_machine_fields,
    check_tool_json_openai_strict_additional_properties,
    check_tool_json_openai_strict_required_coverage,
};

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const PROVIDER_ID: &str = "lintai-ai-security";

declare_rule! {
    pub struct HtmlCommentDirectiveRule {
        code: "SEC101",
        summary: "Hidden HTML comment contains dangerous agent instructions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct MarkdownDownloadExecRule {
        code: "SEC102",
        summary: "Markdown contains remote download-and-execute instruction outside code blocks",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct HtmlCommentDownloadExecRule {
        code: "SEC103",
        summary: "Hidden HTML comment contains remote download-and-execute instruction",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct MarkdownBase64ExecRule {
        code: "SEC104",
        summary: "Markdown contains a base64-decoded executable payload outside code blocks",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct MarkdownPathTraversalRule {
        code: "SEC105",
        summary: "Markdown instructions reference parent-directory traversal for file access",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct HookDownloadExecRule {
        code: "SEC201",
        summary: "Hook script downloads remote code and executes it",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookSecretExfilRule {
        code: "SEC202",
        summary: "Hook script appears to exfiltrate secrets through a network call",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookPlainHttpExfilRule {
        code: "SEC203",
        summary: "Hook script sends secret material to an insecure http:// endpoint",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookTlsBypassRule {
        code: "SEC204",
        summary: "Hook script disables TLS or certificate verification for a network call",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookStaticAuthExposureRule {
        code: "SEC205",
        summary: "Hook script embeds static authentication material in a network call",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookBase64ExecRule {
        code: "SEC206",
        summary: "Hook script decodes a base64 payload and executes it",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpShellWrapperRule {
        code: "SEC301",
        summary: "MCP configuration shells out through sh -c or bash -c",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PlainHttpConfigRule {
        code: "SEC302",
        summary: "Configuration contains an insecure http:// endpoint",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpCredentialEnvPassthroughRule {
        code: "SEC303",
        summary: "MCP configuration passes through credential environment variables",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct TrustVerificationDisabledConfigRule {
        code: "SEC304",
        summary: "Configuration disables TLS or certificate verification",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct StaticAuthExposureConfigRule {
        code: "SEC305",
        summary: "Configuration embeds static authentication material in a connection or auth value",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct JsonHiddenInstructionRule {
        code: "SEC306",
        summary: "JSON configuration description contains override-style hidden instructions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct JsonSensitiveEnvReferenceRule {
        code: "SEC307",
        summary: "Configuration forwards sensitive environment variable references",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct JsonSuspiciousRemoteEndpointRule {
        code: "SEC308",
        summary: "Configuration points at a suspicious remote endpoint",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct JsonLiteralSecretRule {
        code: "SEC309",
        summary: "Configuration commits literal secret material in env, auth, or header values",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct JsonDangerousEndpointHostRule {
        code: "SEC310",
        summary: "Configuration endpoint targets a metadata or private-network host literal",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct CursorPluginUnsafePathRule {
        code: "SEC311",
        summary: "Cursor plugin manifest contains an unsafe absolute or parent-traversing path",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownPrivateKeyPemRule {
        code: "SEC312",
        summary: "Markdown contains committed private key material",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownFencedPipeShellRule {
        code: "SEC313",
        summary: "Fenced shell example pipes remote content directly into a shell",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct McpToolRequiredFieldsRule {
        code: "SEC314",
        summary: "MCP-style tool descriptor is missing required machine fields",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpDuplicateToolNamesRule {
        code: "SEC315",
        summary: "MCP-style tool descriptor collection contains duplicate tool names",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct OpenAiStrictAdditionalPropertiesRule {
        code: "SEC316",
        summary: "OpenAI strict tool schema omits recursive additionalProperties: false",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct OpenAiStrictRequiredCoverageRule {
        code: "SEC317",
        summary: "OpenAI strict tool schema does not require every declared property",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct AnthropicStrictInputSchemaRule {
        code: "SEC318",
        summary: "Anthropic strict tool input schema omits additionalProperties: false",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ServerJsonInsecureRemoteUrlRule {
        code: "SEC319",
        summary: "server.json remotes entry uses an insecure or non-public remote URL",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ServerJsonUnresolvedRemoteVariableRule {
        code: "SEC320",
        summary: "server.json remotes URL references an undefined template variable",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

type CheckFn = fn(&ScanContext, &ArtifactSignals, RuleMetadata) -> Vec<Finding>;
type SafeFixFn = fn(&Finding) -> Fix;
type SuggestionFixFn = fn(&ScanContext, &Finding) -> Option<Fix>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum Surface {
    Markdown,
    Hook,
    Json,
    ToolJson,
    ServerJson,
    Workspace,
}

impl Surface {
    pub(crate) fn matches(self, artifact_kind: ArtifactKind) -> bool {
        match self {
            Self::Markdown => matches!(
                artifact_kind,
                ArtifactKind::Skill
                    | ArtifactKind::Instructions
                    | ArtifactKind::CursorRules
                    | ArtifactKind::CursorPluginCommand
                    | ArtifactKind::CursorPluginAgent
            ),
            Self::Hook => artifact_kind == ArtifactKind::CursorHookScript,
            Self::Json => matches!(
                artifact_kind,
                ArtifactKind::McpConfig
                    | ArtifactKind::CursorPluginManifest
                    | ArtifactKind::CursorPluginHooks
            ),
            Self::ToolJson => artifact_kind == ArtifactKind::ToolDescriptorJson,
            Self::ServerJson => artifact_kind == ArtifactKind::ServerRegistryConfig,
            Self::Workspace => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DetectionClass {
    Structural,
    Heuristic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuleLifecycle {
    Preview {
        blocker: &'static str,
        promotion_requirements: &'static str,
    },
    Stable {
        rationale: &'static str,
        malicious_case_ids: &'static [&'static str],
        benign_case_ids: &'static [&'static str],
        requires_structured_evidence: bool,
        remediation_reviewed: bool,
        deterministic_signal_basis: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum RemediationSupport {
    SafeFix,
    Suggestion,
    MessageOnly,
    None,
}

#[derive(Clone, Copy)]
pub(crate) struct NativeRuleSpec {
    pub(crate) metadata: RuleMetadata,
    pub(crate) surface: Surface,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) detection_class: DetectionClass,
    pub(crate) lifecycle: RuleLifecycle,
    pub(crate) check: CheckFn,
    safe_fix: Option<SafeFixFn>,
    suggestion_message: Option<&'static str>,
    suggestion_fix: Option<SuggestionFixFn>,
}

impl NativeRuleSpec {
    pub(crate) fn apply_remediation(self, ctx: &ScanContext, finding: Finding) -> Finding {
        let safe_fix = self.safe_fix.map(|fix| fix(&finding));
        let finding = match self.safe_fix {
            Some(_) => finding.with_fix(safe_fix.expect("safe fix must exist when configured")),
            None => finding,
        };

        match self.suggestion_message {
            Some(message) => {
                let candidate_fix = self.suggestion_fix.and_then(|fix| fix(ctx, &finding));
                finding.with_suggestion(Suggestion::new(message, candidate_fix))
            }
            None => finding,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn remediation_support(self) -> RemediationSupport {
        if self.safe_fix.is_some() {
            RemediationSupport::SafeFix
        } else if self.suggestion_fix.is_some() {
            RemediationSupport::Suggestion
        } else if self.suggestion_message.is_some() {
            RemediationSupport::MessageOnly
        } else {
            RemediationSupport::None
        }
    }
}

pub(crate) const HEURISTIC_PREVIEW_REQUIREMENTS: &str = "Needs corpus-backed precision review, a non-heuristic graduation basis, and completed stable checklist metadata.";
pub(crate) const STRUCTURAL_PREVIEW_REQUIREMENTS: &str = "Needs corpus-backed precision review, external usefulness evidence, and completed stable checklist metadata.";
pub(crate) const WORKSPACE_PREVIEW_REQUIREMENTS: &str = "Needs workspace precision review, linked benign/malicious corpus proof, and completed stable checklist metadata.";

pub(crate) const RULE_SPECS: [NativeRuleSpec; 31] = [
    NativeRuleSpec {
        metadata: HtmlCommentDirectiveRule::METADATA,
        surface: Surface::Markdown,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on suspicious phrase heuristics inside hidden HTML comments.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_html_comment_directive,
        safe_fix: Some(remove_hidden_comment_fix),
        suggestion_message: None,
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownDownloadExecRule::METADATA,
        surface: Surface::Markdown,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on prose command heuristics outside code blocks.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_download_exec,
        safe_fix: None,
        suggestion_message: Some(
            "rewrite the command as inert prose or move it into a fenced example block",
        ),
        suggestion_fix: Some(markdown_inline_code_fix),
    },
    NativeRuleSpec {
        metadata: HtmlCommentDownloadExecRule::METADATA,
        surface: Surface::Markdown,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on hidden-comment command heuristics rather than a structural execution model.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_html_comment_download_exec,
        safe_fix: Some(remove_hidden_download_exec_comment_fix),
        suggestion_message: None,
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownBase64ExecRule::METADATA,
        surface: Surface::Markdown,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on prose base64-and-exec text heuristics.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_base64_exec,
        safe_fix: None,
        suggestion_message: Some(
            "remove or rewrite the base64 decode-and-exec flow as inert prose or a fenced example",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownPathTraversalRule::METADATA,
        surface: Surface::Markdown,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on prose path-traversal and access-verb heuristics.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_path_traversal,
        safe_fix: None,
        suggestion_message: Some(
            "replace parent-directory traversal instructions with project-scoped paths or explicit safe inputs",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookDownloadExecRule::METADATA,
        surface: Surface::Hook,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit remote download-and-execute behavior in hook shell lines, not prose text.",
            malicious_case_ids: &["hook-download-exec"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals download-and-execute observation over non-comment hook lines.",
        },
        check: check_hook_download_exec,
        safe_fix: None,
        suggestion_message: Some(
            "vendor or pin the script locally instead of downloading and executing it inline",
        ),
        suggestion_fix: Some(hook_download_exec_fix),
    },
    NativeRuleSpec {
        metadata: HookSecretExfilRule::METADATA,
        surface: Surface::Hook,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches secret-bearing network exfil behavior in executable hook lines.",
            malicious_case_ids: &["hook-secret-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals secret exfil observation from network markers plus secret markers on non-comment lines.",
        },
        check: check_hook_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the secret-bearing network exfil flow and keep secret access local",
        ),
        suggestion_fix: Some(hook_secret_exfil_fix),
    },
    NativeRuleSpec {
        metadata: HookPlainHttpExfilRule::METADATA,
        surface: Surface::Hook,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches insecure HTTP transport on a secret-bearing hook exfil path.",
            malicious_case_ids: &["hook-plain-http-secret-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals precise http:// span observation gated by concurrent secret exfil markers.",
        },
        check: check_hook_plain_http_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove insecure HTTP secret exfil and keep secret handling local or over HTTPS",
        ),
        suggestion_fix: Some(hook_plain_http_exfil_fix),
    },
    NativeRuleSpec {
        metadata: HookTlsBypassRule::METADATA,
        surface: Surface::Hook,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit TLS verification bypass tokens in executable hook network context.",
            malicious_case_ids: &["hook-tls-bypass"],
            benign_case_ids: &["cursor-plugin-tls-verified-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals TLS-bypass token observation over parsed hook line tokens and network context.",
        },
        check: check_hook_tls_bypass,
        safe_fix: None,
        suggestion_message: Some(
            "remove TLS-bypass flags or env overrides and use normal certificate verification",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookStaticAuthExposureRule::METADATA,
        surface: Surface::Hook,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches literal static auth material in hook URLs or authorization headers.",
            malicious_case_ids: &["hook-static-auth-userinfo"],
            benign_case_ids: &["hook-auth-dynamic-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals userinfo/header literal extraction excluding dynamic references.",
        },
        check: check_hook_static_auth_exposure,
        safe_fix: None,
        suggestion_message: Some(
            "move embedded credentials out of URLs and headers into environment or provider-local auth configuration",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookBase64ExecRule::METADATA,
        surface: Surface::Hook,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit base64 decode-and-execute behavior in executable hook lines.",
            malicious_case_ids: &["hook-base64-exec"],
            benign_case_ids: &["hook-base64-decode-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals base64-decode plus exec observation over non-comment hook lines.",
        },
        check: check_hook_base64_exec,
        safe_fix: None,
        suggestion_message: Some(
            "remove the obfuscated base64 decode-and-exec flow from the hook script",
        ),
        suggestion_fix: Some(hook_base64_exec_fix),
    },
    NativeRuleSpec {
        metadata: McpShellWrapperRule::METADATA,
        surface: Surface::Json,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit shell-wrapper command structure in JSON config.",
            malicious_case_ids: &["mcp-shell-wrapper"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command and args structure observation for sh -c or bash -c wrappers.",
        },
        check: check_mcp_shell_wrapper,
        safe_fix: None,
        suggestion_message: Some(
            "replace the shell wrapper with a direct command and explicit args",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PlainHttpConfigRule::METADATA,
        surface: Surface::Json,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit insecure http:// endpoints in configuration values.",
            malicious_case_ids: &["mcp-plain-http"],
            benign_case_ids: &["mcp-trusted-endpoint-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals precise http:// endpoint span resolution from parsed JSON location map.",
        },
        check: check_plain_http_config,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure http:// endpoint with https:// or a local/stdio transport",
        ),
        suggestion_fix: Some(https_rewrite_fix),
    },
    NativeRuleSpec {
        metadata: McpCredentialEnvPassthroughRule::METADATA,
        surface: Surface::Json,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit credential env passthrough by key inside configuration env maps.",
            malicious_case_ids: &["mcp-credential-env-passthrough"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals env-map key observation for credential passthrough keys.",
        },
        check: check_mcp_credential_env_passthrough,
        safe_fix: None,
        suggestion_message: Some(
            "remove credential env passthrough and configure secrets only inside the target service",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: TrustVerificationDisabledConfigRule::METADATA,
        surface: Surface::Json,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit TLS or certificate verification disable flags in configuration.",
            malicious_case_ids: &["mcp-trust-verification-disabled"],
            benign_case_ids: &["mcp-trust-verified-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals boolean and key observation for trust-verification disable settings.",
        },
        check: check_trust_verification_disabled_config,
        safe_fix: None,
        suggestion_message: Some(
            "re-enable certificate verification and use trusted HTTPS or local/stdio transport",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: StaticAuthExposureConfigRule::METADATA,
        surface: Surface::Json,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches literal static auth material embedded directly in configuration values.",
            malicious_case_ids: &["mcp-static-authorization"],
            benign_case_ids: &["mcp-authorization-placeholder-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals literal authorization or userinfo span extraction excluding dynamic placeholders.",
        },
        check: check_static_auth_exposure_config,
        safe_fix: None,
        suggestion_message: Some(
            "remove embedded credentials from config values and source auth from environment or provider-local secret configuration",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonHiddenInstructionRule::METADATA,
        surface: Surface::Json,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on descriptive-field phrase heuristics in JSON text.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_json_hidden_instruction,
        safe_fix: None,
        suggestion_message: Some(
            "remove override-style instructions from descriptive JSON fields and keep tool or plugin metadata declarative",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonSensitiveEnvReferenceRule::METADATA,
        surface: Surface::Json,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on sensitive env-name heuristics in forwarded references.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_json_sensitive_env_reference,
        safe_fix: None,
        suggestion_message: Some(
            "stop forwarding sensitive env references through config and resolve secrets only inside the target service",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonSuspiciousRemoteEndpointRule::METADATA,
        surface: Surface::Json,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on suspicious host-marker heuristics for remote endpoints.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_json_suspicious_remote_endpoint,
        safe_fix: None,
        suggestion_message: Some(
            "replace the suspicious remote endpoint with a trusted internal, verified, or pinned service endpoint",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonLiteralSecretRule::METADATA,
        surface: Surface::Json,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches literal secret material committed into env, header, or auth-like JSON fields.",
            malicious_case_ids: &["mcp-literal-secret-config"],
            benign_case_ids: &["mcp-secret-placeholder-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals literal secret observation over env, header, and auth-like keys excluding dynamic placeholders.",
        },
        check: check_json_literal_secret,
        safe_fix: None,
        suggestion_message: Some(
            "replace committed secret literals with environment or input indirection before shipping the config",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonDangerousEndpointHostRule::METADATA,
        surface: Surface::Json,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit metadata-service or private-network host literals in endpoint-like configuration values.",
            malicious_case_ids: &["mcp-metadata-host-literal"],
            benign_case_ids: &["mcp-public-endpoint-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals endpoint-host extraction over URL-like endpoint fields with metadata/private-host classification.",
        },
        check: check_json_dangerous_endpoint_host,
        safe_fix: None,
        suggestion_message: Some(
            "replace metadata or private-network host literals with a trusted public endpoint or local stdio transport",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CursorPluginUnsafePathRule::METADATA,
        surface: Surface::Json,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches absolute or parent-traversing paths in committed Cursor plugin manifest path fields.",
            malicious_case_ids: &["cursor-plugin-unsafe-path"],
            benign_case_ids: &["cursor-plugin-safe-paths"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals plugin-manifest path observation limited to known plugin path fields.",
        },
        check: check_json_unsafe_plugin_path,
        safe_fix: None,
        suggestion_message: Some(
            "keep plugin manifest paths project-relative and inside the plugin root",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownPrivateKeyPemRule::METADATA,
        surface: Surface::Markdown,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit committed private-key PEM markers inside agent markdown surfaces.",
            malicious_case_ids: &["skill-private-key-pem"],
            benign_case_ids: &["skill-public-key-pem-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals private-key marker observation across parsed markdown regions excluding placeholder examples.",
        },
        check: check_markdown_private_key_pem,
        safe_fix: None,
        suggestion_message: Some(
            "remove committed private key material and replace it with redacted or placeholder guidance",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownFencedPipeShellRule::METADATA,
        surface: Surface::Markdown,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on fenced shell-example command heuristics and still needs broader external precision review.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_fenced_pipe_shell,
        safe_fix: None,
        suggestion_message: Some(
            "rewrite the fenced example to download first or explain the command without piping directly into a shell",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpToolRequiredFieldsRule::METADATA,
        surface: Surface::ToolJson,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks unambiguous MCP-style tool descriptors for missing machine fields instead of relying on prose heuristics.",
            malicious_case_ids: &["tool-json-mcp-missing-machine-fields"],
            benign_case_ids: &["tool-json-mcp-valid-tool"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ToolJsonSignals MCP collection analysis over parsed tool descriptor JSON.",
        },
        check: check_tool_json_mcp_missing_machine_fields,
        safe_fix: None,
        suggestion_message: Some(
            "add the missing machine field so the exported MCP tool remains explicit and deterministic",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpDuplicateToolNamesRule::METADATA,
        surface: Surface::ToolJson,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks structured MCP-style tool collections for duplicate names that can shadow one another.",
            malicious_case_ids: &["tool-json-duplicate-tool-names"],
            benign_case_ids: &["tool-json-unique-tool-names"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ToolJsonSignals duplicate-name detection over MCP-style tool collections.",
        },
        check: check_tool_json_duplicate_mcp_tool_names,
        safe_fix: None,
        suggestion_message: Some(
            "rename the duplicated tool so each exported machine identifier is unique",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: OpenAiStrictAdditionalPropertiesRule::METADATA,
        surface: Surface::ToolJson,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks OpenAI strict tool schemas for recursive object locking with additionalProperties: false.",
            malicious_case_ids: &["tool-json-openai-strict-additional-properties"],
            benign_case_ids: &["tool-json-openai-strict-locked"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ToolJsonSignals recursive schema walk over OpenAI function.parameters when strict mode is enabled.",
        },
        check: check_tool_json_openai_strict_additional_properties,
        safe_fix: None,
        suggestion_message: Some(
            "lock every object node in the strict OpenAI tool schema with additionalProperties: false",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: OpenAiStrictRequiredCoverageRule::METADATA,
        surface: Surface::ToolJson,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks OpenAI strict tool schemas for full required coverage of declared properties.",
            malicious_case_ids: &["tool-json-openai-strict-required-coverage"],
            benign_case_ids: &["tool-json-openai-strict-required-complete"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ToolJsonSignals recursive required-versus-properties comparison over strict OpenAI schemas.",
        },
        check: check_tool_json_openai_strict_required_coverage,
        safe_fix: None,
        suggestion_message: Some(
            "include every declared property in required when strict mode is enabled",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: AnthropicStrictInputSchemaRule::METADATA,
        surface: Surface::ToolJson,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks Anthropic strict tool input_schema objects for explicit additionalProperties: false.",
            malicious_case_ids: &["tool-json-anthropic-strict-open-schema"],
            benign_case_ids: &["tool-json-anthropic-strict-locked"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ToolJsonSignals recursive schema walk over Anthropic input_schema when strict mode is enabled.",
        },
        check: check_tool_json_anthropic_strict_locked_input_schema,
        safe_fix: None,
        suggestion_message: Some(
            "lock the Anthropic input_schema with additionalProperties: false on every object node",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ServerJsonInsecureRemoteUrlRule::METADATA,
        surface: Surface::ServerJson,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks MCP registry remotes[] URLs for insecure HTTP and non-public host literals without inspecting local package transport URLs.",
            malicious_case_ids: &["server-json-insecure-remote-url"],
            benign_case_ids: &["server-json-loopback-package-transport-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ServerJsonSignals remotes[] URL analysis limited to streamable-http and sse entries.",
        },
        check: check_server_json_insecure_remote_url,
        safe_fix: None,
        suggestion_message: Some(
            "use a public https remote URL or remove the non-public literal from the registry remote entry",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ServerJsonUnresolvedRemoteVariableRule::METADATA,
        surface: Surface::ServerJson,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks server.json remotes[] URL templates against variables defined on the same remote entry.",
            malicious_case_ids: &["server-json-unresolved-remote-variable"],
            benign_case_ids: &["server-json-remote-variable-defined"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ServerJsonSignals placeholder extraction over remotes[] URLs compared with remotes[].variables keys.",
        },
        check: check_server_json_unresolved_remote_variable,
        safe_fix: None,
        suggestion_message: Some(
            "define every URL placeholder under remotes[].variables or remove the unresolved placeholder from the remote URL",
        ),
        suggestion_fix: None,
    },
];

fn remove_hidden_comment_fix(finding: &Finding) -> Fix {
    Fix::new(
        finding.location.span.clone(),
        "",
        Applicability::Safe,
        Some("remove dangerous hidden HTML comment".to_owned()),
    )
}

fn remove_hidden_download_exec_comment_fix(finding: &Finding) -> Fix {
    Fix::new(
        finding.location.span.clone(),
        "",
        Applicability::Safe,
        Some("remove hidden HTML comment download-and-execute instruction".to_owned()),
    )
}

fn markdown_inline_code_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    let span = &finding.location.span;
    let snippet = ctx.content.get(span.start_byte..span.end_byte)?;
    let command = first_download_exec_span(snippet)?;
    let absolute_start = span.start_byte + command.start_byte;
    let absolute_end = span.start_byte + command.end_byte;
    let original = ctx.content.get(absolute_start..absolute_end)?;
    Some(Fix::new(
        lintai_api::Span::new(absolute_start, absolute_end),
        format!("`{original}`"),
        Applicability::Suggestion,
        Some("render the command as inert inline code".to_owned()),
    ))
}

fn hook_download_exec_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    replace_line_with_comment_fix(ctx, finding, "# lintai: remove download-and-exec behavior")
}

fn hook_secret_exfil_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    replace_line_with_comment_fix(ctx, finding, "# lintai: remove secret exfiltration command")
}

fn hook_plain_http_exfil_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    replace_line_with_comment_fix(
        ctx,
        finding,
        "# lintai: remove insecure secret exfiltration command",
    )
}

fn hook_base64_exec_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    replace_line_with_comment_fix(
        ctx,
        finding,
        "# lintai: remove base64 decode-and-exec behavior",
    )
}

fn replace_line_with_comment_fix(
    ctx: &ScanContext,
    finding: &Finding,
    replacement: &str,
) -> Option<Fix> {
    let span = line_span_for_offset(&ctx.content, finding.location.span.start_byte)?;
    Some(Fix::new(
        span,
        replacement,
        Applicability::Suggestion,
        Some("disable the unsafe hook command".to_owned()),
    ))
}

fn https_rewrite_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    let start = finding.location.span.start_byte;
    let snippet = ctx.content.get(start..finding.location.span.end_byte)?;
    let relative = snippet.find("http://")?;
    let absolute_start = start + relative;
    let absolute_end = absolute_start + "http://".len();
    Some(Fix::new(
        lintai_api::Span::new(absolute_start, absolute_end),
        "https://",
        Applicability::Suggestion,
        Some("rewrite the endpoint to HTTPS".to_owned()),
    ))
}

fn line_span_for_offset(content: &str, offset: usize) -> Option<lintai_api::Span> {
    if offset > content.len() {
        return None;
    }

    let line_start = content[..offset].rfind('\n').map_or(0, |index| index + 1);
    let line_end = content[offset..]
        .find('\n')
        .map_or(content.len(), |index| offset + index);
    Some(lintai_api::Span::new(line_start, line_end))
}

fn first_download_exec_span(content: &str) -> Option<lintai_api::Span> {
    let lowered = content.to_ascii_lowercase();
    let curl = lowered.find("curl ");
    let wget = lowered.find("wget ");
    let start = match (curl, wget) {
        (Some(left), Some(right)) => left.min(right),
        (Some(left), None) => left,
        (None, Some(right)) => right,
        (None, None) => return None,
    };
    let tail = &lowered[start..];
    if !(tail.contains("| sh") || tail.contains("| bash")) {
        return None;
    }
    Some(lintai_api::Span::new(
        start,
        content.trim_end_matches(['\r', '\n']).len(),
    ))
}
