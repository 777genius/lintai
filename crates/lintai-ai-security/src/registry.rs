use std::sync::OnceLock;

use lintai_api::{
    Applicability, ArtifactKind, Category, Confidence, Finding, Fix, RuleMetadata, RuleTier,
    ScanContext, Severity, Suggestion, declare_rule,
};

use crate::claude_settings_rules::{
    check_claude_settings_inline_download_exec, check_claude_settings_mutable_launcher,
    check_claude_settings_network_tls_bypass,
};
use crate::github_workflow_rules::{
    check_github_workflow_pull_request_target_head_checkout,
    check_github_workflow_unpinned_third_party_action,
    check_github_workflow_untrusted_run_interpolation, check_github_workflow_write_all_permissions,
    check_github_workflow_write_capable_third_party_action,
};
use crate::hook_rules::{
    check_hook_base64_exec, check_hook_download_exec, check_hook_plain_http_exfil,
    check_hook_secret_exfil, check_hook_static_auth_exposure, check_hook_tls_bypass,
};
use crate::json_rules::{
    check_json_dangerous_endpoint_host, check_json_hidden_instruction, check_json_literal_secret,
    check_json_sensitive_env_reference, check_json_suspicious_remote_endpoint,
    check_json_unsafe_plugin_path, check_mcp_broad_env_file, check_mcp_credential_env_passthrough,
    check_mcp_dangerous_docker_flag, check_mcp_inline_download_exec, check_mcp_mutable_launcher,
    check_mcp_network_tls_bypass_command, check_mcp_sensitive_docker_mount,
    check_mcp_shell_wrapper, check_mcp_unpinned_docker_image, check_plain_http_config,
    check_plugin_hook_inline_download_exec, check_plugin_hook_mutable_launcher,
    check_plugin_hook_network_tls_bypass, check_static_auth_exposure_config,
    check_trust_verification_disabled_config,
};
use crate::markdown_rules::{
    check_html_comment_directive, check_html_comment_download_exec, check_markdown_base64_exec,
    check_markdown_download_exec, check_markdown_fenced_pipe_shell, check_markdown_path_traversal,
    check_markdown_private_key_pem,
};
use crate::server_json_rules::{
    check_server_json_auth_header_policy_mismatch, check_server_json_insecure_remote_url,
    check_server_json_literal_auth_header, check_server_json_unresolved_header_variable,
    check_server_json_unresolved_remote_variable,
};
use crate::signals::ArtifactSignals;
use crate::tool_json_rules::{
    check_tool_json_anthropic_strict_locked_input_schema, check_tool_json_duplicate_mcp_tool_names,
    check_tool_json_mcp_missing_machine_fields,
    check_tool_json_openai_strict_additional_properties,
    check_tool_json_openai_strict_required_coverage,
};

mod claude_settings;
mod github_workflow;
mod hooks;
mod json;
mod markdown;
mod server_json;
mod tool_json;

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

declare_rule! {
    pub struct ServerJsonLiteralAuthHeaderRule {
        code: "SEC321",
        summary: "server.json remotes header commits literal authentication material",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ServerJsonUnresolvedHeaderVariableRule {
        code: "SEC322",
        summary: "server.json remotes header value references an undefined template variable",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ServerJsonAuthHeaderPolicyMismatchRule {
        code: "SEC323",
        summary: "server.json auth header carries material without an explicit secret flag",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct GithubWorkflowUnpinnedThirdPartyActionRule {
        code: "SEC324",
        summary: "GitHub Actions workflow uses a third-party action that is not pinned to a full commit SHA",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GithubWorkflowUntrustedRunInterpolationRule {
        code: "SEC325",
        summary: "GitHub Actions workflow interpolates untrusted expression data directly inside a run command",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct GithubWorkflowPullRequestTargetHeadCheckoutRule {
        code: "SEC326",
        summary: "GitHub Actions pull_request_target workflow checks out untrusted pull request head content",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GithubWorkflowWriteAllPermissionsRule {
        code: "SEC327",
        summary: "GitHub Actions workflow grants GITHUB_TOKEN write-all permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GithubWorkflowWriteCapableThirdPartyActionRule {
        code: "SEC328",
        summary: "GitHub Actions workflow combines explicit write-capable permissions with a third-party action",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct McpMutableLauncherRule {
        code: "SEC329",
        summary: "MCP configuration launches tooling through a mutable package runner",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpInlineDownloadExecRule {
        code: "SEC330",
        summary: "MCP configuration command downloads remote content and pipes it into a shell",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpNetworkTlsBypassCommandRule {
        code: "SEC331",
        summary: "MCP configuration command disables TLS verification in a network-capable execution path",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpBroadEnvFileRule {
        code: "SEC336",
        summary: "Repo-local MCP client config loads a broad dotenv-style envFile",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct McpUnpinnedDockerImageRule {
        code: "SEC337",
        summary: "MCP configuration launches Docker with an image reference that is not digest-pinned",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpSensitiveDockerMountRule {
        code: "SEC338",
        summary: "MCP configuration launches Docker with a bind mount of sensitive host material",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpDangerousDockerFlagRule {
        code: "SEC339",
        summary: "MCP configuration launches Docker with a host-escape or privileged runtime flag",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsMutableLauncherRule {
        code: "SEC340",
        summary: "Claude settings command hook uses a mutable package launcher",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsInlineDownloadExecRule {
        code: "SEC341",
        summary: "Claude settings command hook downloads remote content and pipes it into a shell",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsNetworkTlsBypassRule {
        code: "SEC342",
        summary: "Claude settings command hook disables TLS verification in a network-capable execution path",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookMutableLauncherRule {
        code: "SEC343",
        summary: "Plugin hook command uses a mutable package launcher",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookInlineDownloadExecRule {
        code: "SEC344",
        summary: "Plugin hook command downloads remote content and pipes it into a shell",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookNetworkTlsBypassRule {
        code: "SEC345",
        summary: "Plugin hook command disables TLS verification in a network-capable execution path",
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
    ClaudeSettings,
    ToolJson,
    ServerJson,
    GithubWorkflow,
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
            Self::ClaudeSettings => artifact_kind == ArtifactKind::ClaudeSettings,
            Self::ToolJson => artifact_kind == ArtifactKind::ToolDescriptorJson,
            Self::ServerJson => artifact_kind == ArtifactKind::ServerRegistryConfig,
            Self::GithubWorkflow => artifact_kind == ArtifactKind::GitHubWorkflow,
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

pub(crate) fn rule_specs() -> &'static [NativeRuleSpec] {
    static RULE_SPECS: OnceLock<Vec<NativeRuleSpec>> = OnceLock::new();

    RULE_SPECS
        .get_or_init(|| {
            let mut specs = Vec::with_capacity(
                markdown::RULE_SPECS.len()
                    + hooks::RULE_SPECS.len()
                    + json::RULE_SPECS.len()
                    + tool_json::RULE_SPECS.len()
                    + server_json::RULE_SPECS.len()
                    + github_workflow::RULE_SPECS.len()
                    + claude_settings::RULE_SPECS.len(),
            );
            specs.extend_from_slice(&markdown::RULE_SPECS);
            specs.extend_from_slice(&hooks::RULE_SPECS);
            specs.extend_from_slice(&json::RULE_SPECS);
            specs.extend_from_slice(&tool_json::RULE_SPECS);
            specs.extend_from_slice(&server_json::RULE_SPECS);
            specs.extend_from_slice(&github_workflow::RULE_SPECS);
            specs.extend_from_slice(&claude_settings::RULE_SPECS);
            specs
        })
        .as_slice()
}

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
