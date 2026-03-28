use std::sync::OnceLock;

use crate::signals::ArtifactSignals;
use lintai_api::{
    Applicability, ArtifactKind, Finding, Fix, RuleMetadata, ScanContext, Suggestion,
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
