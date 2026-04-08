use crate::signals::ArtifactSignals;
use lintai_api::{ArtifactKind, Finding, Fix, RuleMetadata, ScanContext};

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const PROVIDER_ID: &str = "lintai-ai-security";

pub(crate) type CheckFn = fn(&ScanContext, &ArtifactSignals, RuleMetadata) -> Vec<Finding>;
pub(crate) type SafeFixFn = fn(&Finding) -> Fix;
pub(crate) type SuggestionFixFn = fn(&ScanContext, &Finding) -> Option<Fix>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum Surface {
    Markdown,
    Hook,
    Devcontainer,
    DockerCompose,
    Dockerfile,
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
            Self::Devcontainer => artifact_kind == ArtifactKind::DevcontainerConfig,
            Self::DockerCompose => artifact_kind == ArtifactKind::DockerCompose,
            Self::Dockerfile => artifact_kind == ArtifactKind::Dockerfile,
            Self::Json => matches!(
                artifact_kind,
                ArtifactKind::McpConfig
                    | ArtifactKind::PackageManifest
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
    pub(crate) default_presets: &'static [&'static str],
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) detection_class: DetectionClass,
    pub(crate) lifecycle: RuleLifecycle,
    pub(crate) check: CheckFn,
    pub(crate) safe_fix: Option<SafeFixFn>,
    pub(crate) suggestion_message: Option<&'static str>,
    pub(crate) suggestion_fix: Option<SuggestionFixFn>,
}

impl NativeRuleSpec {
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

macro_rules! stable_native_message_rule_spec {
    (
        metadata: $metadata:expr,
        surface: $surface:expr,
        default_presets: $default_presets:expr,
        detection_class: $detection_class:expr,
        rationale: $rationale:expr,
        malicious_case_ids: $malicious_case_ids:expr,
        benign_case_ids: $benign_case_ids:expr,
        deterministic_signal_basis: $deterministic_signal_basis:expr,
        check: $check:expr,
        suggestion_message: $suggestion_message:expr $(,)?
    ) => {
        NativeRuleSpec {
            metadata: $metadata,
            surface: $surface,
            default_presets: $default_presets,
            detection_class: $detection_class,
            lifecycle: RuleLifecycle::Stable {
                rationale: $rationale,
                malicious_case_ids: $malicious_case_ids,
                benign_case_ids: $benign_case_ids,
                requires_structured_evidence: true,
                remediation_reviewed: true,
                deterministic_signal_basis: $deterministic_signal_basis,
            },
            check: $check,
            safe_fix: None,
            suggestion_message: Some($suggestion_message),
            suggestion_fix: None,
        }
    };
}

pub(crate) use stable_native_message_rule_spec;

macro_rules! preview_native_message_rule_spec {
    (
        metadata: $metadata:expr,
        surface: $surface:expr,
        default_presets: $default_presets:expr,
        detection_class: $detection_class:expr,
        blocker: $blocker:expr,
        promotion_requirements: $promotion_requirements:expr,
        check: $check:expr,
        suggestion_message: $suggestion_message:expr $(,)?
    ) => {
        NativeRuleSpec {
            metadata: $metadata,
            surface: $surface,
            default_presets: $default_presets,
            detection_class: $detection_class,
            lifecycle: RuleLifecycle::Preview {
                blocker: $blocker,
                promotion_requirements: $promotion_requirements,
            },
            check: $check,
            safe_fix: None,
            suggestion_message: Some($suggestion_message),
            suggestion_fix: None,
        }
    };
}

pub(crate) use preview_native_message_rule_spec;
