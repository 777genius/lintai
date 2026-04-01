use lintai_api::RuleMetadata;

use crate::registry::{
    DetectionClass, PROVIDER_ID, RemediationSupport, RuleLifecycle, Surface, rule_specs,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCatalogSurface {
    Markdown,
    Hook,
    DockerCompose,
    Dockerfile,
    Json,
    ClaudeSettings,
    ToolJson,
    ServerJson,
    GithubWorkflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCatalogDetectionClass {
    Structural,
    Heuristic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCatalogRuleLifecycle {
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
pub enum NativeCatalogRemediationSupport {
    SafeFix,
    Suggestion,
    MessageOnly,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRuleCatalogEntry {
    pub metadata: RuleMetadata,
    pub provider_id: &'static str,
    pub surface: NativeCatalogSurface,
    pub default_presets: &'static [&'static str],
    pub detection_class: NativeCatalogDetectionClass,
    pub lifecycle: NativeCatalogRuleLifecycle,
    pub remediation_support: NativeCatalogRemediationSupport,
}

pub fn native_rule_catalog_entries() -> Vec<NativeRuleCatalogEntry> {
    rule_specs()
        .iter()
        .map(|spec| NativeRuleCatalogEntry {
            metadata: spec.metadata,
            provider_id: PROVIDER_ID,
            surface: map_surface(spec.surface),
            default_presets: spec.default_presets,
            detection_class: map_detection_class(spec.detection_class),
            lifecycle: map_lifecycle(spec.lifecycle),
            remediation_support: map_remediation(spec.remediation_support()),
        })
        .collect()
}

fn map_surface(surface: Surface) -> NativeCatalogSurface {
    match surface {
        Surface::Markdown => NativeCatalogSurface::Markdown,
        Surface::Hook => NativeCatalogSurface::Hook,
        Surface::DockerCompose => NativeCatalogSurface::DockerCompose,
        Surface::Dockerfile => NativeCatalogSurface::Dockerfile,
        Surface::Json => NativeCatalogSurface::Json,
        Surface::ClaudeSettings => NativeCatalogSurface::ClaudeSettings,
        Surface::ToolJson => NativeCatalogSurface::ToolJson,
        Surface::ServerJson => NativeCatalogSurface::ServerJson,
        Surface::GithubWorkflow => NativeCatalogSurface::GithubWorkflow,
        Surface::Workspace => unreachable!("workspace rules do not belong to lintai-ai-security"),
    }
}

fn map_detection_class(class: DetectionClass) -> NativeCatalogDetectionClass {
    match class {
        DetectionClass::Structural => NativeCatalogDetectionClass::Structural,
        DetectionClass::Heuristic => NativeCatalogDetectionClass::Heuristic,
    }
}

fn map_lifecycle(lifecycle: RuleLifecycle) -> NativeCatalogRuleLifecycle {
    match lifecycle {
        RuleLifecycle::Preview {
            blocker,
            promotion_requirements,
        } => NativeCatalogRuleLifecycle::Preview {
            blocker,
            promotion_requirements,
        },
        RuleLifecycle::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        } => NativeCatalogRuleLifecycle::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        },
    }
}

fn map_remediation(remediation: RemediationSupport) -> NativeCatalogRemediationSupport {
    match remediation {
        RemediationSupport::SafeFix => NativeCatalogRemediationSupport::SafeFix,
        RemediationSupport::Suggestion => NativeCatalogRemediationSupport::Suggestion,
        RemediationSupport::MessageOnly => NativeCatalogRemediationSupport::MessageOnly,
        RemediationSupport::None => NativeCatalogRemediationSupport::None,
    }
}
