use lintai_ai_security::{
    NativeCatalogDetectionClass, NativeCatalogRemediationSupport, NativeCatalogRuleLifecycle,
    NativeCatalogSurface, NativeRuleCatalogEntry,
};
use lintai_policy::{
    PolicyDetectionClass, PolicyRemediationSupport, PolicyRuleCatalogEntry, PolicyRuleLifecycle,
    PolicySurface,
};

use super::{
    CatalogDetectionClass, CatalogRemediationSupport, CatalogRuleLifecycle, CatalogSurface,
    RuleScope, SecurityRuleCatalogEntry,
};

pub(super) fn native_catalog_entry(entry: NativeRuleCatalogEntry) -> SecurityRuleCatalogEntry {
    SecurityRuleCatalogEntry {
        metadata: entry.metadata,
        provider_id: entry.provider_id,
        scope: RuleScope::PerFile,
        surface: match entry.surface {
            NativeCatalogSurface::Markdown => CatalogSurface::Markdown,
            NativeCatalogSurface::Hook => CatalogSurface::Hook,
            NativeCatalogSurface::Devcontainer => CatalogSurface::Devcontainer,
            NativeCatalogSurface::DockerCompose => CatalogSurface::DockerCompose,
            NativeCatalogSurface::Dockerfile => CatalogSurface::Dockerfile,
            NativeCatalogSurface::Json => CatalogSurface::Json,
            NativeCatalogSurface::ClaudeSettings => CatalogSurface::ClaudeSettings,
            NativeCatalogSurface::ToolJson => CatalogSurface::ToolJson,
            NativeCatalogSurface::ServerJson => CatalogSurface::ServerJson,
            NativeCatalogSurface::GithubWorkflow => CatalogSurface::GithubWorkflow,
        },
        default_presets: entry.default_presets,
        detection_class: match entry.detection_class {
            NativeCatalogDetectionClass::Structural => CatalogDetectionClass::Structural,
            NativeCatalogDetectionClass::Heuristic => CatalogDetectionClass::Heuristic,
        },
        lifecycle: match entry.lifecycle {
            NativeCatalogRuleLifecycle::Preview {
                blocker,
                promotion_requirements,
            } => CatalogRuleLifecycle::Preview {
                blocker,
                promotion_requirements,
            },
            NativeCatalogRuleLifecycle::Stable {
                rationale,
                malicious_case_ids,
                benign_case_ids,
                requires_structured_evidence,
                remediation_reviewed,
                deterministic_signal_basis,
            } => CatalogRuleLifecycle::Stable {
                rationale,
                malicious_case_ids,
                benign_case_ids,
                requires_structured_evidence,
                remediation_reviewed,
                deterministic_signal_basis,
            },
        },
        remediation_support: match entry.remediation_support {
            NativeCatalogRemediationSupport::SafeFix => CatalogRemediationSupport::SafeFix,
            NativeCatalogRemediationSupport::Suggestion => CatalogRemediationSupport::Suggestion,
            NativeCatalogRemediationSupport::MessageOnly => CatalogRemediationSupport::MessageOnly,
            NativeCatalogRemediationSupport::None => CatalogRemediationSupport::None,
        },
    }
}

pub(super) fn policy_catalog_entry(entry: PolicyRuleCatalogEntry) -> SecurityRuleCatalogEntry {
    SecurityRuleCatalogEntry {
        metadata: entry.metadata,
        provider_id: entry.provider_id,
        scope: RuleScope::Workspace,
        surface: match entry.surface {
            PolicySurface::Workspace => CatalogSurface::Workspace,
        },
        default_presets: entry.default_presets,
        detection_class: match entry.detection_class {
            PolicyDetectionClass::Structural => CatalogDetectionClass::Structural,
        },
        lifecycle: match entry.lifecycle {
            PolicyRuleLifecycle::Preview {
                blocker,
                promotion_requirements,
            } => CatalogRuleLifecycle::Preview {
                blocker,
                promotion_requirements,
            },
        },
        remediation_support: match entry.remediation_support {
            PolicyRemediationSupport::None => CatalogRemediationSupport::None,
        },
    }
}
