use lintai_builtins::{
    BuiltinCatalogDetectionClass, BuiltinCatalogRemediationSupport, BuiltinCatalogRuleLifecycle,
    BuiltinCatalogSurface, BuiltinRuleCatalogEntry, BuiltinRuleScope,
};

use super::{
    CatalogDetectionClass, CatalogRemediationSupport, CatalogRuleLifecycle, CatalogSurface,
    RuleScope, SecurityRuleCatalogEntry,
};

pub(super) fn builtin_catalog_entry(entry: BuiltinRuleCatalogEntry) -> SecurityRuleCatalogEntry {
    SecurityRuleCatalogEntry {
        metadata: entry.metadata,
        provider_id: entry.provider_id,
        scope: match entry.scope {
            BuiltinRuleScope::PerFile => RuleScope::PerFile,
            BuiltinRuleScope::Workspace => RuleScope::Workspace,
        },
        surface: match entry.surface {
            BuiltinCatalogSurface::Markdown => CatalogSurface::Markdown,
            BuiltinCatalogSurface::Hook => CatalogSurface::Hook,
            BuiltinCatalogSurface::Devcontainer => CatalogSurface::Devcontainer,
            BuiltinCatalogSurface::DockerCompose => CatalogSurface::DockerCompose,
            BuiltinCatalogSurface::Dockerfile => CatalogSurface::Dockerfile,
            BuiltinCatalogSurface::Json => CatalogSurface::Json,
            BuiltinCatalogSurface::ClaudeSettings => CatalogSurface::ClaudeSettings,
            BuiltinCatalogSurface::ToolJson => CatalogSurface::ToolJson,
            BuiltinCatalogSurface::ServerJson => CatalogSurface::ServerJson,
            BuiltinCatalogSurface::GithubWorkflow => CatalogSurface::GithubWorkflow,
            BuiltinCatalogSurface::Workspace => CatalogSurface::Workspace,
        },
        default_presets: entry.default_presets,
        detection_class: match entry.detection_class {
            BuiltinCatalogDetectionClass::Structural => CatalogDetectionClass::Structural,
            BuiltinCatalogDetectionClass::Heuristic => CatalogDetectionClass::Heuristic,
        },
        lifecycle: match entry.lifecycle {
            BuiltinCatalogRuleLifecycle::Preview {
                blocker,
                promotion_requirements,
            } => CatalogRuleLifecycle::Preview {
                blocker,
                promotion_requirements,
            },
            BuiltinCatalogRuleLifecycle::Stable {
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
            BuiltinCatalogRemediationSupport::SafeFix => CatalogRemediationSupport::SafeFix,
            BuiltinCatalogRemediationSupport::Suggestion => CatalogRemediationSupport::Suggestion,
            BuiltinCatalogRemediationSupport::MessageOnly => CatalogRemediationSupport::MessageOnly,
            BuiltinCatalogRemediationSupport::None => CatalogRemediationSupport::None,
        },
    }
}
