use std::collections::BTreeSet;

use lintai_ai_security::{
    NativeCatalogDetectionClass, NativeCatalogRemediationSupport, NativeCatalogRuleLifecycle,
    NativeCatalogSurface, native_rule_catalog_entries,
};
use lintai_api::{
    CatalogDetectionClassKind, CatalogLifecycleClass, CatalogRuleIdentity, RuleMetadata,
    validate_rule_identities, validate_rule_presets, validate_rule_quality_contract,
};
use lintai_dep_vulns::{
    DepVulnDetectionClass, DepVulnRemediationSupport, DepVulnRuleLifecycle, DepVulnSurface,
    dep_vuln_rule_catalog_entries,
};
use lintai_policy::{
    PolicyDetectionClass, PolicyRemediationSupport, PolicyRuleLifecycle, PolicySurface,
    policy_rule_catalog_entries,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinRuleScope {
    PerFile,
    Workspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinCatalogSurface {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinCatalogDetectionClass {
    Structural,
    Heuristic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinCatalogRuleLifecycle {
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
pub enum BuiltinCatalogRemediationSupport {
    SafeFix,
    Suggestion,
    MessageOnly,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuiltinRuleCatalogEntry {
    pub metadata: RuleMetadata,
    pub provider_id: &'static str,
    pub scope: BuiltinRuleScope,
    pub surface: BuiltinCatalogSurface,
    pub default_presets: &'static [&'static str],
    pub detection_class: BuiltinCatalogDetectionClass,
    pub lifecycle: BuiltinCatalogRuleLifecycle,
    pub remediation_support: BuiltinCatalogRemediationSupport,
}

pub fn builtin_rule_catalog_entries() -> Vec<BuiltinRuleCatalogEntry> {
    let mut entries = native_rule_catalog_entries()
        .into_iter()
        .map(|entry| BuiltinRuleCatalogEntry {
            metadata: entry.metadata,
            provider_id: entry.provider_id,
            scope: BuiltinRuleScope::PerFile,
            surface: match entry.surface {
                NativeCatalogSurface::Markdown => BuiltinCatalogSurface::Markdown,
                NativeCatalogSurface::Hook => BuiltinCatalogSurface::Hook,
                NativeCatalogSurface::Devcontainer => BuiltinCatalogSurface::Devcontainer,
                NativeCatalogSurface::DockerCompose => BuiltinCatalogSurface::DockerCompose,
                NativeCatalogSurface::Dockerfile => BuiltinCatalogSurface::Dockerfile,
                NativeCatalogSurface::Json => BuiltinCatalogSurface::Json,
                NativeCatalogSurface::ClaudeSettings => BuiltinCatalogSurface::ClaudeSettings,
                NativeCatalogSurface::ToolJson => BuiltinCatalogSurface::ToolJson,
                NativeCatalogSurface::ServerJson => BuiltinCatalogSurface::ServerJson,
                NativeCatalogSurface::GithubWorkflow => BuiltinCatalogSurface::GithubWorkflow,
            },
            default_presets: entry.default_presets,
            detection_class: match entry.detection_class {
                NativeCatalogDetectionClass::Structural => BuiltinCatalogDetectionClass::Structural,
                NativeCatalogDetectionClass::Heuristic => BuiltinCatalogDetectionClass::Heuristic,
            },
            lifecycle: match entry.lifecycle {
                NativeCatalogRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => BuiltinCatalogRuleLifecycle::Preview {
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
                } => BuiltinCatalogRuleLifecycle::Stable {
                    rationale,
                    malicious_case_ids,
                    benign_case_ids,
                    requires_structured_evidence,
                    remediation_reviewed,
                    deterministic_signal_basis,
                },
            },
            remediation_support: match entry.remediation_support {
                NativeCatalogRemediationSupport::SafeFix => {
                    BuiltinCatalogRemediationSupport::SafeFix
                }
                NativeCatalogRemediationSupport::Suggestion => {
                    BuiltinCatalogRemediationSupport::Suggestion
                }
                NativeCatalogRemediationSupport::MessageOnly => {
                    BuiltinCatalogRemediationSupport::MessageOnly
                }
                NativeCatalogRemediationSupport::None => BuiltinCatalogRemediationSupport::None,
            },
        })
        .collect::<Vec<_>>();
    entries.extend(policy_rule_catalog_entries().iter().copied().map(|entry| {
        BuiltinRuleCatalogEntry {
            metadata: entry.metadata,
            provider_id: entry.provider_id,
            scope: BuiltinRuleScope::Workspace,
            surface: match entry.surface {
                PolicySurface::Workspace => BuiltinCatalogSurface::Workspace,
            },
            default_presets: entry.default_presets,
            detection_class: match entry.detection_class {
                PolicyDetectionClass::Structural => BuiltinCatalogDetectionClass::Structural,
            },
            lifecycle: match entry.lifecycle {
                PolicyRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => BuiltinCatalogRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                },
            },
            remediation_support: match entry.remediation_support {
                PolicyRemediationSupport::None => BuiltinCatalogRemediationSupport::None,
            },
        }
    }));
    entries.extend(
        dep_vuln_rule_catalog_entries()
            .iter()
            .copied()
            .map(|entry| BuiltinRuleCatalogEntry {
                metadata: entry.metadata,
                provider_id: entry.provider_id,
                scope: BuiltinRuleScope::Workspace,
                surface: match entry.surface {
                    DepVulnSurface::Workspace => BuiltinCatalogSurface::Workspace,
                },
                default_presets: entry.default_presets,
                detection_class: match entry.detection_class {
                    DepVulnDetectionClass::Structural => BuiltinCatalogDetectionClass::Structural,
                },
                lifecycle: match entry.lifecycle {
                    DepVulnRuleLifecycle::Preview {
                        blocker,
                        promotion_requirements,
                    } => BuiltinCatalogRuleLifecycle::Preview {
                        blocker,
                        promotion_requirements,
                    },
                },
                remediation_support: match entry.remediation_support {
                    DepVulnRemediationSupport::Suggestion => {
                        BuiltinCatalogRemediationSupport::Suggestion
                    }
                },
            }),
    );
    validate_builtin_rule_catalog_entries(&entries);
    entries
}

pub fn builtin_known_rule_codes() -> BTreeSet<String> {
    builtin_rule_catalog_entries()
        .into_iter()
        .map(|entry| entry.metadata.code.to_owned())
        .collect()
}

pub fn builtin_rule_codes_for_preset(preset: &str) -> BTreeSet<String> {
    builtin_rule_catalog_entries()
        .into_iter()
        .filter(|entry| entry.default_presets.contains(&preset))
        .map(|entry| entry.metadata.code.to_owned())
        .collect()
}

fn validate_builtin_rule_catalog_entries(entries: &[BuiltinRuleCatalogEntry]) {
    let mut provider_rule_ids = BTreeSet::new();
    validate_rule_identities(
        "builtin",
        entries.iter().map(|entry| CatalogRuleIdentity {
            owner: entry.metadata.code,
            code: entry.metadata.code,
            doc_title: entry.metadata.doc_title,
        }),
    );

    for entry in entries {
        let provider_rule_id = (entry.provider_id, entry.metadata.code);
        assert!(
            provider_rule_ids.insert(provider_rule_id),
            "duplicate builtin provider/rule pair {}:{}",
            entry.provider_id,
            entry.metadata.code
        );
        validate_rule_presets("builtin", entry.metadata.code, entry.default_presets);
        validate_rule_quality_contract(
            "builtin",
            entry.metadata.code,
            entry.metadata.tier,
            match entry.detection_class {
                BuiltinCatalogDetectionClass::Structural => CatalogDetectionClassKind::Structural,
                BuiltinCatalogDetectionClass::Heuristic => CatalogDetectionClassKind::Heuristic,
            },
            match entry.lifecycle {
                BuiltinCatalogRuleLifecycle::Preview { .. } => CatalogLifecycleClass::Preview,
                BuiltinCatalogRuleLifecycle::Stable { .. } => CatalogLifecycleClass::Stable,
            },
            entry.default_presets,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::builtin_rule_catalog_entries;

    #[test]
    fn builtin_rule_catalog_entries_pass_validation_contracts() {
        let entries = builtin_rule_catalog_entries();
        assert!(
            !entries.is_empty(),
            "builtin rule catalog should not be empty"
        );
    }
}
