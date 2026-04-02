use lintai_api::{
    CatalogDetectionClass, CatalogRemediationSupport, CatalogRuleEntry, CatalogRuleLifecycle,
    CatalogRuleScope, CatalogSurface, RuleMetadata, RuleTier, declare_rule,
};

use crate::PROVIDER_ID;

pub const WORKSPACE_PREVIEW_REQUIREMENTS: &str = "Needs workspace precision review, linked benign/malicious corpus proof, and completed stable checklist metadata.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyDetectionClass {
    Structural,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyRuleLifecycle {
    Preview {
        blocker: &'static str,
        promotion_requirements: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyRemediationSupport {
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicySurface {
    Workspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyRuleCatalogEntry {
    pub metadata: RuleMetadata,
    pub provider_id: &'static str,
    pub surface: PolicySurface,
    pub default_presets: &'static [&'static str],
    pub detection_class: PolicyDetectionClass,
    pub lifecycle: PolicyRuleLifecycle,
    pub remediation_support: PolicyRemediationSupport,
}

const COMPAT_PRESETS: &[&str] = &["compat"];

declare_rule! {
    pub struct ProjectExecMismatchRule {
        code: "SEC401",
        summary: "Project policy forbids execution, but repository contains executable behavior",
        doc_title: "Policy mismatch: execution",
        category: lintai_api::Category::Audit,
        default_severity: lintai_api::Severity::Warn,
        default_confidence: lintai_api::Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ProjectNetworkMismatchRule {
        code: "SEC402",
        summary: "Project policy forbids network access, but repository contains network behavior",
        doc_title: "Policy mismatch: network access",
        category: lintai_api::Category::Audit,
        default_severity: lintai_api::Severity::Warn,
        default_confidence: lintai_api::Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CapabilityConflictRule {
        code: "SEC403",
        summary: "Skill frontmatter capabilities conflict with project policy",
        doc_title: "Skill capabilities mismatch",
        category: lintai_api::Category::Audit,
        default_severity: lintai_api::Severity::Warn,
        default_confidence: lintai_api::Confidence::High,
        tier: RuleTier::Preview,
    }
}

pub const POLICY_RULES: [RuleMetadata; 3] = [
    ProjectExecMismatchRule::METADATA,
    ProjectNetworkMismatchRule::METADATA,
    CapabilityConflictRule::METADATA,
];

const POLICY_RULE_CATALOG_ENTRIES: [PolicyRuleCatalogEntry; 3] = [
    PolicyRuleCatalogEntry {
        metadata: ProjectExecMismatchRule::METADATA,
        provider_id: PROVIDER_ID,
        surface: PolicySurface::Workspace,
        default_presets: COMPAT_PRESETS,
        detection_class: PolicyDetectionClass::Structural,
        lifecycle: PolicyRuleLifecycle::Preview {
            blocker: "Needs workspace-level precision review and linked graduation corpus before promotion to Stable.",
            promotion_requirements: WORKSPACE_PREVIEW_REQUIREMENTS,
        },
        remediation_support: PolicyRemediationSupport::None,
    },
    PolicyRuleCatalogEntry {
        metadata: ProjectNetworkMismatchRule::METADATA,
        provider_id: PROVIDER_ID,
        surface: PolicySurface::Workspace,
        default_presets: COMPAT_PRESETS,
        detection_class: PolicyDetectionClass::Structural,
        lifecycle: PolicyRuleLifecycle::Preview {
            blocker: "Needs workspace-level network precision review and linked graduation corpus before promotion to Stable.",
            promotion_requirements: WORKSPACE_PREVIEW_REQUIREMENTS,
        },
        remediation_support: PolicyRemediationSupport::None,
    },
    PolicyRuleCatalogEntry {
        metadata: CapabilityConflictRule::METADATA,
        provider_id: PROVIDER_ID,
        surface: PolicySurface::Workspace,
        default_presets: COMPAT_PRESETS,
        detection_class: PolicyDetectionClass::Structural,
        lifecycle: PolicyRuleLifecycle::Preview {
            blocker: "Needs workspace-level capability-conflict precision review and linked graduation corpus before promotion to Stable.",
            promotion_requirements: WORKSPACE_PREVIEW_REQUIREMENTS,
        },
        remediation_support: PolicyRemediationSupport::None,
    },
];

pub fn policy_rule_catalog_entries() -> &'static [PolicyRuleCatalogEntry] {
    &POLICY_RULE_CATALOG_ENTRIES
}

impl From<PolicyRuleCatalogEntry> for CatalogRuleEntry {
    fn from(entry: PolicyRuleCatalogEntry) -> Self {
        Self {
            metadata: entry.metadata,
            provider_id: entry.provider_id,
            scope: CatalogRuleScope::Workspace,
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
}

#[cfg(test)]
mod tests {
    use lintai_api::{
        CatalogDetectionClass, CatalogRemediationSupport, CatalogRuleEntry, CatalogRuleLifecycle,
        CatalogRuleScope, CatalogSurface,
    };

    use super::policy_rule_catalog_entries;

    #[test]
    fn policy_catalog_entries_convert_to_shared_catalog_entries() {
        for entry in policy_rule_catalog_entries().iter().copied() {
            let converted = CatalogRuleEntry::from(entry);
            assert_eq!(converted.metadata, entry.metadata);
            assert_eq!(converted.provider_id, entry.provider_id);
            assert_eq!(converted.scope, CatalogRuleScope::Workspace);
            assert_eq!(converted.surface, CatalogSurface::Workspace);
            assert_eq!(converted.default_presets, entry.default_presets);
            assert_eq!(converted.detection_class, CatalogDetectionClass::Structural);
            assert_eq!(
                converted.remediation_support,
                CatalogRemediationSupport::None
            );
            match (entry.lifecycle, converted.lifecycle) {
                (
                    super::PolicyRuleLifecycle::Preview {
                        blocker: expected_blocker,
                        promotion_requirements: expected_requirements,
                    },
                    CatalogRuleLifecycle::Preview {
                        blocker,
                        promotion_requirements,
                    },
                ) => {
                    assert_eq!(blocker, expected_blocker);
                    assert_eq!(promotion_requirements, expected_requirements);
                }
                _ => panic!(
                    "policy lifecycle conversion drifted for {}",
                    entry.metadata.code
                ),
            }
        }
    }
}
