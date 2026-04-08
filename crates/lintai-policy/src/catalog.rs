use std::sync::OnceLock;

use lintai_api::{
    CatalogDetectionClass, CatalogPublicLane, CatalogRemediationSupport, CatalogRuleEntry,
    CatalogRuleLifecycle, CatalogRuleScope, CatalogSurface, RuleMetadata, RuleTier, declare_rule,
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
    pub public_lane: CatalogPublicLane,
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
        public_lane: CatalogPublicLane::Compat,
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
        public_lane: CatalogPublicLane::Compat,
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
        public_lane: CatalogPublicLane::Compat,
        detection_class: PolicyDetectionClass::Structural,
        lifecycle: PolicyRuleLifecycle::Preview {
            blocker: "Needs workspace-level capability-conflict precision review and linked graduation corpus before promotion to Stable.",
            promotion_requirements: WORKSPACE_PREVIEW_REQUIREMENTS,
        },
        remediation_support: PolicyRemediationSupport::None,
    },
];

pub fn policy_shared_rule_catalog_entries() -> &'static [CatalogRuleEntry] {
    static ENTRIES: OnceLock<Vec<CatalogRuleEntry>> = OnceLock::new();

    ENTRIES
        .get_or_init(|| {
            policy_rule_catalog_entries()
                .iter()
                .copied()
                .map(CatalogRuleEntry::from)
                .collect()
        })
        .as_slice()
}

pub fn policy_rule_catalog_entries() -> &'static [PolicyRuleCatalogEntry] {
    &POLICY_RULE_CATALOG_ENTRIES
}

impl TryFrom<CatalogRuleEntry> for PolicyRuleCatalogEntry {
    type Error = String;

    fn try_from(entry: CatalogRuleEntry) -> Result<Self, Self::Error> {
        if entry.scope != CatalogRuleScope::Workspace {
            return Err(format!(
                "policy shared catalog entry {} unexpectedly declared {:?} scope",
                entry.metadata.code, entry.scope
            ));
        }
        Ok(Self {
            metadata: entry.metadata,
            provider_id: entry.provider_id,
            surface: match entry.surface {
                CatalogSurface::Workspace => PolicySurface::Workspace,
                other => {
                    return Err(format!(
                        "policy shared catalog entry {} cannot declare surface {:?}",
                        entry.metadata.code, other
                    ));
                }
            },
            default_presets: entry.default_presets,
            public_lane: entry.public_lane,
            detection_class: match entry.detection_class {
                CatalogDetectionClass::Structural => PolicyDetectionClass::Structural,
                CatalogDetectionClass::Heuristic => {
                    return Err(format!(
                        "policy shared catalog entry {} cannot declare heuristic detection",
                        entry.metadata.code
                    ));
                }
            },
            lifecycle: match entry.lifecycle {
                CatalogRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => PolicyRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                },
                CatalogRuleLifecycle::Stable { .. } => {
                    return Err(format!(
                        "policy shared catalog entry {} cannot declare stable lifecycle",
                        entry.metadata.code
                    ));
                }
            },
            remediation_support: match entry.remediation_support {
                CatalogRemediationSupport::None => PolicyRemediationSupport::None,
                other => {
                    return Err(format!(
                        "policy shared catalog entry {} cannot declare remediation {:?}",
                        entry.metadata.code, other
                    ));
                }
            },
        })
    }
}

impl From<PolicyRuleCatalogEntry> for CatalogRuleEntry {
    fn from(entry: PolicyRuleCatalogEntry) -> Self {
        Self {
            metadata: entry.metadata,
            provider_id: entry.provider_id,
            scope: CatalogRuleScope::Workspace,
            surface: CatalogSurface::Workspace,
            default_presets: entry.default_presets,
            public_lane: entry.public_lane,
            detection_class: CatalogDetectionClass::Structural,
            lifecycle: match entry.lifecycle {
                PolicyRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => CatalogRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                },
            },
            remediation_support: CatalogRemediationSupport::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use lintai_api::{
        CatalogDetectionClass, CatalogPublicLane, CatalogRemediationSupport, CatalogRuleEntry,
        CatalogRuleLifecycle, CatalogRuleScope, CatalogSurface,
    };

    use super::{
        PolicyRuleCatalogEntry, policy_rule_catalog_entries, policy_shared_rule_catalog_entries,
    };

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

    #[test]
    fn shared_policy_catalog_entries_stay_in_sync_with_local_catalog_entries() {
        let shared = policy_shared_rule_catalog_entries();
        let local = policy_rule_catalog_entries();
        assert_eq!(shared.len(), local.len());

        for (shared_entry, local_entry) in shared.iter().copied().zip(local.iter().copied()) {
            assert_eq!(
                PolicyRuleCatalogEntry::try_from(shared_entry).unwrap(),
                local_entry
            );
        }
    }

    #[test]
    fn invalid_shared_policy_entry_returns_error_instead_of_panicking() {
        let invalid = CatalogRuleEntry {
            metadata: super::ProjectExecMismatchRule::METADATA,
            provider_id: super::PROVIDER_ID,
            scope: CatalogRuleScope::Workspace,
            surface: CatalogSurface::Workspace,
            default_presets: super::COMPAT_PRESETS,
            public_lane: CatalogPublicLane::Compat,
            detection_class: CatalogDetectionClass::Heuristic,
            lifecycle: CatalogRuleLifecycle::Preview {
                blocker: "x",
                promotion_requirements: "y",
            },
            remediation_support: CatalogRemediationSupport::None,
        };

        let error = PolicyRuleCatalogEntry::try_from(invalid).unwrap_err();
        assert!(error.contains("cannot declare heuristic detection"));
    }
}
