use lintai_api::{
    CatalogDetectionClass, CatalogRemediationSupport, CatalogRuleEntry, CatalogRuleLifecycle,
    CatalogRuleScope, CatalogSurface, RuleMetadata, RuleTier, declare_rule,
};

use crate::PROVIDER_ID;

pub const WORKSPACE_PREVIEW_REQUIREMENTS: &str = "Needs larger advisory snapshot coverage, cross-lockfile corpus proof, and stable review of package/version matching before promotion to Stable.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepVulnDetectionClass {
    Structural,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepVulnRuleLifecycle {
    Preview {
        blocker: &'static str,
        promotion_requirements: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepVulnRemediationSupport {
    Suggestion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepVulnSurface {
    Workspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepVulnRuleCatalogEntry {
    pub metadata: RuleMetadata,
    pub provider_id: &'static str,
    pub surface: DepVulnSurface,
    pub default_presets: &'static [&'static str],
    pub detection_class: DepVulnDetectionClass,
    pub lifecycle: DepVulnRuleLifecycle,
    pub remediation_support: DepVulnRemediationSupport,
}

const ADVISORY_PRESETS: &[&str] = &["advisory"];

declare_rule! {
    pub struct InstalledVulnerableDependencyRule {
        code: "SEC756",
        summary: "Installed npm dependency version matches an offline vulnerability advisory",
        doc_title: "Dependency vulnerability: installed npm package version",
        category: lintai_api::Category::Security,
        default_severity: lintai_api::Severity::Warn,
        default_confidence: lintai_api::Confidence::High,
        tier: RuleTier::Preview,
    }
}

const DEP_VULN_RULE_CATALOG_ENTRIES: [DepVulnRuleCatalogEntry; 1] = [DepVulnRuleCatalogEntry {
    metadata: InstalledVulnerableDependencyRule::METADATA,
    provider_id: PROVIDER_ID,
    surface: DepVulnSurface::Workspace,
    default_presets: ADVISORY_PRESETS,
    detection_class: DepVulnDetectionClass::Structural,
    lifecycle: DepVulnRuleLifecycle::Preview {
        blocker: "Initial advisory snapshot coverage is intentionally small in the first release and needs broader snapshot discipline before Stable.",
        promotion_requirements: WORKSPACE_PREVIEW_REQUIREMENTS,
    },
    remediation_support: DepVulnRemediationSupport::Suggestion,
}];

pub fn dep_vuln_rule_catalog_entries() -> &'static [DepVulnRuleCatalogEntry] {
    &DEP_VULN_RULE_CATALOG_ENTRIES
}

impl From<DepVulnRuleCatalogEntry> for CatalogRuleEntry {
    fn from(entry: DepVulnRuleCatalogEntry) -> Self {
        Self {
            metadata: entry.metadata,
            provider_id: entry.provider_id,
            scope: CatalogRuleScope::Workspace,
            surface: match entry.surface {
                DepVulnSurface::Workspace => CatalogSurface::Workspace,
            },
            default_presets: entry.default_presets,
            detection_class: match entry.detection_class {
                DepVulnDetectionClass::Structural => CatalogDetectionClass::Structural,
            },
            lifecycle: match entry.lifecycle {
                DepVulnRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => CatalogRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                },
            },
            remediation_support: match entry.remediation_support {
                DepVulnRemediationSupport::Suggestion => CatalogRemediationSupport::Suggestion,
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

    use super::dep_vuln_rule_catalog_entries;

    #[test]
    fn dep_vuln_catalog_entries_convert_to_shared_catalog_entries() {
        for entry in dep_vuln_rule_catalog_entries().iter().copied() {
            let converted = CatalogRuleEntry::from(entry);
            assert_eq!(converted.metadata, entry.metadata);
            assert_eq!(converted.provider_id, entry.provider_id);
            assert_eq!(converted.scope, CatalogRuleScope::Workspace);
            assert_eq!(converted.surface, CatalogSurface::Workspace);
            assert_eq!(converted.default_presets, entry.default_presets);
            assert_eq!(converted.detection_class, CatalogDetectionClass::Structural);
            assert_eq!(
                converted.remediation_support,
                CatalogRemediationSupport::Suggestion
            );
            match (entry.lifecycle, converted.lifecycle) {
                (
                    super::DepVulnRuleLifecycle::Preview {
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
                    "dependency-vuln lifecycle conversion drifted for {}",
                    entry.metadata.code
                ),
            }
        }
    }
}
