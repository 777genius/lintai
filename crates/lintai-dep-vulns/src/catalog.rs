use lintai_api::{RuleMetadata, RuleTier, declare_rule};

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
        summary: "Installed npm dependency version matches a bundled vulnerability advisory",
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
        blocker: "Bundled advisory coverage is intentionally small in the first release and needs broader snapshot discipline before Stable.",
        promotion_requirements: WORKSPACE_PREVIEW_REQUIREMENTS,
    },
    remediation_support: DepVulnRemediationSupport::Suggestion,
}];

pub fn dep_vuln_rule_catalog_entries() -> &'static [DepVulnRuleCatalogEntry] {
    &DEP_VULN_RULE_CATALOG_ENTRIES
}
