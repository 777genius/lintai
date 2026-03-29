use lintai_api::{RuleMetadata, RuleTier, declare_rule};

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
    pub detection_class: PolicyDetectionClass,
    pub lifecycle: PolicyRuleLifecycle,
    pub remediation_support: PolicyRemediationSupport,
}

declare_rule! {
    pub struct ProjectExecMismatchRule {
        code: "SEC401",
        summary: "Project policy forbids execution, but repository contains executable behavior",
        category: lintai_api::Category::Security,
        default_severity: lintai_api::Severity::Warn,
        default_confidence: lintai_api::Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ProjectNetworkMismatchRule {
        code: "SEC402",
        summary: "Project policy forbids network access, but repository contains network behavior",
        category: lintai_api::Category::Security,
        default_severity: lintai_api::Severity::Warn,
        default_confidence: lintai_api::Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CapabilityConflictRule {
        code: "SEC403",
        summary: "Skill frontmatter capabilities conflict with project policy",
        category: lintai_api::Category::Security,
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
