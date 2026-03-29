use std::collections::BTreeMap;

use lintai_ai_security::{
    NativeCatalogDetectionClass, NativeCatalogRemediationSupport, NativeCatalogRuleLifecycle,
    NativeCatalogSurface, NativeRuleCatalogEntry, native_rule_catalog_entries,
};
use lintai_api::{RuleMetadata, RuleTier};
use lintai_policy::{
    PolicyDetectionClass, PolicyRemediationSupport, PolicyRuleCatalogEntry, PolicyRuleLifecycle,
    PolicySurface, policy_rule_catalog_entries,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuleScope {
    PerFile,
    Workspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatalogSurface {
    Markdown,
    Hook,
    Json,
    ClaudeSettings,
    ToolJson,
    ServerJson,
    GithubWorkflow,
    Workspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatalogDetectionClass {
    Structural,
    Heuristic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatalogRuleLifecycle {
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
pub(crate) enum CatalogRemediationSupport {
    SafeFix,
    Suggestion,
    MessageOnly,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SecurityRuleCatalogEntry {
    pub(crate) metadata: RuleMetadata,
    pub(crate) provider_id: &'static str,
    pub(crate) scope: RuleScope,
    pub(crate) surface: CatalogSurface,
    pub(crate) detection_class: CatalogDetectionClass,
    pub(crate) lifecycle: CatalogRuleLifecycle,
    pub(crate) remediation_support: CatalogRemediationSupport,
}

impl SecurityRuleCatalogEntry {
    pub(crate) fn canonical_note(self) -> &'static str {
        if self.metadata.code == "SEC324" {
            return "Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.";
        }
        match (self.detection_class, self.metadata.tier) {
            (CatalogDetectionClass::Heuristic, _) => {
                "Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves."
            }
            (CatalogDetectionClass::Structural, RuleTier::Stable) => {
                "Structural stable rule intended as a high-precision check with deterministic evidence."
            }
            (CatalogDetectionClass::Structural, RuleTier::Preview) => {
                "Structural preview rule; deterministic today, but the preview contract may still evolve."
            }
        }
    }

    pub(crate) fn lifecycle_state(self) -> &'static str {
        match self.lifecycle {
            CatalogRuleLifecycle::Preview { .. } => "preview_blocked",
            CatalogRuleLifecycle::Stable { .. } => "stable_gated",
        }
    }
}

pub(crate) fn shipped_security_rule_catalog_entries() -> Vec<SecurityRuleCatalogEntry> {
    let mut entries = Vec::new();
    entries.extend(
        native_rule_catalog_entries()
            .into_iter()
            .map(native_catalog_entry),
    );
    entries.extend(
        policy_rule_catalog_entries()
            .iter()
            .copied()
            .map(policy_catalog_entry),
    );
    entries.sort_by_key(|entry| (provider_sort_key(entry.provider_id), entry.metadata.code));
    entries
}

pub(crate) fn shipped_rule_tiers() -> BTreeMap<String, RuleTier> {
    shipped_security_rule_catalog_entries()
        .into_iter()
        .map(|entry| (entry.metadata.code.to_owned(), entry.metadata.tier))
        .collect()
}

pub(crate) fn provider_sort_key(provider_id: &str) -> usize {
    match provider_id {
        "lintai-ai-security" => 0,
        "lintai-policy-mismatch" => 1,
        _ => usize::MAX,
    }
}

fn native_catalog_entry(entry: NativeRuleCatalogEntry) -> SecurityRuleCatalogEntry {
    SecurityRuleCatalogEntry {
        metadata: entry.metadata,
        provider_id: entry.provider_id,
        scope: RuleScope::PerFile,
        surface: match entry.surface {
            NativeCatalogSurface::Markdown => CatalogSurface::Markdown,
            NativeCatalogSurface::Hook => CatalogSurface::Hook,
            NativeCatalogSurface::Json => CatalogSurface::Json,
            NativeCatalogSurface::ClaudeSettings => CatalogSurface::ClaudeSettings,
            NativeCatalogSurface::ToolJson => CatalogSurface::ToolJson,
            NativeCatalogSurface::ServerJson => CatalogSurface::ServerJson,
            NativeCatalogSurface::GithubWorkflow => CatalogSurface::GithubWorkflow,
        },
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

fn policy_catalog_entry(entry: PolicyRuleCatalogEntry) -> SecurityRuleCatalogEntry {
    SecurityRuleCatalogEntry {
        metadata: entry.metadata,
        provider_id: entry.provider_id,
        scope: RuleScope::Workspace,
        surface: match entry.surface {
            PolicySurface::Workspace => CatalogSurface::Workspace,
        },
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
