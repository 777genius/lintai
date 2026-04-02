use lintai_api::{RuleMetadata, RuleTier};
use lintai_builtins::BuiltinRuleCatalogEntry;

pub(crate) use lintai_builtins::{
    BuiltinCatalogDetectionClass as CatalogDetectionClass,
    BuiltinCatalogRemediationSupport as CatalogRemediationSupport,
    BuiltinCatalogRuleLifecycle as CatalogRuleLifecycle, BuiltinCatalogSurface as CatalogSurface,
    BuiltinRuleScope as RuleScope,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SecurityRuleCatalogEntry {
    pub(crate) metadata: RuleMetadata,
    pub(crate) provider_id: &'static str,
    pub(crate) scope: RuleScope,
    pub(crate) surface: CatalogSurface,
    pub(crate) default_presets: &'static [&'static str],
    pub(crate) detection_class: CatalogDetectionClass,
    pub(crate) lifecycle: CatalogRuleLifecycle,
    pub(crate) remediation_support: CatalogRemediationSupport,
}

impl From<BuiltinRuleCatalogEntry> for SecurityRuleCatalogEntry {
    fn from(entry: BuiltinRuleCatalogEntry) -> Self {
        Self {
            metadata: entry.metadata,
            provider_id: entry.provider_id,
            scope: entry.scope,
            surface: entry.surface,
            default_presets: entry.default_presets,
            detection_class: entry.detection_class,
            lifecycle: entry.lifecycle,
            remediation_support: entry.remediation_support,
        }
    }
}

impl SecurityRuleCatalogEntry {
    pub(crate) fn default_presets(self) -> Vec<&'static str> {
        self.default_presets.to_vec()
    }

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
