use lintai_api::{CatalogPublicLane, CatalogRuleEntry, RuleMetadata, RuleTier};

pub(crate) use lintai_api::{
    CatalogDetectionClass, CatalogPublicLane as PublicLane, CatalogRemediationSupport,
    CatalogRuleLifecycle, CatalogRuleScope as RuleScope, CatalogSurface,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SecurityRuleCatalogEntry {
    pub(crate) metadata: RuleMetadata,
    pub(crate) provider_id: &'static str,
    pub(crate) scope: RuleScope,
    pub(crate) surface: CatalogSurface,
    pub(crate) default_presets: &'static [&'static str],
    pub(crate) public_lane: PublicLane,
    pub(crate) detection_class: CatalogDetectionClass,
    pub(crate) lifecycle: CatalogRuleLifecycle,
    pub(crate) remediation_support: CatalogRemediationSupport,
}

impl From<CatalogRuleEntry> for SecurityRuleCatalogEntry {
    fn from(entry: CatalogRuleEntry) -> Self {
        Self {
            metadata: entry.metadata,
            provider_id: entry.provider_id,
            scope: entry.scope,
            surface: entry.surface,
            default_presets: entry.default_presets,
            public_lane: entry.public_lane,
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

    pub(crate) fn public_lane(self) -> CatalogPublicLane {
        self.public_lane
    }

    pub(crate) fn canonical_note(self) -> &'static str {
        match (self.detection_class, self.metadata.tier) {
            (CatalogDetectionClass::Structural, RuleTier::Stable)
                if self.public_lane == CatalogPublicLane::SupplyChain =>
            {
                "Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise."
            }
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
