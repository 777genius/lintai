use lintai_api::{RuleMetadata, RuleTier};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuleScope {
    PerFile,
    Workspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatalogSurface {
    Markdown,
    Hook,
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
    pub(crate) default_presets: &'static [&'static str],
    pub(crate) detection_class: CatalogDetectionClass,
    pub(crate) lifecycle: CatalogRuleLifecycle,
    pub(crate) remediation_support: CatalogRemediationSupport,
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
