use crate::RuleMetadata;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogRuleScope {
    PerFile,
    Workspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogSurface {
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
pub enum CatalogDetectionClass {
    Structural,
    Heuristic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogRuleLifecycle {
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
pub enum CatalogRemediationSupport {
    SafeFix,
    Suggestion,
    MessageOnly,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogRuleEntry {
    pub metadata: RuleMetadata,
    pub provider_id: &'static str,
    pub scope: CatalogRuleScope,
    pub surface: CatalogSurface,
    pub default_presets: &'static [&'static str],
    pub detection_class: CatalogDetectionClass,
    pub lifecycle: CatalogRuleLifecycle,
    pub remediation_support: CatalogRemediationSupport,
}
