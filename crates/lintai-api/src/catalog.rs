use crate::RuleMetadata;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogRuleScope {
    PerFile,
    Workspace,
}

impl CatalogRuleScope {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::PerFile => "per_file",
            Self::Workspace => "workspace",
        }
    }
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

impl CatalogSurface {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::Hook => "hook",
            Self::Devcontainer => "devcontainer",
            Self::DockerCompose => "docker-compose",
            Self::Dockerfile => "dockerfile",
            Self::Json => "json",
            Self::ClaudeSettings => "claude_settings",
            Self::ToolJson => "tool_json",
            Self::ServerJson => "server_json",
            Self::GithubWorkflow => "github_workflow",
            Self::Workspace => "workspace",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogDetectionClass {
    Structural,
    Heuristic,
}

impl CatalogDetectionClass {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Structural => "structural",
            Self::Heuristic => "heuristic",
        }
    }
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

impl CatalogRemediationSupport {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::SafeFix => "safe_fix",
            Self::Suggestion => "suggestion",
            Self::MessageOnly => "message_only",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogPublicLane {
    Recommended,
    Preview,
    Governance,
    Guidance,
    SupplyChain,
    Compat,
    Advisory,
}

impl CatalogPublicLane {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Recommended => "recommended",
            Self::Preview => "preview",
            Self::Governance => "governance",
            Self::Guidance => "guidance",
            Self::SupplyChain => "supply-chain",
            Self::Compat => "compat",
            Self::Advisory => "advisory",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogRuleEntry {
    pub metadata: RuleMetadata,
    pub provider_id: &'static str,
    pub scope: CatalogRuleScope,
    pub surface: CatalogSurface,
    pub default_presets: &'static [&'static str],
    pub public_lane: CatalogPublicLane,
    pub detection_class: CatalogDetectionClass,
    pub lifecycle: CatalogRuleLifecycle,
    pub remediation_support: CatalogRemediationSupport,
}

#[cfg(test)]
mod tests {
    use super::{
        CatalogDetectionClass, CatalogPublicLane, CatalogRemediationSupport, CatalogRuleScope,
        CatalogSurface,
    };

    #[test]
    fn catalog_taxonomy_slugs_are_stable() {
        assert_eq!(CatalogRuleScope::PerFile.slug(), "per_file");
        assert_eq!(CatalogRuleScope::Workspace.slug(), "workspace");
        assert_eq!(CatalogSurface::GithubWorkflow.slug(), "github_workflow");
        assert_eq!(CatalogDetectionClass::Heuristic.slug(), "heuristic");
        assert_eq!(CatalogPublicLane::Governance.slug(), "governance");
        assert_eq!(CatalogPublicLane::Guidance.slug(), "guidance");
        assert_eq!(CatalogPublicLane::SupplyChain.slug(), "supply-chain");
        assert_eq!(CatalogPublicLane::Compat.slug(), "compat");
        assert_eq!(CatalogPublicLane::Advisory.slug(), "advisory");
        assert_eq!(
            CatalogRemediationSupport::MessageOnly.slug(),
            "message_only"
        );
    }
}
