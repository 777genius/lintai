use lintai_api::{
    ProviderError, ProviderScanResult, RuleProvider, ScanContext, WorkspaceRuleProvider,
    WorkspaceScanContext,
};

use crate::analysis::{
    artifact_observes_exec, artifact_observes_network, capabilities_conflict, exec_forbidden,
    network_forbidden,
};
use crate::catalog::{
    CapabilityConflictRule, POLICY_RULES, ProjectExecMismatchRule, ProjectNetworkMismatchRule,
};
use crate::evidence::policy_finding;

pub const PROVIDER_ID: &str = "lintai-policy-mismatch";

pub struct PolicyMismatchProvider;

impl WorkspaceRuleProvider for PolicyMismatchProvider {
    fn id(&self) -> &str {
        PROVIDER_ID
    }

    fn rules(&self) -> &[lintai_api::RuleMetadata] {
        &POLICY_RULES
    }

    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult {
        let Some(project_capabilities) = ctx.project_capabilities.as_ref() else {
            return ProviderScanResult::new(Vec::new(), Vec::new());
        };

        let mut findings = Vec::new();
        for artifact in &ctx.artifacts {
            if exec_forbidden(project_capabilities) && artifact_observes_exec(artifact) {
                findings.push(policy_finding(
                    &ProjectExecMismatchRule::METADATA,
                    artifact,
                    "project policy declares `exec: none`, but this artifact contains executable behavior",
                    ctx.capability_conflict_mode,
                ));
            }

            if network_forbidden(project_capabilities) && artifact_observes_network(artifact) {
                findings.push(policy_finding(
                    &ProjectNetworkMismatchRule::METADATA,
                    artifact,
                    "project policy declares `network: none`, but this artifact contains network behavior",
                    ctx.capability_conflict_mode,
                ));
            }

            if let Some(frontmatter_caps) = artifact.capabilities.as_ref()
                && capabilities_conflict(project_capabilities, &frontmatter_caps)
            {
                findings.push(policy_finding(
                    &CapabilityConflictRule::METADATA,
                    artifact,
                    "skill frontmatter capabilities conflict with project policy",
                    ctx.capability_conflict_mode,
                ));
            }
        }

        ProviderScanResult::new(findings, Vec::new())
    }
}

impl RuleProvider for PolicyMismatchProvider {
    fn id(&self) -> &str {
        WorkspaceRuleProvider::id(self)
    }

    fn rules(&self) -> &[lintai_api::RuleMetadata] {
        WorkspaceRuleProvider::rules(self)
    }

    fn check_result(&self, _ctx: &ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            Vec::new(),
            vec![ProviderError::new(
                PROVIDER_ID,
                "workspace provider cannot run in file phase",
            )],
        )
    }

    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult {
        WorkspaceRuleProvider::check_workspace_result(self, ctx)
    }
}
