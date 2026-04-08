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
                && capabilities_conflict(project_capabilities, frontmatter_caps)
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

#[cfg(test)]
mod tests {
    use super::PolicyMismatchProvider;
    use lintai_api::{
        Artifact, ArtifactKind, CapabilityProfile, DocumentSemantics, ExecCapability,
        FrontmatterFormat, FrontmatterSemantics, MarkdownSemantics, NetworkCapability,
        ParsedDocument, RuleProvider, ScanContext, SourceFormat, WorkspaceArtifact,
        WorkspaceRuleProvider, WorkspaceScanContext,
    };
    use serde_json::json;

    fn workspace_artifact(
        kind: ArtifactKind,
        content: &str,
        semantics: Option<DocumentSemantics>,
    ) -> WorkspaceArtifact {
        WorkspaceArtifact::new(
            Artifact::new("repo/file", kind, SourceFormat::Markdown),
            content,
            ParsedDocument::new(Vec::new(), None),
            semantics,
        )
    }

    #[test]
    fn workspace_check_no_project_capabilities_reports_no_findings() {
        let provider = PolicyMismatchProvider;
        let result = WorkspaceRuleProvider::check_workspace_result(
            &provider,
            &WorkspaceScanContext::new(
                None,
                vec![workspace_artifact(ArtifactKind::PackageManifest, "", None)],
                None,
                lintai_api::CapabilityConflictMode::Warn,
            ),
        );

        assert!(result.errors.is_empty());
        assert!(result.findings.is_empty());
    }

    #[test]
    fn workspace_check_flags_exec_and_network_mismatches() {
        let mut project = CapabilityProfile::default();
        project.exec = Some(ExecCapability::None);
        project.network = Some(NetworkCapability::None);

        let exec_artifact = workspace_artifact(ArtifactKind::CursorHookScript, "echo hi", None);
        let network_artifact = workspace_artifact(
            ArtifactKind::CursorHookScript,
            "curl https://example.com",
            None,
        );

        let result = WorkspaceRuleProvider::check_workspace_result(
            &PolicyMismatchProvider,
            &WorkspaceScanContext::new(
                None,
                vec![exec_artifact, network_artifact],
                Some(project),
                lintai_api::CapabilityConflictMode::Warn,
            ),
        );

        assert_eq!(result.findings.len(), 3);
        let codes = result
            .findings
            .iter()
            .map(|finding| finding.rule_code.as_str())
            .collect::<std::collections::HashSet<_>>();
        assert!(codes.contains(&crate::catalog::ProjectExecMismatchRule::METADATA.code));
        assert!(codes.contains(&crate::catalog::ProjectNetworkMismatchRule::METADATA.code));
    }

    #[test]
    fn workspace_check_flags_frontmatter_conflict_when_skill_requests_more_capability() {
        let mut project = CapabilityProfile::default();
        project.exec = Some(ExecCapability::None);

        let artifact = workspace_artifact(
            ArtifactKind::Instructions,
            "{}",
            Some(DocumentSemantics::Markdown(MarkdownSemantics::new(Some(
                FrontmatterSemantics::new(
                    FrontmatterFormat::Yaml,
                    json!({"capabilities": {"exec": "shell"}}),
                ),
            )))),
        );

        let result = WorkspaceRuleProvider::check_workspace_result(
            &PolicyMismatchProvider,
            &WorkspaceScanContext::new(
                None,
                vec![artifact],
                Some(project),
                lintai_api::CapabilityConflictMode::Warn,
            ),
        );

        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].rule_code,
            crate::catalog::CapabilityConflictRule::METADATA.code
        );
    }

    #[test]
    fn rule_provider_check_result_reports_workspace_misuse() {
        let provider = PolicyMismatchProvider;
        let result = provider.check_result(&ScanContext::new(
            Artifact::new(
                "repo/file",
                ArtifactKind::Instructions,
                SourceFormat::Markdown,
            ),
            "",
            ParsedDocument::new(Vec::new(), None),
            None,
        ));

        assert_eq!(result.errors.len(), 1);
        assert_eq!(
            result.errors[0].message,
            "workspace provider cannot run in file phase"
        );
    }
}
