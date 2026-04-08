use lintai_api::{ProviderScanResult, WorkspaceRuleProvider, WorkspaceScanContext};

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
        let active_rule_codes = ctx.active_rule_codes.as_ref();
        let exec_rule_active =
            is_rule_active(active_rule_codes, ProjectExecMismatchRule::METADATA.code);
        let network_rule_active =
            is_rule_active(active_rule_codes, ProjectNetworkMismatchRule::METADATA.code);
        let capability_rule_active =
            is_rule_active(active_rule_codes, CapabilityConflictRule::METADATA.code);

        if !(exec_rule_active || network_rule_active || capability_rule_active) {
            return ProviderScanResult::new(Vec::new(), Vec::new());
        }

        let Some(project_capabilities) = ctx.project_capabilities.as_ref() else {
            return ProviderScanResult::new(Vec::new(), Vec::new());
        };

        let mut findings = Vec::new();
        for artifact in &ctx.artifacts {
            if exec_rule_active
                && exec_forbidden(project_capabilities)
                && artifact_observes_exec(artifact)
            {
                findings.push(policy_finding(
                    &ProjectExecMismatchRule::METADATA,
                    artifact,
                    "project policy declares `exec: none`, but this artifact contains executable behavior",
                    ctx.capability_conflict_mode,
                ));
            }

            if network_rule_active
                && network_forbidden(project_capabilities)
                && artifact_observes_network(artifact)
            {
                findings.push(policy_finding(
                    &ProjectNetworkMismatchRule::METADATA,
                    artifact,
                    "project policy declares `network: none`, but this artifact contains network behavior",
                    ctx.capability_conflict_mode,
                ));
            }

            if capability_rule_active
                && let Some(frontmatter_caps) = artifact.capabilities.as_ref()
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

fn is_rule_active(
    active_rule_codes: Option<&std::collections::BTreeSet<String>>,
    rule_code: &str,
) -> bool {
    active_rule_codes.is_none_or(|active| active.contains(rule_code))
}

#[cfg(test)]
mod tests {
    use super::PolicyMismatchProvider;
    use lintai_api::{
        Artifact, ArtifactKind, CapabilityProfile, DocumentSemantics, ExecCapability,
        FrontmatterFormat, FrontmatterSemantics, MarkdownSemantics, NetworkCapability,
        ParsedDocument, SourceFormat, WorkspaceArtifact, WorkspaceRuleProvider,
        WorkspaceScanContext,
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
    fn workspace_check_skips_when_policy_rules_are_inactive() {
        let mut project = CapabilityProfile::default();
        project.exec = Some(ExecCapability::None);

        let result = WorkspaceRuleProvider::check_workspace_result(
            &PolicyMismatchProvider,
            &WorkspaceScanContext::new(
                None,
                vec![workspace_artifact(
                    ArtifactKind::CursorHookScript,
                    "echo hi",
                    None,
                )],
                Some(project),
                lintai_api::CapabilityConflictMode::Warn,
            )
            .with_active_rule_codes(std::collections::BTreeSet::from(["SEC101".to_owned()])),
        );

        assert!(result.errors.is_empty());
        assert!(result.findings.is_empty());
    }

    #[test]
    fn workspace_check_only_reports_active_policy_rule_codes() {
        let mut project = CapabilityProfile::default();
        project.exec = Some(ExecCapability::None);
        project.network = Some(NetworkCapability::None);

        let result = WorkspaceRuleProvider::check_workspace_result(
            &PolicyMismatchProvider,
            &WorkspaceScanContext::new(
                None,
                vec![workspace_artifact(
                    ArtifactKind::CursorHookScript,
                    "curl https://example.com",
                    None,
                )],
                Some(project),
                lintai_api::CapabilityConflictMode::Warn,
            )
            .with_active_rule_codes(std::collections::BTreeSet::from([
                crate::catalog::ProjectNetworkMismatchRule::METADATA
                    .code
                    .to_owned(),
            ])),
        );

        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].rule_code,
            crate::catalog::ProjectNetworkMismatchRule::METADATA.code
        );
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
}
