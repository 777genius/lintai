use lintai_api::Finding;

use crate::artifact_view::ArtifactContextRef;
use crate::provider::{ProviderCatalog, ProviderEntry};
use crate::summary::{ProviderExecutionPhase, ScanSummary};

use super::super::Engine;
use super::super::runtime::execution::ProviderExecutionRequest;
use super::projection::WorkspaceProjection;

pub(super) struct WorkspaceProviderExecutor<'engine, 'projection> {
    engine: &'engine Engine,
    projection: &'projection WorkspaceProjection,
}

impl<'engine, 'projection> WorkspaceProviderExecutor<'engine, 'projection> {
    pub(super) fn new(
        engine: &'engine Engine,
        projection: &'projection WorkspaceProjection,
    ) -> Self {
        Self { engine, projection }
    }

    pub(super) fn execute(&self, providers: &ProviderCatalog<'_>, summary: &mut ScanSummary) {
        for provider in providers.workspace() {
            self.execute_provider(provider, summary);
        }
    }

    fn execute_provider(&self, provider: &ProviderEntry<'_>, summary: &mut ScanSummary) {
        let project_root = self.projection.project_root_owned();
        self.engine.execute_provider_with_accounting(
            ProviderExecutionRequest {
                normalized_path: &project_root,
                provider,
                phase: ProviderExecutionPhase::Workspace,
            },
            summary,
            || {
                provider
                    .backend()
                    .check_workspace_result(&self.projection.workspace)
            },
            |finding, summary| self.reconcile_finding(provider, &project_root, finding, summary),
        );
    }

    fn reconcile_finding(
        &self,
        provider: &ProviderEntry<'_>,
        project_root: &str,
        finding: Finding,
        summary: &mut ScanSummary,
    ) {
        let Some(resolved) = self.projection.resolve(&finding.location.normalized_path) else {
            summary
                .diagnostics
                .push(unknown_workspace_artifact_diagnostic(
                    project_root,
                    provider.id(),
                    &finding.location.normalized_path,
                ));
            return;
        };

        let artifact_view = ArtifactContextRef::from_workspace_artifact(resolved.artifact);
        if let Some(finding) = provider.prepare_workspace_finding(
            &artifact_view.artifact.normalized_path,
            artifact_view.content,
            finding,
            &mut summary.diagnostics,
        ) {
            self.engine
                .collect_finding(&artifact_view, resolved.file_config, finding, summary);
        }
    }
}

fn unknown_workspace_artifact_diagnostic(
    project_root: &str,
    provider_id: &str,
    normalized_path: &str,
) -> crate::ScanDiagnostic {
    crate::ScanDiagnostic {
        normalized_path: project_root.to_owned(),
        severity: crate::DiagnosticSeverity::Warn,
        code: Some("provider_contract".to_owned()),
        message: format!(
            "provider `{provider_id}` emitted workspace finding for unknown artifact `{normalized_path}`"
        ),
    }
}
