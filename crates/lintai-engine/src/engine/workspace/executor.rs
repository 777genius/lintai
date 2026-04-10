use std::time::Instant;

use lintai_api::{Finding, ProviderErrorKind};

use crate::artifact_view::ArtifactContextRef;
use crate::provider::{ProviderCatalog, ProviderEntry};
use crate::summary::{ProviderExecutionPhase, ScanSummary};

use super::super::Engine;
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
        let started = Instant::now();
        let result = provider
            .backend()
            .check_workspace_result(&self.projection.workspace);
        let elapsed = started.elapsed();
        let findings_emitted = result.findings.len();
        let errors_emitted = result.errors.len();
        let project_root = self.projection.project_root_owned();

        if !result
            .errors
            .iter()
            .any(|error| matches!(error.kind, ProviderErrorKind::Timeout))
        {
            self.engine.record_budget_overrun(
                &project_root,
                provider.id(),
                provider.timeout(),
                elapsed,
                summary,
            );
        }

        self.engine.record_provider_metric(
            crate::ProviderExecutionMetric {
                normalized_path: project_root.clone(),
                provider_id: provider.id().to_owned(),
                phase: ProviderExecutionPhase::Workspace,
                elapsed_us: elapsed.as_micros(),
                findings_emitted,
                errors_emitted,
            },
            summary,
        );
        self.engine.record_provider_execution_errors(
            &project_root,
            ProviderExecutionPhase::Workspace,
            result.errors,
            summary,
        );

        for finding in result.findings {
            self.reconcile_finding(provider, &project_root, finding, summary);
        }
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
