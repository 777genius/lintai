use std::time::Instant;

use lintai_api::{ProviderErrorKind, WorkspaceArtifact, WorkspaceScanContext};

use crate::artifact_view::ArtifactContextRef;
use crate::provider::ProviderCatalog;
use crate::summary::{ProviderExecutionPhase, ScanSummary};
use crate::workspace_index::{WorkspaceEntry, WorkspaceIndex, full_artifact_location};

use super::{Engine, ScannedArtifact};

impl Engine {
    pub(super) fn run_workspace_providers(
        &self,
        providers: &ProviderCatalog<'_>,
        scanned_artifacts: Vec<ScannedArtifact>,
        summary: &mut ScanSummary,
    ) {
        let mut workspace_artifacts = Vec::with_capacity(scanned_artifacts.len());
        let mut workspace_entries = Vec::with_capacity(scanned_artifacts.len());
        for scanned in scanned_artifacts {
            let normalized_path = scanned.context.artifact.normalized_path.clone();
            let location_hint =
                full_artifact_location(normalized_path.clone(), &scanned.context.content);
            let artifact_index = workspace_artifacts.len();
            workspace_artifacts.push(
                WorkspaceArtifact::new(
                    scanned.context.artifact,
                    scanned.context.content,
                    scanned.context.document,
                    scanned.context.semantics,
                )
                .with_location_hint(location_hint),
            );
            workspace_entries.push(WorkspaceEntry {
                artifact_index,
                normalized_path,
                file_config: scanned.file_config,
            });
        }
        let workspace_index = WorkspaceIndex::new(workspace_entries);
        let workspace = WorkspaceScanContext::new(
            self.config
                .project_root
                .as_ref()
                .map(|path| crate::normalize::normalize_path_string(path)),
            workspace_artifacts,
            self.config.capability_profile.clone(),
            self.config.capability_conflict_mode,
        );

        for provider in providers.workspace() {
            let started = Instant::now();
            let result = provider.backend().check_workspace_result(&workspace);
            let elapsed = started.elapsed();
            if !result
                .errors
                .iter()
                .any(|error| matches!(error.kind, ProviderErrorKind::Timeout))
            {
                self.record_budget_overrun(
                    workspace.project_root.as_deref().unwrap_or("."),
                    provider.id(),
                    provider.timeout(),
                    elapsed,
                    summary,
                );
            }
            self.record_provider_metric(
                crate::ProviderExecutionMetric {
                    normalized_path: workspace
                        .project_root
                        .clone()
                        .unwrap_or_else(|| ".".to_owned()),
                    provider_id: provider.id().to_owned(),
                    phase: ProviderExecutionPhase::Workspace,
                    elapsed_us: elapsed.as_micros(),
                    findings_emitted: result.findings.len(),
                    errors_emitted: result.errors.len(),
                },
                summary,
            );
            self.record_provider_execution_errors(
                workspace.project_root.as_deref().unwrap_or("."),
                ProviderExecutionPhase::Workspace,
                result.errors,
                summary,
            );
            for finding in result.findings {
                let Some(scanned) = workspace_index.get(&finding.location.normalized_path) else {
                    summary.diagnostics.push(crate::ScanDiagnostic {
                        normalized_path: workspace
                            .project_root
                            .clone()
                            .unwrap_or_else(|| ".".to_owned()),
                        severity: crate::DiagnosticSeverity::Warn,
                        code: Some("provider_contract".to_owned()),
                        message: format!(
                            "provider `{}` emitted workspace finding for unknown artifact `{}`",
                            provider.id(),
                            finding.location.normalized_path
                        ),
                    });
                    continue;
                };

                let artifact = &workspace.artifacts[scanned.artifact_index];
                let artifact_view = ArtifactContextRef::from_workspace_artifact(artifact);
                if let Some(finding) = provider.prepare_workspace_finding(
                    &artifact_view.artifact.normalized_path,
                    artifact_view.content,
                    finding,
                    &mut summary.diagnostics,
                ) {
                    self.collect_finding(&artifact_view, &scanned.file_config, finding, summary);
                }
            }
        }
    }
}
