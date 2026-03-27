use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use lintai_adapters::parse_document;
use lintai_api::{
    Artifact, Finding, ProviderError, ProviderErrorKind, ScanContext, WorkspaceArtifact,
    WorkspaceScanContext,
};

use crate::artifact_view::ArtifactContextRef;
use crate::detector::FileTypeDetector;
use crate::discovery::{collect_files, scan_base};
use crate::normalize::{
    looks_binary, normalize_path, normalize_path_string, normalize_text, populate_line_columns,
};
use crate::provider::{ProviderBackend, ProviderCatalog};
use crate::summary::{ProviderExecutionPhase, RuntimeErrorKind, ScanRuntimeError, ScanSummary};
use crate::workspace_index::{WorkspaceEntry, WorkspaceIndex, full_artifact_location};
use crate::{EngineConfig, EngineError, ResolvedFileConfig, SuppressionMatcher};

pub struct Engine {
    pub(crate) config: EngineConfig,
    pub(crate) detector: FileTypeDetector,
    pub(crate) backends: Vec<Arc<dyn ProviderBackend>>,
    pub(crate) suppressions: Arc<dyn SuppressionMatcher>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Engine {
    pub fn scan_path(&self, path: &Path) -> Result<ScanSummary, EngineError> {
        let providers = ProviderCatalog::new(&self.backends)?;
        let mut summary = self.scan_path_inner(path, &providers)?;
        summary.diagnostics.extend(self.suppressions.finalize());
        summary.finalize();
        Ok(summary)
    }

    fn scan_path_inner(
        &self,
        path: &Path,
        providers: &ProviderCatalog<'_>,
    ) -> Result<ScanSummary, EngineError> {
        let mut summary = ScanSummary::default();
        let mut scanned_artifacts = Vec::new();
        let files = collect_files(path, &self.config)?;
        let base_path = scan_base(path, &self.config);
        let canonical_project_root = self
            .config
            .project_root
            .as_deref()
            .map(std::fs::canonicalize)
            .transpose()?;

        for file in files {
            if let Some(scanned) = self.scan_file(
                &base_path,
                canonical_project_root.as_deref(),
                &file,
                &mut summary,
            ) {
                self.run_per_file_providers(providers, &scanned, &mut summary);
                scanned_artifacts.push(scanned);
            }
        }

        self.run_workspace_providers(providers, scanned_artifacts, &mut summary);
        Ok(summary)
    }

    fn scan_file(
        &self,
        base_path: &Path,
        canonical_project_root: Option<&Path>,
        path: &Path,
        summary: &mut ScanSummary,
    ) -> Option<ScannedArtifact> {
        let normalized_path = normalize_path(base_path, path);
        let file_config = self.config.resolve_for(&normalized_path);
        if !file_config.included {
            summary.skipped_files += 1;
            return None;
        }
        if let Some(project_root) = canonical_project_root {
            match std::fs::canonicalize(path) {
                Ok(canonical_path) => {
                    if canonical_path != project_root && !canonical_path.starts_with(project_root) {
                        summary.runtime_errors.push(ScanRuntimeError {
                            normalized_path,
                            kind: RuntimeErrorKind::Read,
                            provider_id: None,
                            phase: None,
                            message: format!(
                                "path resolves outside project root {}",
                                project_root.display()
                            ),
                        });
                        return None;
                    }
                }
                Err(error) => {
                    summary.runtime_errors.push(ScanRuntimeError {
                        normalized_path,
                        kind: RuntimeErrorKind::Read,
                        provider_id: None,
                        phase: None,
                        message: error.to_string(),
                    });
                    return None;
                }
            }
        }
        let Some(detected) = self.detector.detect(path, &normalized_path) else {
            summary.skipped_files += 1;
            return None;
        };

        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                summary.runtime_errors.push(ScanRuntimeError {
                    normalized_path,
                    kind: RuntimeErrorKind::Read,
                    provider_id: None,
                    phase: None,
                    message: error.to_string(),
                });
                return None;
            }
        };

        if looks_binary(&bytes) {
            summary.skipped_files += 1;
            return None;
        }

        let content = match String::from_utf8(bytes) {
            Ok(content) => normalize_text(content),
            Err(error) => {
                summary.runtime_errors.push(ScanRuntimeError {
                    normalized_path,
                    kind: RuntimeErrorKind::InvalidUtf8,
                    provider_id: None,
                    phase: None,
                    message: error.to_string(),
                });
                return None;
            }
        };

        let artifact = Artifact::new(normalized_path.clone(), detected.kind, detected.format);
        let parsed = match parse_document(&artifact, &content) {
            Ok(parsed) => parsed,
            Err(error) => {
                summary.runtime_errors.push(ScanRuntimeError {
                    normalized_path,
                    kind: RuntimeErrorKind::Parse,
                    provider_id: None,
                    phase: None,
                    message: error.message,
                });
                return None;
            }
        };

        let context = ScanContext::new(artifact, content, parsed.document, parsed.semantics);

        summary.scanned_files += 1;
        Some(ScannedArtifact {
            context,
            file_config,
        })
    }

    fn run_per_file_providers(
        &self,
        providers: &ProviderCatalog<'_>,
        scanned: &ScannedArtifact,
        summary: &mut ScanSummary,
    ) {
        for provider in providers.per_file() {
            let started = Instant::now();
            let result = provider.backend().check_result(&scanned.context);
            if !result
                .errors
                .iter()
                .any(|error| matches!(error.kind, ProviderErrorKind::Timeout))
            {
                self.record_budget_overrun(
                    &scanned.context.artifact.normalized_path,
                    provider.id(),
                    provider.timeout(),
                    started.elapsed(),
                    summary,
                );
            }
            self.record_provider_execution_errors(
                &scanned.context.artifact.normalized_path,
                ProviderExecutionPhase::File,
                result.errors,
                summary,
            );
            for finding in result.findings {
                if let Some(finding) =
                    provider.prepare_finding(&scanned.context, finding, &mut summary.diagnostics)
                {
                    let artifact_view = ArtifactContextRef::from_scan_context(&scanned.context);
                    self.collect_finding(&artifact_view, &scanned.file_config, finding, summary);
                }
            }
        }
    }

    fn run_workspace_providers(
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
                .map(|path| normalize_path_string(path)),
            workspace_artifacts,
            self.config.capability_profile.clone(),
            self.config.capability_conflict_mode,
        );

        for provider in providers.workspace() {
            let started = Instant::now();
            let result = provider.backend().check_workspace_result(&workspace);
            if !result
                .errors
                .iter()
                .any(|error| matches!(error.kind, ProviderErrorKind::Timeout))
            {
                self.record_budget_overrun(
                    workspace.project_root.as_deref().unwrap_or("."),
                    provider.id(),
                    provider.timeout(),
                    started.elapsed(),
                    summary,
                );
            }
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

    fn collect_finding(
        &self,
        context: &ArtifactContextRef<'_>,
        file_config: &ResolvedFileConfig,
        mut finding: Finding,
        summary: &mut ScanSummary,
    ) {
        let _ = context.document;
        let _ = context.semantics;
        populate_line_columns(context.content, &mut finding);
        finding.severity =
            file_config.severity_for(&finding.rule_code, finding.category, finding.severity);
        if !self.suppressions.is_suppressed(context, &finding) {
            summary.findings.push(finding);
        }
    }

    fn record_budget_overrun(
        &self,
        normalized_path: &str,
        provider_id: &str,
        timeout: std::time::Duration,
        elapsed: std::time::Duration,
        summary: &mut ScanSummary,
    ) {
        if elapsed <= timeout {
            return;
        }

        summary.runtime_errors.push(ScanRuntimeError {
            normalized_path: normalized_path.to_owned(),
            kind: RuntimeErrorKind::ProviderTimeout,
            provider_id: Some(provider_id.to_owned()),
            phase: None,
            message: format!(
                "provider `{provider_id}` exceeded its soft time budget: {:?} > {:?}",
                elapsed, timeout
            ),
        });
    }

    fn record_provider_execution_errors(
        &self,
        normalized_path: &str,
        phase: ProviderExecutionPhase,
        errors: Vec<ProviderError>,
        summary: &mut ScanSummary,
    ) {
        for error in errors {
            summary.runtime_errors.push(ScanRuntimeError {
                normalized_path: normalized_path.to_owned(),
                kind: match error.kind {
                    ProviderErrorKind::Execution => RuntimeErrorKind::ProviderExecution,
                    ProviderErrorKind::Timeout => RuntimeErrorKind::ProviderTimeout,
                },
                provider_id: Some(error.provider_id),
                phase: Some(phase),
                message: error.message,
            });
        }
    }
}

#[derive(Clone)]
struct ScannedArtifact {
    context: ScanContext,
    file_config: ResolvedFileConfig,
}
