use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use lintai_adapters::parse_document;
use lintai_api::{
    Artifact, Finding, ProviderError, RuleProvider, ScanContext, WorkspaceArtifact,
    WorkspaceScanContext,
};

use crate::detector::FileTypeDetector;
use crate::discovery::{collect_files, scan_base};
use crate::normalize::{
    looks_binary, normalize_path, normalize_path_string, normalize_text, populate_line_columns,
};
use crate::provider::ProviderCatalog;
use crate::summary::{RuntimeErrorKind, ScanRuntimeError, ScanSummary};
use crate::workspace_index::{WorkspaceEntry, WorkspaceIndex, full_artifact_location};
use crate::{EngineConfig, EngineError, ResolvedFileConfig, SuppressionMatcher};

pub struct Engine {
    pub(crate) config: EngineConfig,
    pub(crate) detector: FileTypeDetector,
    pub(crate) providers: Vec<Arc<dyn RuleProvider>>,
    pub(crate) suppressions: Arc<dyn SuppressionMatcher>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Engine {
    pub fn scan_path(&self, path: &Path) -> Result<ScanSummary, EngineError> {
        let providers = ProviderCatalog::new(&self.providers)?;
        let started_providers = providers.start_all()?;
        let scan_result = self.scan_path_inner(path, &providers);
        let finish_result = providers.finish_started(started_providers);

        match (scan_result, finish_result) {
            (Ok(mut summary), Ok(())) => {
                summary.diagnostics.extend(self.suppressions.finalize());
                summary.finalize();
                Ok(summary)
            }
            (Err(error), Ok(())) => Err(error),
            (_, Err(error)) => Err(error),
        }
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

        self.run_workspace_providers(providers, &scanned_artifacts, &mut summary);
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
            let findings = provider.provider().check(&scanned.context);
            self.record_budget_overrun(
                &scanned.context.artifact.normalized_path,
                provider.id(),
                provider.timeout(),
                started.elapsed(),
                summary,
            );
            for finding in findings {
                if let Some(finding) =
                    provider.prepare_finding(&scanned.context, finding, &mut summary.diagnostics)
                {
                    self.collect_finding(&scanned.context, &scanned.file_config, finding, summary);
                }
            }
        }
    }

    fn run_workspace_providers(
        &self,
        providers: &ProviderCatalog<'_>,
        scanned_artifacts: &[ScannedArtifact],
        summary: &mut ScanSummary,
    ) {
        let workspace_index = WorkspaceIndex::new(
            scanned_artifacts
                .iter()
                .map(|scanned| WorkspaceEntry {
                    artifact: WorkspaceArtifact::new(
                        scanned.context.artifact.clone(),
                        scanned.context.content.clone(),
                        scanned.context.document.clone(),
                        scanned.context.semantics.clone(),
                    )
                    .with_location_hint(full_artifact_location(
                        scanned.context.artifact.normalized_path.clone(),
                        &scanned.context.content,
                    )),
                    file_config: scanned.file_config.clone(),
                })
                .collect(),
        );
        let workspace = WorkspaceScanContext::new(
            self.config
                .project_root
                .as_ref()
                .map(|path| normalize_path_string(path)),
            workspace_index.artifacts(),
            self.config.capability_profile.clone(),
            self.config.capability_conflict_mode,
        );

        for provider in providers.workspace() {
            let started = Instant::now();
            let findings = provider.provider().check_workspace(&workspace);
            self.record_budget_overrun(
                workspace.project_root.as_deref().unwrap_or("."),
                provider.id(),
                provider.timeout(),
                started.elapsed(),
                summary,
            );
            for finding in findings {
                let Some(scanned) = workspace_index.get(&finding.location.normalized_path) else {
                    summary.diagnostics.push(crate::ScanDiagnostic {
                        normalized_path: workspace.project_root.clone().unwrap_or_else(|| ".".to_owned()),
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

                if let Some(finding) = provider.prepare_workspace_finding(
                    &scanned.artifact.artifact.normalized_path,
                    &scanned.artifact.content,
                    finding,
                    &mut summary.diagnostics,
                ) {
                    let context = ScanContext::new(
                        scanned.artifact.artifact.clone(),
                        scanned.artifact.content.clone(),
                        scanned.artifact.document.clone(),
                        scanned.artifact.semantics.clone(),
                    );
                    self.collect_finding(&context, &scanned.file_config, finding, summary);
                }
            }
        }
    }

    fn collect_finding(
        &self,
        context: &ScanContext,
        file_config: &ResolvedFileConfig,
        mut finding: Finding,
        summary: &mut ScanSummary,
    ) {
        populate_line_columns(&context.content, &mut finding);
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
            message: format!(
                "provider `{provider_id}` exceeded its soft time budget: {:?} > {:?}",
                elapsed, timeout
            ),
        });
    }
}

#[derive(Clone)]
struct ScannedArtifact {
    context: ScanContext,
    file_config: ResolvedFileConfig,
}

pub(crate) fn combine_lifecycle_errors(
    start_error: ProviderError,
    cleanup_error: EngineError,
) -> EngineError {
    let cleanup_message = cleanup_error.to_string();
    EngineError::ProviderLifecycle(ProviderError::new(
        start_error.provider_id,
        format!(
            "{}; cleanup after failed startup also failed: {cleanup_message}",
            start_error.message
        ),
    ))
}
