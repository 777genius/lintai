use std::path::Path;
use std::time::Instant;

use lintai_adapters::parse_document;
use lintai_api::{Artifact, Finding, ProviderError, ProviderErrorKind, ScanContext};

use crate::ResolvedFileConfig;
use crate::artifact_view::ArtifactContextRef;
use crate::detector::FileTypeDetector;
use crate::normalize::{looks_binary, normalize_path, normalize_text, populate_line_columns};
use crate::provider::ProviderCatalog;
use crate::summary::{
    ProviderExecutionMetric, ProviderExecutionPhase, RuntimeErrorKind, ScanRuntimeError,
    ScanSummary,
};

use super::{Engine, ScannedArtifact};

impl Engine {
    pub(super) fn scan_file(
        &self,
        base_path: &Path,
        canonical_project_root: Option<&Path>,
        detector: &FileTypeDetector,
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
        let Some(detected) = detector.detect(path, &normalized_path) else {
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
        summary
            .diagnostics
            .extend(
                parsed
                    .diagnostics
                    .iter()
                    .map(|diagnostic| crate::ScanDiagnostic {
                        normalized_path: normalized_path.clone(),
                        severity: crate::DiagnosticSeverity::Warn,
                        code: Some("parse_recovery".to_owned()),
                        message: diagnostic.message.clone(),
                    }),
            );

        let context = ScanContext::new(artifact, content, parsed.document, parsed.semantics);

        summary.scanned_files += 1;
        Some(ScannedArtifact {
            context,
            file_config,
        })
    }

    pub(super) fn run_per_file_providers(
        &self,
        providers: &ProviderCatalog<'_>,
        scanned: &ScannedArtifact,
        summary: &mut ScanSummary,
    ) {
        for provider in providers.per_file() {
            let started = Instant::now();
            let result = provider.backend().check_result(&scanned.context);
            let elapsed = started.elapsed();
            if !result
                .errors
                .iter()
                .any(|error| matches!(error.kind, ProviderErrorKind::Timeout))
            {
                self.record_budget_overrun(
                    &scanned.context.artifact.normalized_path,
                    provider.id(),
                    provider.timeout(),
                    elapsed,
                    summary,
                );
            }
            self.record_provider_metric(
                &scanned.context.artifact.normalized_path,
                provider.id(),
                ProviderExecutionPhase::File,
                elapsed,
                result.findings.len(),
                result.errors.len(),
                summary,
            );
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

    pub(super) fn collect_finding(
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

    pub(super) fn record_budget_overrun(
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

    pub(super) fn record_provider_execution_errors(
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

    pub(super) fn record_provider_metric(
        &self,
        normalized_path: &str,
        provider_id: &str,
        phase: ProviderExecutionPhase,
        elapsed: std::time::Duration,
        findings_emitted: usize,
        errors_emitted: usize,
        summary: &mut ScanSummary,
    ) {
        summary.provider_metrics.push(ProviderExecutionMetric {
            normalized_path: normalized_path.to_owned(),
            provider_id: provider_id.to_owned(),
            phase,
            elapsed_us: elapsed.as_micros(),
            findings_emitted,
            errors_emitted,
        });
    }
}
