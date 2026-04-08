use std::path::Path;

use lintai_adapters::parse_document;
use lintai_api::{Artifact, ScanContext};

use crate::detector::FileTypeDetector;
use crate::normalize::{looks_binary, normalize_path, normalize_text};
use crate::summary::{RuntimeErrorKind, ScanRuntimeError, ScanSummary};

use super::super::{Engine, ScannedArtifact};

impl Engine {
    pub(in crate::engine) fn scan_file(
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

        let context = ScanContext::new(artifact, content, parsed.document, parsed.semantics)
            .with_active_rule_codes(file_config.active_rule_codes.clone());

        summary.scanned_files += 1;
        Some(ScannedArtifact {
            context,
            file_config,
        })
    }
}
