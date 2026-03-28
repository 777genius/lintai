use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use lintai_adapters::parse_document;
use lintai_api::{
    Artifact, ArtifactKind, Finding, ProviderError, ProviderErrorKind, ScanContext, SourceFormat,
    WorkspaceArtifact, WorkspaceScanContext,
};
use lintai_runtime::ProviderBackend;
use serde_json::Value;

use crate::artifact_view::ArtifactContextRef;
use crate::detector::FileTypeDetector;
use crate::discovery::{collect_files, scan_base};
use crate::normalize::{
    looks_binary, normalize_path, normalize_path_string, normalize_text, populate_line_columns,
};
use crate::provider::ProviderCatalog;
use crate::summary::{
    ProviderExecutionMetric, ProviderExecutionPhase, RuntimeErrorKind, ScanRuntimeError,
    ScanSummary,
};
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
        let files = collect_files(path, &self.config)?;
        let base_path = scan_base(path, &self.config);
        let detector = self.detector_for_scan(&base_path, &files);
        let canonical_project_root = self
            .config
            .project_root
            .as_deref()
            .map(std::fs::canonicalize)
            .transpose()?;
        let (mut summary, mut scanned_artifacts) = self.scan_files_in_parallel(
            &base_path,
            canonical_project_root.as_deref(),
            &detector,
            files,
            providers,
        );

        scanned_artifacts.sort_by(|left, right| {
            left.context
                .artifact
                .normalized_path
                .cmp(&right.context.artifact.normalized_path)
        });

        self.run_workspace_providers(providers, scanned_artifacts, &mut summary);
        Ok(summary)
    }

    fn scan_files_in_parallel(
        &self,
        base_path: &Path,
        canonical_project_root: Option<&Path>,
        detector: &FileTypeDetector,
        files: Vec<std::path::PathBuf>,
        providers: &ProviderCatalog<'_>,
    ) -> (ScanSummary, Vec<ScannedArtifact>) {
        let worker_count = worker_count_for_scan(files.len());
        if worker_count == 1 {
            let result = self.scan_file_batch(
                base_path,
                canonical_project_root,
                detector,
                files,
                providers,
            );
            return (result.summary, result.scanned_artifacts);
        }

        let mut chunks = vec![Vec::new(); worker_count];
        for (index, file) in files.into_iter().enumerate() {
            chunks[index % worker_count].push(file);
        }

        let results = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(chunks.len());
            for chunk in chunks {
                handles.push(scope.spawn(move || {
                    self.scan_file_batch(
                        base_path,
                        canonical_project_root,
                        detector,
                        chunk,
                        providers,
                    )
                }));
            }

            handles
                .into_iter()
                .map(|handle| handle.join().expect("file scan worker panicked"))
                .collect::<Vec<_>>()
        });

        let mut summary = ScanSummary::default();
        let mut scanned_artifacts = Vec::new();
        for mut result in results {
            summary.merge(result.summary);
            scanned_artifacts.append(&mut result.scanned_artifacts);
        }

        (summary, scanned_artifacts)
    }

    fn scan_file_batch(
        &self,
        base_path: &Path,
        canonical_project_root: Option<&Path>,
        detector: &FileTypeDetector,
        files: Vec<PathBuf>,
        providers: &ProviderCatalog<'_>,
    ) -> WorkerScanResult {
        let mut summary = ScanSummary::default();
        let mut scanned_artifacts = Vec::new();
        for file in files {
            if let Some(scanned) = self.scan_file(
                base_path,
                canonical_project_root,
                detector,
                &file,
                &mut summary,
            ) {
                self.run_per_file_providers(providers, &scanned, &mut summary);
                scanned_artifacts.push(scanned);
            }
        }
        WorkerScanResult {
            summary,
            scanned_artifacts,
        }
    }

    fn scan_file(
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

    fn run_per_file_providers(
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
                workspace.project_root.as_deref().unwrap_or("."),
                provider.id(),
                ProviderExecutionPhase::Workspace,
                elapsed,
                result.findings.len(),
                result.errors.len(),
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

    fn record_provider_metric(
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

    fn detector_for_scan(&self, base_path: &Path, files: &[PathBuf]) -> FileTypeDetector {
        let dynamic_patterns = manifest_backed_plugin_detection_patterns(base_path, files);
        if dynamic_patterns.is_empty() {
            return self.detector.clone();
        }

        let mut config = self.config.clone();
        for override_spec in dynamic_patterns {
            let escaped = globset::escape(&override_spec.normalized_path);
            let _ =
                config.add_detection_override(&[escaped], override_spec.kind, override_spec.format);
        }
        FileTypeDetector::new(&config)
    }
}

#[derive(Clone)]
struct ScannedArtifact {
    context: ScanContext,
    file_config: ResolvedFileConfig,
}

struct WorkerScanResult {
    summary: ScanSummary,
    scanned_artifacts: Vec<ScannedArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DynamicDetectionOverride {
    normalized_path: String,
    kind: ArtifactKind,
    format: SourceFormat,
}

fn manifest_backed_plugin_detection_patterns(
    base_path: &Path,
    files: &[PathBuf],
) -> Vec<DynamicDetectionOverride> {
    let normalized_to_path = files
        .iter()
        .map(|path| (normalize_path(base_path, path), path.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut overrides = BTreeMap::new();

    for (normalized_manifest_path, manifest_path) in &normalized_to_path {
        if !normalized_manifest_path.ends_with(".cursor-plugin/plugin.json") {
            continue;
        }

        let Ok(text) = std::fs::read_to_string(manifest_path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Some(object) = value.as_object() else {
            continue;
        };
        let Some(plugin_root_fs) = manifest_path.parent().and_then(Path::parent) else {
            continue;
        };

        if let Some(target) = object.get("hooks").and_then(Value::as_str)
            && let Some(normalized_target) =
                resolve_manifest_target_path(base_path, plugin_root_fs, target, &normalized_to_path)
            && let Some(target_path) = normalized_to_path.get(&normalized_target)
            && let Ok(target_text) = std::fs::read_to_string(target_path)
            && contains_semantic_plugin_hook_commands(&target_text)
        {
            overrides.insert(
                normalized_target.clone(),
                DynamicDetectionOverride {
                    normalized_path: normalized_target,
                    kind: ArtifactKind::CursorPluginHooks,
                    format: SourceFormat::Json,
                },
            );
        }

        if let Some(target) = object.get("agents").and_then(Value::as_str)
            && let Some(normalized_dir) =
                resolve_manifest_target_directory(base_path, plugin_root_fs, target)
        {
            let prefix = format!("{normalized_dir}/");
            for normalized_file in normalized_to_path.keys() {
                if normalized_file.starts_with(&prefix) && normalized_file.ends_with(".md") {
                    overrides.insert(
                        normalized_file.clone(),
                        DynamicDetectionOverride {
                            normalized_path: normalized_file.clone(),
                            kind: ArtifactKind::CursorPluginAgent,
                            format: SourceFormat::Markdown,
                        },
                    );
                }
            }
        }
    }

    overrides.into_values().collect()
}

fn resolve_manifest_target_path(
    base_path: &Path,
    plugin_root_fs: &Path,
    target: &str,
    normalized_to_path: &BTreeMap<String, PathBuf>,
) -> Option<String> {
    let resolved = plugin_root_fs.join(target);
    let normalized = normalize_path(base_path, &resolved);
    (is_repo_local_normalized_path(&normalized) && normalized_to_path.contains_key(&normalized))
        .then_some(normalized)
}

fn resolve_manifest_target_directory(
    base_path: &Path,
    plugin_root_fs: &Path,
    target: &str,
) -> Option<String> {
    let resolved = plugin_root_fs.join(target);
    if !resolved.is_dir() {
        return None;
    }
    let normalized = normalize_path(base_path, &resolved);
    is_repo_local_normalized_path(&normalized).then_some(normalized)
}

const FORCE_SEQUENTIAL_SCAN_ENV: &str = "LINTAI_FORCE_SEQUENTIAL_SCAN";
const MIN_FILES_FOR_PARALLEL_SCAN: usize = 4;

fn worker_count_for_scan(file_count: usize) -> usize {
    if should_scan_sequentially(file_count) {
        1
    } else {
        file_count
            .min(
                thread::available_parallelism()
                    .map(usize::from)
                    .unwrap_or(1),
            )
            .max(1)
    }
}

fn should_scan_sequentially(file_count: usize) -> bool {
    file_count < MIN_FILES_FOR_PARALLEL_SCAN || force_sequential_scans()
}

fn force_sequential_scans() -> bool {
    matches!(
        std::env::var(FORCE_SEQUENTIAL_SCAN_ENV),
        Ok(value) if matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")
    )
}

fn contains_semantic_plugin_hook_commands(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object
        .get("hooks")
        .and_then(Value::as_object)
        .is_some_and(|hooks| {
            hooks.values().any(|entries| {
                entries.as_array().is_some_and(|entries| {
                    entries.iter().any(|entry| {
                        entry
                            .as_object()
                            .and_then(|entry| entry.get("command"))
                            .and_then(Value::as_str)
                            .is_some()
                    })
                })
            })
        })
}

fn is_repo_local_normalized_path(path: &str) -> bool {
    !path.starts_with('/') && !path.starts_with("../") && path != ".."
}
