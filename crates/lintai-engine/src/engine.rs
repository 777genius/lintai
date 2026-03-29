use lintai_api::ScanContext;
use lintai_runtime::ProviderBackend;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use crate::detector::FileTypeDetector;
use crate::discovery::{collect_files, scan_base};
use crate::dynamic_detection::dynamic_detection_overrides;
use crate::provider::ProviderCatalog;
use crate::summary::ScanSummary;
use crate::{EngineConfig, EngineError, ResolvedFileConfig, SuppressionMatcher};

mod file_scan;
mod runtime;
mod workspace;

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

    fn detector_for_scan(&self, base_path: &Path, files: &[PathBuf]) -> FileTypeDetector {
        let dynamic_patterns = dynamic_detection_overrides(base_path, files);
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
pub(super) struct ScannedArtifact {
    pub(super) context: ScanContext,
    pub(super) file_config: ResolvedFileConfig,
}

pub(super) struct WorkerScanResult {
    pub(super) summary: ScanSummary,
    pub(super) scanned_artifacts: Vec<ScannedArtifact>,
}
