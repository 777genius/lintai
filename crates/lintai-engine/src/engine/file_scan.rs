use std::path::{Path, PathBuf};
use std::thread;

use crate::detector::FileTypeDetector;
use crate::provider::ProviderCatalog;
use crate::summary::ScanSummary;

use super::{Engine, ScannedArtifact, WorkerScanResult};

impl Engine {
    pub(super) fn scan_files_in_parallel(
        &self,
        base_path: &Path,
        canonical_project_root: Option<&Path>,
        detector: &FileTypeDetector,
        files: Vec<PathBuf>,
        providers: &ProviderCatalog<'_>,
    ) -> (ScanSummary, Vec<ScannedArtifact>) {
        let worker_count = crate::scan_schedule::scan_worker_count(files.len());
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

    pub(super) fn scan_file_batch(
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
}
