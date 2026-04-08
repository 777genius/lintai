use std::time::Instant;

use lintai_api::ProviderErrorKind;

use crate::artifact_view::ArtifactContextRef;
use crate::provider::ProviderCatalog;
use crate::summary::{ProviderExecutionPhase, ScanSummary};

use super::super::{Engine, ScannedArtifact};

impl Engine {
    pub(in crate::engine) fn run_per_file_providers(
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
                crate::ProviderExecutionMetric {
                    normalized_path: scanned.context.artifact.normalized_path.clone(),
                    provider_id: provider.id().to_owned(),
                    phase: ProviderExecutionPhase::File,
                    elapsed_us: elapsed.as_micros(),
                    findings_emitted: result.findings.len(),
                    errors_emitted: result.errors.len(),
                },
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
}
