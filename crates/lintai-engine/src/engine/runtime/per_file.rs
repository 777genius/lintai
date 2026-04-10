use crate::artifact_view::ArtifactContextRef;
use crate::provider::ProviderCatalog;
use crate::summary::{ProviderExecutionPhase, ScanSummary};

use super::super::{Engine, ScannedArtifact};
use super::execution::ProviderExecutionRequest;

impl Engine {
    pub(in crate::engine) fn run_per_file_providers(
        &self,
        providers: &ProviderCatalog<'_>,
        scanned: &ScannedArtifact,
        summary: &mut ScanSummary,
    ) {
        for provider in providers.per_file() {
            self.execute_provider_with_accounting(
                ProviderExecutionRequest {
                    normalized_path: &scanned.context.artifact.normalized_path,
                    provider,
                    phase: ProviderExecutionPhase::File,
                },
                summary,
                || provider.backend().check_result(&scanned.context),
                |finding, summary| {
                    if let Some(finding) = provider.prepare_finding(
                        &scanned.context,
                        finding,
                        &mut summary.diagnostics,
                    ) {
                        let artifact_view = ArtifactContextRef::from_scan_context(&scanned.context);
                        self.collect_finding(
                            &artifact_view,
                            &scanned.file_config,
                            finding,
                            summary,
                        );
                    }
                },
            );
        }
    }
}
