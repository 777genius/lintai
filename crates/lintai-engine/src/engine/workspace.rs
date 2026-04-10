use crate::provider::ProviderCatalog;
use crate::summary::ScanSummary;

use super::{Engine, ScannedArtifact};
use executor::WorkspaceProviderExecutor;
use projection::WorkspaceProjection;

mod executor;
mod projection;

impl Engine {
    pub(super) fn run_workspace_providers(
        &self,
        providers: &ProviderCatalog<'_>,
        scanned_artifacts: Vec<ScannedArtifact>,
        summary: &mut ScanSummary,
    ) {
        let projection = WorkspaceProjection::build(&self.config, scanned_artifacts);
        WorkspaceProviderExecutor::new(self, &projection).execute(providers, summary);
    }
}
