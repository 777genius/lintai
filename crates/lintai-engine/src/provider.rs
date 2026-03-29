use std::collections::BTreeMap;
use std::time::Duration;

use lintai_api::{Finding, RuleMetadata, ScanContext, ScanScope};
use lintai_runtime::ProviderBackend;

use crate::ScanDiagnostic;

#[path = "provider/catalog.rs"]
mod catalog;
#[path = "provider/diagnostics.rs"]
mod diagnostics;
#[path = "provider/normalize.rs"]
mod normalize;

pub(crate) struct ProviderCatalog<'a> {
    entries: Vec<ProviderEntry<'a>>,
}

pub(crate) struct ProviderEntry<'a> {
    backend: &'a dyn ProviderBackend,
    id: String,
    rules: BTreeMap<String, RuleMetadata>,
    scope: ScanScope,
    timeout: Duration,
}

impl ProviderEntry<'_> {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn backend(&self) -> &dyn ProviderBackend {
        self.backend
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(crate) fn prepare_finding(
        &self,
        ctx: &ScanContext,
        mut finding: Finding,
        diagnostics: &mut Vec<ScanDiagnostic>,
    ) -> Option<Finding> {
        self.prepare_finding_internal(
            &ctx.artifact.normalized_path,
            &ctx.content,
            &mut finding,
            diagnostics,
        )
    }

    pub(crate) fn prepare_workspace_finding(
        &self,
        artifact_path: &str,
        content: &str,
        mut finding: Finding,
        diagnostics: &mut Vec<ScanDiagnostic>,
    ) -> Option<Finding> {
        self.prepare_finding_internal(artifact_path, content, &mut finding, diagnostics)
    }
}
