use std::sync::Arc;
use std::time::Duration;

use lintai_api::{ProviderScanResult, RuleMetadata, ScanContext, ScanScope, WorkspaceScanContext};
use lintai_runtime::{ExecutableResolver, ProviderBackend, SubprocessProviderBackend};

use crate::builtin_providers::kind::BuiltInProviderKind;
use crate::internal_bin::resolve_lintai_driver_path;

pub(crate) struct IsolatedBuiltInBackend(SubprocessProviderBackend<BuiltInProviderKind>);

impl IsolatedBuiltInBackend {
    pub(crate) fn new(kind: BuiltInProviderKind) -> Self {
        let provider = kind.instantiate();
        let resolver: ExecutableResolver = Arc::new(resolve_lintai_driver_path);
        Self(SubprocessProviderBackend::new(
            kind,
            provider.id().to_owned(),
            provider.rules().to_vec(),
            kind.timeout(),
            kind.scope(),
            resolver,
            "__provider-runner",
        ))
    }
}

impl ProviderBackend for IsolatedBuiltInBackend {
    fn id(&self) -> &str {
        self.0.id()
    }

    fn rules(&self) -> &[RuleMetadata] {
        self.0.rules()
    }

    fn scan_scope(&self) -> ScanScope {
        self.0.scan_scope()
    }

    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult {
        self.0.check_result(ctx)
    }

    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult {
        self.0.check_workspace_result(ctx)
    }

    fn timeout(&self) -> Duration {
        self.0.timeout()
    }
}
