use std::sync::Arc;
use std::time::Duration;

use lintai_api::{
    ProviderScanResult, RuleMetadata, RuleProvider, ScanContext, ScanScope, WorkspaceScanContext,
};

pub trait ProviderBackend: Send + Sync {
    fn id(&self) -> &str;
    fn rules(&self) -> &[RuleMetadata];
    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult;

    fn scan_scope(&self) -> ScanScope {
        ScanScope::PerFile
    }

    fn check_workspace_result(&self, _ctx: &WorkspaceScanContext) -> ProviderScanResult {
        ProviderScanResult::new(Vec::new(), Vec::new())
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

pub struct InProcessProviderBackend {
    provider: Arc<dyn RuleProvider>,
    scope: ScanScope,
    timeout: Duration,
}

impl InProcessProviderBackend {
    pub fn new(provider: Arc<dyn RuleProvider>) -> Self {
        Self::with_scope_and_timeout(provider, ScanScope::PerFile, Duration::from_secs(30))
    }

    pub fn with_scope(provider: Arc<dyn RuleProvider>, scope: ScanScope) -> Self {
        Self::with_scope_and_timeout(provider, scope, Duration::from_secs(30))
    }

    pub fn with_timeout(provider: Arc<dyn RuleProvider>, timeout: Duration) -> Self {
        Self::with_scope_and_timeout(provider, ScanScope::PerFile, timeout)
    }

    pub fn with_scope_and_timeout(
        provider: Arc<dyn RuleProvider>,
        scope: ScanScope,
        timeout: Duration,
    ) -> Self {
        Self {
            provider,
            scope,
            timeout,
        }
    }
}

impl ProviderBackend for InProcessProviderBackend {
    fn id(&self) -> &str {
        self.provider.id()
    }

    fn rules(&self) -> &[RuleMetadata] {
        self.provider.rules()
    }

    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult {
        self.provider.check_result(ctx)
    }

    fn scan_scope(&self) -> ScanScope {
        self.scope
    }

    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult {
        self.provider.check_workspace_result(ctx)
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }
}
