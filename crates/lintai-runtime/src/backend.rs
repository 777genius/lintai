use std::sync::Arc;
use std::time::Duration;

use lintai_api::{
    FileRuleProvider, ProviderError, ProviderScanResult, RuleMetadata, RuleProvider, ScanContext,
    ScanScope, WorkspaceRuleProvider, WorkspaceScanContext,
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

pub struct InProcessFileProviderBackend {
    provider: Arc<dyn FileRuleProvider>,
    timeout: Duration,
}

pub struct InProcessWorkspaceProviderBackend {
    provider: Arc<dyn WorkspaceRuleProvider>,
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

impl InProcessFileProviderBackend {
    pub fn new(provider: Arc<dyn FileRuleProvider>) -> Self {
        Self::with_timeout(provider, Duration::from_secs(30))
    }

    pub fn with_timeout(provider: Arc<dyn FileRuleProvider>, timeout: Duration) -> Self {
        Self { provider, timeout }
    }
}

impl InProcessWorkspaceProviderBackend {
    pub fn new(provider: Arc<dyn WorkspaceRuleProvider>) -> Self {
        Self::with_timeout(provider, Duration::from_secs(30))
    }

    pub fn with_timeout(provider: Arc<dyn WorkspaceRuleProvider>, timeout: Duration) -> Self {
        Self { provider, timeout }
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

impl ProviderBackend for InProcessFileProviderBackend {
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
        ScanScope::PerFile
    }

    fn check_workspace_result(&self, _ctx: &WorkspaceScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            Vec::new(),
            vec![ProviderError::new(
                self.id(),
                "file provider cannot run in workspace phase",
            )],
        )
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl ProviderBackend for InProcessWorkspaceProviderBackend {
    fn id(&self) -> &str {
        self.provider.id()
    }

    fn rules(&self) -> &[RuleMetadata] {
        self.provider.rules()
    }

    fn check_result(&self, _ctx: &ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            Vec::new(),
            vec![ProviderError::new(
                self.id(),
                "workspace provider cannot run in file phase",
            )],
        )
    }

    fn scan_scope(&self) -> ScanScope {
        ScanScope::Workspace
    }

    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult {
        self.provider.check_workspace_result(ctx)
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use lintai_api::{ParsedDocument, RuleMetadata, RuleTier};

    use super::*;

    struct TestFileProvider;
    struct TestWorkspaceProvider;
    struct TestRuleProvider;

    static TEST_RULES: [RuleMetadata; 1] = [RuleMetadata::new(
        "TEST001",
        "test rule",
        lintai_api::Category::Security,
        lintai_api::Severity::Warn,
        lintai_api::Confidence::High,
        RuleTier::Preview,
    )];

    impl FileRuleProvider for TestFileProvider {
        fn id(&self) -> &str {
            "test-file"
        }

        fn rules(&self) -> &[RuleMetadata] {
            &TEST_RULES
        }

        fn check_result(&self, _ctx: &ScanContext) -> ProviderScanResult {
            ProviderScanResult::new(Vec::new(), Vec::new())
        }
    }

    impl WorkspaceRuleProvider for TestWorkspaceProvider {
        fn id(&self) -> &str {
            "test-workspace"
        }

        fn rules(&self) -> &[RuleMetadata] {
            &TEST_RULES
        }

        fn check_workspace_result(&self, _ctx: &WorkspaceScanContext) -> ProviderScanResult {
            ProviderScanResult::new(Vec::new(), Vec::new())
        }
    }

    impl RuleProvider for TestRuleProvider {
        fn id(&self) -> &str {
            "test-rule"
        }

        fn rules(&self) -> &[RuleMetadata] {
            &TEST_RULES
        }

        fn check_result(&self, _ctx: &ScanContext) -> ProviderScanResult {
            ProviderScanResult::new(Vec::new(), Vec::new())
        }

        fn check_workspace_result(&self, _ctx: &WorkspaceScanContext) -> ProviderScanResult {
            ProviderScanResult::new(Vec::new(), Vec::new())
        }
    }

    #[test]
    fn file_backend_reports_workspace_phase_misuse() {
        let backend = InProcessFileProviderBackend::new(Arc::new(TestFileProvider));
        let result = backend.check_workspace_result(&WorkspaceScanContext::new(
            None,
            Vec::new(),
            None,
            lintai_api::CapabilityConflictMode::Warn,
        ));
        assert!(result.findings.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].provider_id, "test-file");
    }

    #[test]
    fn workspace_backend_reports_file_phase_misuse() {
        let backend = InProcessWorkspaceProviderBackend::new(Arc::new(TestWorkspaceProvider));
        let result = backend.check_result(&ScanContext::new(
            lintai_api::Artifact::new(
                "file.txt",
                lintai_api::ArtifactKind::Instructions,
                lintai_api::SourceFormat::Markdown,
            ),
            String::new(),
            ParsedDocument::new(Vec::new(), None),
            None,
        ));
        assert!(result.findings.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].provider_id, "test-workspace");
    }

    #[test]
    fn inprocess_backend_exposes_constructor_overrides() {
        let provider: Arc<dyn RuleProvider> = Arc::new(TestRuleProvider);
        let default_backend =
            InProcessProviderBackend::new(Arc::new(TestRuleProvider) as Arc<dyn RuleProvider>);
        assert_eq!(default_backend.id(), "test-rule");
        assert_eq!(default_backend.scan_scope(), ScanScope::PerFile);
        assert_eq!(default_backend.timeout(), Duration::from_secs(30));

        let scoped =
            InProcessProviderBackend::with_scope(Arc::clone(&provider), ScanScope::Workspace);
        assert_eq!(scoped.scan_scope(), ScanScope::Workspace);

        let timeout = Duration::from_secs(5);
        let timed = InProcessProviderBackend::with_timeout(Arc::new(TestRuleProvider), timeout);
        assert_eq!(timed.timeout(), timeout);
        assert_eq!(timed.id(), "test-rule");
        assert_eq!(timed.rules(), &TEST_RULES);
    }

    #[test]
    fn file_workspace_backends_keep_metadata_and_scope() {
        let file_backend = InProcessFileProviderBackend::with_timeout(
            Arc::new(TestFileProvider),
            Duration::from_secs(7),
        );
        assert_eq!(file_backend.id(), "test-file");
        assert_eq!(file_backend.scan_scope(), ScanScope::PerFile);
        assert_eq!(file_backend.timeout(), Duration::from_secs(7));
        assert_eq!(file_backend.rules(), &TEST_RULES);

        let workspace_backend = InProcessWorkspaceProviderBackend::with_timeout(
            Arc::new(TestWorkspaceProvider),
            Duration::from_secs(9),
        );
        assert_eq!(workspace_backend.id(), "test-workspace");
        assert_eq!(workspace_backend.scan_scope(), ScanScope::Workspace);
        assert_eq!(workspace_backend.timeout(), Duration::from_secs(9));
        assert_eq!(workspace_backend.rules(), &TEST_RULES);
    }
}
