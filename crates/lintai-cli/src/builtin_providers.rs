use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use lintai_ai_security::{AiSecurityProvider, PolicyMismatchProvider};
use lintai_api::{
    Confidence, Finding, Location, ProviderError, ProviderScanResult, RuleMetadata, RuleProvider,
    RuleTier, ScanContext, ScanScope, Severity, Span, WorkspaceScanContext,
};
use lintai_runtime::{
    ExecutableResolver, ProviderBackend, RunnerPhase, RunnerRequest, RunnerResponse,
    SubprocessProviderBackend,
};

use crate::internal_bin::resolve_lintai_driver_path;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BuiltInProviderKind {
    AiSecurity,
    PolicyMismatch,
    #[cfg(debug_assertions)]
    TestTimeout,
    #[cfg(debug_assertions)]
    TestPanic,
    #[cfg(debug_assertions)]
    TestPartialError,
}

impl BuiltInProviderKind {
    fn instantiate(self) -> Box<dyn RuleProvider> {
        match self {
            Self::AiSecurity => Box::new(AiSecurityProvider::default()),
            Self::PolicyMismatch => Box::new(PolicyMismatchProvider),
            #[cfg(debug_assertions)]
            Self::TestTimeout => Box::new(TestTimeoutProvider),
            #[cfg(debug_assertions)]
            Self::TestPanic => Box::new(TestPanicProvider),
            #[cfg(debug_assertions)]
            Self::TestPartialError => Box::new(TestPartialErrorProvider),
        }
    }

    fn product_kinds() -> [Self; 2] {
        [Self::AiSecurity, Self::PolicyMismatch]
    }

    fn timeout(self) -> Duration {
        match self {
            Self::AiSecurity | Self::PolicyMismatch => Duration::from_secs(30),
            #[cfg(debug_assertions)]
            Self::TestTimeout => Duration::from_millis(30),
            #[cfg(debug_assertions)]
            Self::TestPanic | Self::TestPartialError => Duration::from_secs(30),
        }
    }

    fn scope(self) -> ScanScope {
        match self {
            Self::AiSecurity => ScanScope::PerFile,
            Self::PolicyMismatch => ScanScope::Workspace,
            #[cfg(debug_assertions)]
            Self::TestTimeout | Self::TestPanic | Self::TestPartialError => ScanScope::PerFile,
        }
    }
}

pub(crate) fn product_provider_set() -> Vec<Arc<dyn ProviderBackend>> {
    BuiltInProviderKind::product_kinds()
        .into_iter()
        .map(|kind| Arc::new(IsolatedBuiltInBackend::new(kind)) as Arc<dyn ProviderBackend>)
        .collect()
}

pub(crate) fn run_provider_runner(args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    if args.into_iter().next().is_some() {
        return Err("provider runner does not accept extra arguments".to_owned());
    }

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("provider runner failed to read stdin: {error}"))?;
    let request: RunnerRequest<BuiltInProviderKind> = serde_json::from_str(&input)
        .map_err(|error| format!("provider runner request decode failed: {error}"))?;

    let provider = request.provider.instantiate();
    let result = match request.phase {
        RunnerPhase::File => provider.check_result(
            request
                .scan
                .as_ref()
                .ok_or_else(|| "provider runner missing file scan context".to_owned())?,
        ),
        RunnerPhase::Workspace => provider.check_workspace_result(
            request
                .workspace
                .as_ref()
                .ok_or_else(|| "provider runner missing workspace scan context".to_owned())?,
        ),
    };
    let response = RunnerResponse { result };
    serde_json::to_writer(std::io::stdout(), &response)
        .map_err(|error| format!("provider runner response encode failed: {error}"))?;
    Ok(ExitCode::SUCCESS)
}

struct IsolatedBuiltInBackend(SubprocessProviderBackend<BuiltInProviderKind>);

impl IsolatedBuiltInBackend {
    fn new(kind: BuiltInProviderKind) -> Self {
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

#[cfg(debug_assertions)]
const TEST_RULE: RuleMetadata = RuleMetadata::new(
    "SEC998",
    "isolated test rule",
    lintai_api::Category::Security,
    Severity::Warn,
    Confidence::High,
    RuleTier::Preview,
);

#[cfg(debug_assertions)]
struct TestTimeoutProvider;

#[cfg(debug_assertions)]
impl RuleProvider for TestTimeoutProvider {
    fn id(&self) -> &str {
        "__test-timeout"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check_result(&self, _ctx: &ScanContext) -> ProviderScanResult {
        thread::sleep(Duration::from_millis(100));
        ProviderScanResult::new(Vec::new(), Vec::new())
    }
}

#[cfg(debug_assertions)]
struct TestPanicProvider;

#[cfg(debug_assertions)]
impl RuleProvider for TestPanicProvider {
    fn id(&self) -> &str {
        "__test-panic"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check_result(&self, _ctx: &ScanContext) -> ProviderScanResult {
        panic!("panic inside isolated provider");
    }
}

#[cfg(debug_assertions)]
struct TestPartialErrorProvider;

#[cfg(debug_assertions)]
impl RuleProvider for TestPartialErrorProvider {
    fn id(&self) -> &str {
        "__test-partial-error"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[TEST_RULE]
    }

    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            vec![Finding::new(
                &TEST_RULE,
                Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
                "isolated child finding",
            )],
            vec![ProviderError::new(
                self.id(),
                "isolated child execution error",
            )],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BuiltInProviderKind, IsolatedBuiltInBackend, RunnerPhase, RunnerRequest,
        resolve_lintai_driver_path,
    };
    use lintai_api::{Artifact, ArtifactKind, ScanContext, SourceFormat};
    use lintai_runtime::ProviderBackend;

    fn scan_context() -> ScanContext {
        let artifact = Artifact::new("SKILL.md", ArtifactKind::Skill, SourceFormat::Markdown);
        let content = "# demo\n";
        let document = serde_json::from_value(serde_json::json!({
            "regions": [],
            "raw_frontmatter": null
        }))
        .unwrap();
        ScanContext::new(artifact, content, document, None)
    }

    #[test]
    fn resolves_real_lintai_driver_near_test_binary() {
        let path = resolve_lintai_driver_path().unwrap();
        assert!(path.exists());
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .contains("lintai")
        );
    }

    #[test]
    fn isolated_timeout_provider_returns_timeout_error() {
        let provider = IsolatedBuiltInBackend::new(BuiltInProviderKind::TestTimeout);
        let result = provider.check_result(&scan_context());

        assert!(result.findings.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].provider_id, "__test-timeout");
        assert_eq!(
            result.errors[0].kind,
            lintai_api::ProviderErrorKind::Timeout
        );
    }

    #[test]
    fn isolated_panic_provider_returns_execution_error() {
        let provider = IsolatedBuiltInBackend::new(BuiltInProviderKind::TestPanic);
        let result = provider.check_result(&scan_context());

        assert!(result.findings.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(
            result.errors[0].kind,
            lintai_api::ProviderErrorKind::Execution
        );
    }

    #[test]
    fn isolated_partial_error_provider_preserves_findings_and_errors() {
        let provider = IsolatedBuiltInBackend::new(BuiltInProviderKind::TestPartialError);
        let result = provider.check_result(&scan_context());

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].message, "isolated child finding");
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].provider_id, "__test-partial-error");
    }

    #[test]
    fn runner_request_serializes_schema_and_phase() {
        let request = RunnerRequest {
            provider: BuiltInProviderKind::TestTimeout,
            phase: RunnerPhase::File,
            scan: Some(scan_context()),
            workspace: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"phase\":\"file\""));
    }
}
