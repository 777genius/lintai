use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use lintai_ai_security::{AiSecurityProvider, PolicyMismatchProvider};
use lintai_api::{
    Confidence, Finding, Location, ProviderError, ProviderScanResult, RuleMetadata, RuleProvider,
    RuleTier, ScanContext, ScanScope, Severity, Span, WorkspaceScanContext,
};
use lintai_engine::ProviderBackend;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum RunnerPhase {
    File,
    Workspace,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RunnerRequest {
    provider: BuiltInProviderKind,
    phase: RunnerPhase,
    scan: Option<ScanContext>,
    workspace: Option<WorkspaceScanContext>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RunnerResponse {
    result: ProviderScanResult,
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
    let request: RunnerRequest = serde_json::from_str(&input)
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

struct IsolatedBuiltInBackend {
    kind: BuiltInProviderKind,
    provider_id: String,
    rules: Box<[RuleMetadata]>,
    timeout: Duration,
    scope: ScanScope,
}

impl IsolatedBuiltInBackend {
    fn new(kind: BuiltInProviderKind) -> Self {
        let provider = kind.instantiate();
        Self {
            kind,
            provider_id: provider.id().to_owned(),
            rules: provider.rules().to_vec().into_boxed_slice(),
            timeout: kind.timeout(),
            scope: kind.scope(),
        }
    }

    fn run_child(&self, request: RunnerRequest) -> ProviderScanResult {
        let executable = match resolve_lintai_driver_path() {
            Ok(path) => path,
            Err(message) => {
                return ProviderScanResult::new(
                    Vec::new(),
                    vec![ProviderError::new(self.id(), message)],
                );
            }
        };
        let request_json = match serde_json::to_vec(&request) {
            Ok(value) => value,
            Err(error) => {
                return ProviderScanResult::new(
                    Vec::new(),
                    vec![ProviderError::new(
                        self.id(),
                        format!("provider runner request encode failed: {error}"),
                    )],
                );
            }
        };
        let mut child = match Command::new(executable)
            .arg("__provider-runner")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                return ProviderScanResult::new(
                    Vec::new(),
                    vec![ProviderError::new(
                        self.id(),
                        format!("provider runner spawn failed: {error}"),
                    )],
                );
            }
        };

        let mut stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                return ProviderScanResult::new(
                    Vec::new(),
                    vec![ProviderError::new(
                        self.id(),
                        "provider runner stdin was unavailable".to_owned(),
                    )],
                );
            }
        };
        if let Err(error) = stdin.write_all(&request_json) {
            let _ = child.kill();
            let _ = child.wait();
            return ProviderScanResult::new(
                Vec::new(),
                vec![ProviderError::new(
                    self.id(),
                    format!("provider runner request write failed: {error}"),
                )],
            );
        }
        drop(stdin);

        let mut stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return ProviderScanResult::new(
                    Vec::new(),
                    vec![ProviderError::new(
                        self.id(),
                        "provider runner stdout was unavailable".to_owned(),
                    )],
                );
            }
        };
        let mut stderr = child.stderr.take();
        let started = Instant::now();

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut output = String::new();
                    let _ = stdout.read_to_string(&mut output);
                    let stderr_output = read_optional_stderr(&mut stderr);
                    if !status.success() {
                        let suffix = if stderr_output.is_empty() {
                            String::new()
                        } else {
                            format!(": {stderr_output}")
                        };
                        return ProviderScanResult::new(
                            Vec::new(),
                            vec![ProviderError::new(
                                self.id(),
                                format!("provider runner exited unsuccessfully{suffix}"),
                            )],
                        );
                    }
                    let response: RunnerResponse = match serde_json::from_str(&output) {
                        Ok(response) => response,
                        Err(error) => {
                            return ProviderScanResult::new(
                                Vec::new(),
                                vec![ProviderError::new(
                                    self.id(),
                                    format!("provider runner response decode failed: {error}"),
                                )],
                            );
                        }
                    };
                    return response.result;
                }
                Ok(None) => {
                    if started.elapsed() >= self.timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return ProviderScanResult::new(
                            Vec::new(),
                            vec![ProviderError::timeout(
                                self.id(),
                                format!(
                                    "isolated provider child was terminated after exceeding timeout {:?}",
                                    self.timeout
                                ),
                            )],
                        );
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return ProviderScanResult::new(
                        Vec::new(),
                        vec![ProviderError::new(
                            self.id(),
                            format!("provider runner wait failed: {error}"),
                        )],
                    );
                }
            }
        }
    }
}

impl ProviderBackend for IsolatedBuiltInBackend {
    fn id(&self) -> &str {
        &self.provider_id
    }

    fn rules(&self) -> &[RuleMetadata] {
        &self.rules
    }

    fn scan_scope(&self) -> ScanScope {
        self.scope
    }

    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult {
        self.run_child(RunnerRequest {
            provider: self.kind,
            phase: RunnerPhase::File,
            scan: Some(ctx.clone()),
            workspace: None,
        })
    }

    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult {
        self.run_child(RunnerRequest {
            provider: self.kind,
            phase: RunnerPhase::Workspace,
            scan: None,
            workspace: Some(ctx.clone()),
        })
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }
}

fn read_optional_stderr(stderr: &mut Option<std::process::ChildStderr>) -> String {
    let Some(stderr) = stderr.as_mut() else {
        return String::new();
    };
    let mut output = String::new();
    let _ = stderr.read_to_string(&mut output);
    output.trim().to_owned()
}

fn resolve_lintai_driver_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("LINTAI_SELF_EXE") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_lintai") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }

    let current = std::env::current_exe()
        .map_err(|error| format!("failed to resolve current executable: {error}"))?;
    if current
        .file_stem()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name == "lintai")
    {
        return Ok(current);
    }

    let binary_name = format!("lintai{}", std::env::consts::EXE_SUFFIX);
    let mut candidates = Vec::new();
    if let Some(parent) = current.parent() {
        candidates.push(parent.join(&binary_name));
        if parent.file_name().is_some_and(|name| name == "deps") {
            if let Some(grandparent) = parent.parent() {
                candidates.push(grandparent.join(&binary_name));
            }
        }
    }

    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "failed to locate lintai executable near {}",
        current.display()
    ))
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
    use lintai_engine::ProviderBackend;

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
