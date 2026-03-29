use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use lintai_api::{
    ProviderError, ProviderScanResult, RuleMetadata, ScanContext, ScanScope, WorkspaceScanContext,
};
use serde::Serialize;

use crate::backend::ProviderBackend;
use crate::protocol::{RunnerPhase, RunnerRequest, RunnerResponse};

pub type ExecutableResolver = Arc<dyn Fn() -> Result<PathBuf, String> + Send + Sync>;

pub struct SubprocessProviderBackend<S> {
    selector: S,
    provider_id: String,
    rules: Box<[RuleMetadata]>,
    timeout: Duration,
    scope: ScanScope,
    resolve_executable: ExecutableResolver,
    runner_arg: String,
}

impl<S> SubprocessProviderBackend<S> {
    pub fn new(
        selector: S,
        provider_id: impl Into<String>,
        rules: impl Into<Vec<RuleMetadata>>,
        timeout: Duration,
        scope: ScanScope,
        resolve_executable: ExecutableResolver,
        runner_arg: impl Into<String>,
    ) -> Self {
        Self {
            selector,
            provider_id: provider_id.into(),
            rules: rules.into().into_boxed_slice(),
            timeout,
            scope,
            resolve_executable,
            runner_arg: runner_arg.into(),
        }
    }

    fn run_child(&self, request: RunnerRequest<S>) -> ProviderScanResult
    where
        S: Clone + Send + Sync + Serialize,
    {
        match self.prepare_request(&request) {
            Ok(prepared) => match self.start_child(prepared) {
                Ok(child) => self.complete_child(child),
                Err(error) => self.error_result(error),
            },
            Err(error) => self.error_result(error),
        }
    }

    fn prepare_request(
        &self,
        request: &RunnerRequest<S>,
    ) -> Result<PreparedChildRequest, ProviderError>
    where
        S: Serialize,
    {
        Ok(PreparedChildRequest {
            executable: self.resolve_executable_path()?,
            request_json: self.encode_request(request)?,
        })
    }

    fn resolve_executable_path(&self) -> Result<PathBuf, ProviderError> {
        (self.resolve_executable)()
            .map_err(|message| ProviderError::new(self.provider_id.as_str(), message))
    }

    fn encode_request(&self, request: &RunnerRequest<S>) -> Result<Vec<u8>, ProviderError>
    where
        S: Serialize,
    {
        serde_json::to_vec(request).map_err(|error| {
            ProviderError::new(
                self.provider_id.as_str(),
                format!("provider runner request encode failed: {error}"),
            )
        })
    }

    fn start_child(&self, prepared: PreparedChildRequest) -> Result<RunningChild, ProviderError> {
        let mut child = self.spawn_child(&prepared.executable)?;
        if let Err(error) = self.write_request(&mut child, &prepared.request_json) {
            terminate_child(&mut child.child);
            return Err(error);
        }
        Ok(child)
    }

    fn spawn_child(&self, executable: &PathBuf) -> Result<RunningChild, ProviderError> {
        let mut child = Command::new(executable)
            .arg(&self.runner_arg)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                ProviderError::new(
                    self.provider_id.as_str(),
                    format!("provider runner spawn failed: {error}"),
                )
            })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            ProviderError::new(
                self.provider_id.as_str(),
                "provider runner stdout was unavailable".to_owned(),
            )
        })?;
        let stderr = child.stderr.take();

        Ok(RunningChild {
            child,
            stdout,
            stderr,
        })
    }

    fn write_request(
        &self,
        child: &mut RunningChild,
        request_json: &[u8],
    ) -> Result<(), ProviderError> {
        let mut stdin = child.child.stdin.take().ok_or_else(|| {
            ProviderError::new(
                self.provider_id.as_str(),
                "provider runner stdin was unavailable".to_owned(),
            )
        })?;
        stdin.write_all(request_json).map_err(|error| {
            ProviderError::new(
                self.provider_id.as_str(),
                format!("provider runner request write failed: {error}"),
            )
        })?;
        drop(stdin);
        Ok(())
    }

    fn complete_child(&self, mut child: RunningChild) -> ProviderScanResult {
        match self.wait_for_completion(&mut child) {
            Ok(completed) => self.decode_response(completed),
            Err(error) => {
                terminate_child(&mut child.child);
                self.error_result(error)
            }
        }
    }

    fn wait_for_completion(
        &self,
        child: &mut RunningChild,
    ) -> Result<CompletedChild, ProviderError> {
        let status = wait_for_exit(
            &mut child.child,
            ChildWaitPolicy::new(self.timeout),
            self.provider_id.as_str(),
        )?;
        let output = read_child_output(child);
        Ok(CompletedChild { status, output })
    }

    fn decode_response(&self, completed: CompletedChild) -> ProviderScanResult {
        if !completed.status.success() {
            let suffix = if completed.output.stderr.is_empty() {
                String::new()
            } else {
                format!(": {}", completed.output.stderr)
            };
            return self.error_result(ProviderError::new(
                self.provider_id.as_str(),
                format!("provider runner exited unsuccessfully{suffix}"),
            ));
        }

        match serde_json::from_str::<RunnerResponse>(&completed.output.stdout) {
            Ok(response) => response.result,
            Err(error) => self.error_result(ProviderError::new(
                self.provider_id.as_str(),
                format!("provider runner response decode failed: {error}"),
            )),
        }
    }

    fn error_result(&self, error: ProviderError) -> ProviderScanResult {
        ProviderScanResult::new(Vec::new(), vec![error])
    }
}

impl<S> ProviderBackend for SubprocessProviderBackend<S>
where
    S: Clone + Send + Sync + Serialize,
{
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
            provider: self.selector.clone(),
            phase: RunnerPhase::File,
            scan: Some(ctx.clone()),
            workspace: None,
        })
    }

    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult {
        self.run_child(RunnerRequest {
            provider: self.selector.clone(),
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

struct RunningChild {
    child: Child,
    stdout: ChildStdout,
    stderr: Option<ChildStderr>,
}

struct ChildOutput {
    stdout: String,
    stderr: String,
}

struct PreparedChildRequest {
    executable: PathBuf,
    request_json: Vec<u8>,
}

struct CompletedChild {
    status: ExitStatus,
    output: ChildOutput,
}

struct ChildWaitPolicy {
    timeout: Duration,
    poll_interval: Duration,
}

impl ChildWaitPolicy {
    fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            poll_interval: Duration::from_millis(5),
        }
    }
}

fn read_stdout(stdout: &mut ChildStdout) -> String {
    let mut output = String::new();
    let _ = stdout.read_to_string(&mut output);
    output
}

fn read_child_output(child: &mut RunningChild) -> ChildOutput {
    ChildOutput {
        stdout: read_stdout(&mut child.stdout),
        stderr: read_optional_stderr(&mut child.stderr),
    }
}

fn wait_for_exit(
    child: &mut Child,
    policy: ChildWaitPolicy,
    provider_id: &str,
) -> Result<ExitStatus, ProviderError> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if started.elapsed() >= policy.timeout {
                    terminate_child(child);
                    return Err(ProviderError::timeout(
                        provider_id,
                        format!(
                            "isolated provider child was terminated after exceeding timeout {:?}",
                            policy.timeout
                        ),
                    ));
                }
                thread::sleep(policy.poll_interval);
            }
            Err(error) => {
                return Err(ProviderError::new(
                    provider_id,
                    format!("provider runner wait failed: {error}"),
                ));
            }
        }
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
