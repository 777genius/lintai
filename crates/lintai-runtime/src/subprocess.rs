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
        let executable = match self.resolve_executable_path() {
            Ok(path) => path,
            Err(error) => return self.error_result(error),
        };
        let request_json = match self.encode_request(&request) {
            Ok(value) => value,
            Err(error) => return self.error_result(error),
        };
        let mut child = match self.spawn_child(&executable) {
            Ok(child) => child,
            Err(error) => return self.error_result(error),
        };
        if let Err(error) = self.write_request(&mut child, &request_json) {
            terminate_child(&mut child.child);
            return self.error_result(error);
        }

        self.wait_for_child(child)
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

    fn wait_for_child(&self, mut child: RunningChild) -> ProviderScanResult {
        let started = Instant::now();

        loop {
            match self.poll_child_exit(&mut child.child, started) {
                Ok(Some(status)) => return self.handle_completed_child(status, child),
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(error) => {
                    terminate_child(&mut child.child);
                    return self.error_result(error);
                }
            }
        }
    }

    fn poll_child_exit(
        &self,
        child: &mut Child,
        started: Instant,
    ) -> Result<Option<ExitStatus>, ProviderError> {
        match child.try_wait() {
            Ok(Some(status)) => Ok(Some(status)),
            Ok(None) => {
                if started.elapsed() >= self.timeout {
                    terminate_child(child);
                    Err(ProviderError::timeout(
                        self.provider_id.as_str(),
                        format!(
                            "isolated provider child was terminated after exceeding timeout {:?}",
                            self.timeout
                        ),
                    ))
                } else {
                    Ok(None)
                }
            }
            Err(error) => Err(ProviderError::new(
                self.provider_id.as_str(),
                format!("provider runner wait failed: {error}"),
            )),
        }
    }

    fn handle_completed_child(
        &self,
        status: ExitStatus,
        mut child: RunningChild,
    ) -> ProviderScanResult {
        let output = read_stdout(&mut child.stdout);
        let stderr_output = read_optional_stderr(&mut child.stderr);
        if !status.success() {
            let suffix = if stderr_output.is_empty() {
                String::new()
            } else {
                format!(": {stderr_output}")
            };
            return self.error_result(ProviderError::new(
                self.provider_id.as_str(),
                format!("provider runner exited unsuccessfully{suffix}"),
            ));
        }

        match serde_json::from_str::<RunnerResponse>(&output) {
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

fn read_stdout(stdout: &mut ChildStdout) -> String {
    let mut output = String::new();
    let _ = stdout.read_to_string(&mut output);
    output
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
