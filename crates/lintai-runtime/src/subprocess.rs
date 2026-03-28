use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
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
        let executable = match (self.resolve_executable)() {
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
            .arg(&self.runner_arg)
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
