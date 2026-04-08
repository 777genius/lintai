use std::process::{Child, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use lintai_api::ProviderError;

use super::child::terminate_child;

pub(super) struct ChildWaitPolicy {
    timeout: Duration,
    poll_interval: Duration,
}

impl ChildWaitPolicy {
    pub(super) fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            poll_interval: Duration::from_millis(5),
        }
    }
}

pub(super) fn wait_for_exit(
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

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::Duration;

    use super::*;

    #[test]
    fn wait_policy_persists_timeout_and_interval() {
        let policy = ChildWaitPolicy::new(Duration::from_millis(25));
        assert_eq!(policy.timeout, Duration::from_millis(25));
        assert_eq!(policy.poll_interval, Duration::from_millis(5));
    }

    #[test]
    fn wait_for_exit_returns_status_for_fast_exit() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("should spawn");
        let status = wait_for_exit(
            &mut child,
            ChildWaitPolicy::new(Duration::from_millis(200)),
            "unit",
        )
        .expect("child should finish quickly");
        assert!(status.success());
    }

    #[test]
    fn wait_for_exit_times_out_and_reports_error() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("sleep 1")
            .spawn()
            .expect("should spawn");
        let error = wait_for_exit(
            &mut child,
            ChildWaitPolicy::new(Duration::from_millis(10)),
            "unit-timeout",
        )
        .expect_err("expected timeout");

        assert_eq!(error.provider_id, "unit-timeout");
        assert_eq!(error.kind, lintai_api::ProviderErrorKind::Timeout);
    }
}
