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
