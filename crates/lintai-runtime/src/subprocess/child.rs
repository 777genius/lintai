use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdout, ExitStatus};

pub(super) struct RunningChild {
    pub(super) child: Child,
    pub(super) stdout: ChildStdout,
    pub(super) stderr: Option<ChildStderr>,
}

pub(super) struct ChildOutput {
    pub(super) stdout: String,
    pub(super) stderr: String,
}

pub(super) struct PreparedChildRequest {
    pub(super) executable: PathBuf,
    pub(super) request_json: Vec<u8>,
}

pub(super) struct CompletedChild {
    pub(super) status: ExitStatus,
    pub(super) output: ChildOutput,
}

pub(super) fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
