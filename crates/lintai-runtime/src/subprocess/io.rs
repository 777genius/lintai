use std::io::Read;
use std::process::ChildStderr;

use super::child::{ChildOutput, RunningChild};

pub(super) fn read_optional_stderr(stderr: &mut Option<ChildStderr>) -> String {
    let Some(stderr) = stderr.as_mut() else {
        return String::new();
    };
    let mut output = String::new();
    let _ = stderr.read_to_string(&mut output);
    output.trim().to_owned()
}

fn read_stdout(stdout: &mut std::process::ChildStdout) -> String {
    let mut output = String::new();
    let _ = stdout.read_to_string(&mut output);
    output
}

pub(super) fn read_child_output(child: &mut RunningChild) -> ChildOutput {
    ChildOutput {
        stdout: read_stdout(&mut child.stdout),
        stderr: read_optional_stderr(&mut child.stderr),
    }
}
