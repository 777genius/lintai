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

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};

    use super::*;

    #[test]
    fn read_optional_stderr_returns_empty_when_missing() {
        let mut child = Command::new("true")
            .stdout(Stdio::piped())
            .spawn()
            .expect("should spawn");
        let mut running = RunningChild {
            stdout: child.stdout.take().expect("stdout should be piped"),
            stderr: child.stderr.take(),
            child,
        };

        let output = read_child_output(&mut running);
        assert_eq!(output.stdout, "");
        assert_eq!(output.stderr, "");

        let status = running.child.wait().expect("wait should work");
        assert!(status.success());
    }

    #[test]
    fn read_child_output_collects_stdout_and_stderr() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("printf 'out'; printf 'err' 1>&2")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("should spawn");

        let mut running = RunningChild {
            stdout: child.stdout.take().expect("stdout should be piped"),
            stderr: child.stderr.take(),
            child,
        };

        let output = read_child_output(&mut running);
        assert_eq!(output.stdout, "out");
        assert_eq!(output.stderr, "err");
        assert!(running.child.wait().is_ok());
    }
}
