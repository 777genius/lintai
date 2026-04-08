use super::super::*;

pub(crate) fn run_scan(lintai_bin: &Path, repo_dir: &Path, json: bool) -> Result<String, String> {
    let mut command = Command::new(lintai_bin);
    command.current_dir(repo_dir).arg("scan").arg(".");
    if json {
        command.arg("--format=json");
    }
    let output = command
        .output()
        .map_err(|error| format!("failed to run lintai in {}: {error}", repo_dir.display()))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("lintai stdout was not valid UTF-8: {error}"))?;
    if matches!(output.status.code(), Some(0 | 1)) {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "lintai scan failed in {} with exit {:?}: {}",
        repo_dir.display(),
        output.status.code(),
        stderr.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn existing_unix_command(paths: &[&str]) -> PathBuf {
        paths
            .iter()
            .copied()
            .find(|path| Path::new(path).is_file())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/bin/echo"))
    }

    #[cfg(unix)]
    fn write_failure_script() -> PathBuf {
        let script = std::env::temp_dir().join(format!("lintai-scan-fail-{}", std::process::id()));
        let _ = std::fs::remove_file(&script);
        std::fs::write(
            &script,
            "#!/bin/sh\n\
echo scan .\n\
exit 2\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        script
    }

    #[cfg(unix)]
    #[test]
    fn run_scan_with_unix_echo_returns_stdout() {
        let path = existing_unix_command(&["/usr/bin/echo", "/bin/echo", "/usr/local/bin/echo"]);
        let text = run_scan(Path::new(&path), Path::new("/"), false).unwrap();
        assert_eq!(text, "scan .\n");
    }

    #[cfg(unix)]
    #[test]
    fn run_scan_with_unix_false_returns_runtime_error() {
        let path = write_failure_script();
        let error = run_scan(Path::new(&path), Path::new("/"), false).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(error.starts_with("lintai scan failed in / with exit Some(2):"));
    }

    #[cfg(unix)]
    #[test]
    fn run_scan_with_missing_binary_returns_spawn_error() {
        let error = run_scan(Path::new("/does/not/exist"), Path::new("/"), false).unwrap_err();
        assert!(
            error.starts_with("failed to run lintai in /:"),
            "unexpected error: {error}"
        );
    }
}
