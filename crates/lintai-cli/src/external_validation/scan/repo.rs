use super::super::*;

pub(crate) fn materialize_repo(repo: &ShortlistRepo, local_dir: &Path) -> Result<(), String> {
    let marker_path = local_dir.join(".lintai-external-validation-ref");
    if marker_path.exists()
        && fs::read_to_string(&marker_path)
            .map(|value| value.trim().to_owned())
            .unwrap_or_default()
            == repo.pinned_ref
    {
        return Ok(());
    }

    if local_dir.exists() {
        fs::remove_dir_all(local_dir).map_err(|error| {
            format!(
                "failed to remove stale repo cache dir {}: {error}",
                local_dir.display()
            )
        })?;
    }
    fs::create_dir_all(local_dir).map_err(|error| {
        format!(
            "failed to create repo cache dir {}: {error}",
            local_dir.display()
        )
    })?;

    let archive_path = local_dir.with_extension("tar.gz");
    let download_url = format!(
        "https://codeload.github.com/{}/tar.gz/{}",
        repo.repo, repo.pinned_ref
    );
    let curl_output = Command::new("curl")
        .args(["-L", "--fail", "-o"])
        .arg(&archive_path)
        .arg(&download_url)
        .output()
        .map_err(|error| format!("failed to download {download_url}: {error}"))?;
    if !curl_output.status.success() {
        return Err(format!(
            "failed to download {download_url}: {}",
            String::from_utf8_lossy(&curl_output.stderr).trim()
        ));
    }

    let tar_output = Command::new("tar")
        .arg("-xzf")
        .arg(&archive_path)
        .arg("--strip-components=1")
        .arg("-C")
        .arg(local_dir)
        .output()
        .map_err(|error| {
            format!(
                "failed to extract archive {}: {error}",
                archive_path.display()
            )
        })?;
    if !tar_output.status.success() {
        return Err(format!(
            "failed to extract archive {}: {}",
            archive_path.display(),
            String::from_utf8_lossy(&tar_output.stderr).trim()
        ));
    }

    let _ = fs::remove_file(&archive_path);
    fs::write(&marker_path, format!("{}\n", repo.pinned_ref)).map_err(|error| {
        format!(
            "failed to write repo materialization marker {}: {error}",
            marker_path.display()
        )
    })?;

    Ok(())
}

pub(crate) fn repo_dir_name(repo: &str) -> String {
    repo.replace('/', "__")
}

pub(crate) fn normalize_rel_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|parent| parent.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| "failed to resolve lintai workspace root".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::ffi::OsString;
    use std::path::Path;
    use std::process;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    static PATH_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn repo_dir_name_normalizes_slashes() {
        assert_eq!(repo_dir_name("owner/repo"), "owner__repo");
        assert_eq!(repo_dir_name("a/b/c"), "a__b__c");
    }

    #[test]
    fn normalize_rel_path_keeps_relative_components() {
        assert_eq!(normalize_rel_path(Path::new("a/../b")), "a/../b".to_owned());
    }

    #[test]
    fn workspace_root_resolves_to_repo_parent_parent_of_manifest() {
        let workspace_root = workspace_root().unwrap();
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let expected = manifest_dir
            .parent()
            .and_then(|parent| parent.parent())
            .unwrap_or_else(|| panic!("unexpected manifest dir layout"));
        assert_eq!(workspace_root, expected.to_path_buf());
    }

    #[cfg(unix)]
    #[test]
    fn materialize_repo_reuses_matching_marker_without_running_commands() {
        let workspace = unique_temp_dir();
        let local_dir = workspace.join("repo");
        let marker_path = local_dir.join(".lintai-external-validation-ref");
        fs::create_dir_all(&local_dir).unwrap();
        fs::write(&marker_path, "v1.2.3\n").unwrap();
        fs::write(local_dir.join("ignore-me.txt"), "legacy-cache").unwrap();

        let _path_guard = PathEnvGuard::new("/definitely/missing");

        let repo = ShortlistRepo {
            repo: "acme/example".to_owned(),
            url: "https://example.com/acme/example".to_owned(),
            pinned_ref: "v1.2.3".to_owned(),
            category: "tooling".to_owned(),
            subtype: "utility".to_owned(),
            status: "active".to_owned(),
            surfaces_present: Vec::new(),
            admission_paths: Vec::new(),
            rationale: String::new(),
        };
        let result = materialize_repo(&repo, &local_dir);

        if let Err(error) = result {
            panic!("materialize_repo failed: {error}");
        }
        assert_eq!(fs::read_to_string(marker_path).unwrap(), "v1.2.3\n");
        fs::remove_dir_all(workspace).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn materialize_repo_uses_curl_and_tar_when_marker_is_stale() {
        let workspace = unique_temp_dir();
        let local_dir = workspace.join("repo");
        let marker_path = local_dir.join(".lintai-external-validation-ref");
        fs::create_dir_all(&local_dir).unwrap();
        fs::write(&marker_path, "old\n").unwrap();

        write_mock_command(
            &workspace,
            "curl",
            r#"#!/usr/bin/env sh
set -eu
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    shift
    echo "mock archive" > "$1"
    exit 0
  fi
  shift
done
exit 0
"#,
        );

        write_mock_command(
            &workspace,
            "tar",
            r#"#!/usr/bin/env sh
set -eu
output_dir=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-C" ]; then
    shift
    output_dir="$1"
    break
  fi
  shift
done
mkdir -p "$output_dir"
exit 0
"#,
        );

        let previous_path = env::var_os("PATH");
        let path_value = {
            let base = previous_path.as_deref().map(|path| path.to_string_lossy());
            match base {
                Some(base) => format!("{}:{}", workspace.display(), base),
                None => workspace.to_string_lossy().to_string(),
            }
        };
        let _path_guard = PathEnvGuard::new(&path_value);

        let repo = ShortlistRepo {
            repo: "acme/example".to_owned(),
            url: "https://example.com/acme/example".to_owned(),
            pinned_ref: "v1.2.3".to_owned(),
            category: "tooling".to_owned(),
            subtype: "utility".to_owned(),
            status: "active".to_owned(),
            surfaces_present: Vec::new(),
            admission_paths: Vec::new(),
            rationale: String::new(),
        };

        let result = materialize_repo(&repo, &local_dir);

        assert!(result.is_ok());
        assert_eq!(fs::read_to_string(marker_path).unwrap(), "v1.2.3\n");
        fs::remove_dir_all(workspace).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn materialize_repo_propagates_download_error_from_curl() {
        let workspace = unique_temp_dir();
        let local_dir = workspace.join("repo");
        let previous_path = env::var_os("PATH");
        write_mock_command(
            &workspace,
            "curl",
            r#"#!/usr/bin/env sh
echo "curl failed" >&2
exit 1
"#,
        );
        write_mock_command(&workspace, "tar", "#!/usr/bin/env sh\nexit 0\n");
        let path_value = {
            let base = previous_path.as_deref().map(|path| path.to_string_lossy());
            match base {
                Some(base) => format!("{}:{}", workspace.display(), base),
                None => workspace.to_string_lossy().to_string(),
            }
        };
        let _path_guard = PathEnvGuard::new(&path_value);

        let repo = ShortlistRepo {
            repo: "acme/example".to_owned(),
            url: "https://example.com/acme/example".to_owned(),
            pinned_ref: "v1.2.3".to_owned(),
            category: "tooling".to_owned(),
            subtype: "utility".to_owned(),
            status: "active".to_owned(),
            surfaces_present: Vec::new(),
            admission_paths: Vec::new(),
            rationale: String::new(),
        };

        let result = materialize_repo(&repo, &local_dir);

        let error = result.unwrap_err();
        assert!(
            error.contains(
                "failed to download https://codeload.github.com/acme/example/tar.gz/v1.2.3"
            )
        );
        fs::remove_dir_all(workspace).unwrap();
    }

    #[cfg(unix)]
    fn write_mock_command(directory: &Path, name: &str, body: &str) {
        let path = directory.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    fn unique_temp_dir() -> PathBuf {
        static DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let sequence = DIR_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let dir = env::temp_dir().join(format!(
            "lintai-materialize-repo-{}-{}",
            process::id(),
            sequence
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    struct PathEnvGuard {
        previous: Option<OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    #[cfg(unix)]
    impl PathEnvGuard {
        fn new(path: &str) -> Self {
            let lock = PATH_MUTEX.lock().unwrap();
            let previous = env::var_os("PATH");
            // SAFETY: tests intentionally isolate PATH; this only affects the current test process.
            unsafe { env::set_var("PATH", path) };
            Self {
                previous,
                _lock: lock,
            }
        }
    }

    #[cfg(unix)]
    impl Drop for PathEnvGuard {
        fn drop(&mut self) {
            match self.previous.as_ref() {
                Some(path) => {
                    // SAFETY: restoration is scoped to the tests and always runs on drop.
                    unsafe { env::set_var("PATH", path) };
                }
                None => {
                    // SAFETY: restoration is scoped to the tests and always runs on drop.
                    unsafe { env::remove_var("PATH") };
                }
            }
        }
    }
}
