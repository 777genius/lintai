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
    let archive_result = download_and_extract_archive(&download_url, &archive_path, local_dir);
    if let Err(archive_error) = archive_result {
        let _ = fs::remove_file(&archive_path);
        fetch_repo_via_git(repo, local_dir).map_err(|git_error| {
            format!(
                "failed to materialize {} at {} via archive ({archive_error}) or git fallback ({git_error})",
                repo.repo, repo.pinned_ref
            )
        })?;
    } else {
        let _ = fs::remove_file(&archive_path);
    }
    fs::write(&marker_path, format!("{}\n", repo.pinned_ref)).map_err(|error| {
        format!(
            "failed to write repo materialization marker {}: {error}",
            marker_path.display()
        )
    })?;

    Ok(())
}

fn download_and_extract_archive(
    download_url: &str,
    archive_path: &Path,
    local_dir: &Path,
) -> Result<(), String> {
    let curl_output = Command::new("curl")
        .args([
            "-L",
            "--fail",
            "--connect-timeout",
            "20",
            "--max-time",
            "180",
            "--retry",
            "2",
            "--retry-delay",
            "1",
            "-o",
        ])
        .arg(archive_path)
        .arg(download_url)
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
        .arg(archive_path)
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

    Ok(())
}

fn fetch_repo_via_git(repo: &ShortlistRepo, local_dir: &Path) -> Result<(), String> {
    let git_url = format!("https://github.com/{}.git", repo.repo);
    run_git(local_dir, ["init"], "failed to initialize git repo cache")?;
    run_git(
        local_dir,
        ["sparse-checkout", "init", "--no-cone"],
        "failed to initialize sparse checkout for repo cache",
    )?;
    run_git(
        local_dir,
        [
            "sparse-checkout",
            "set",
            "--no-cone",
            "/*.md",
            "/**/*.md",
            "/**/*.mdc",
            "/**/*.json",
            "/**/*.toml",
            "/**/*.yml",
            "/**/*.yaml",
            "/**/Dockerfile",
            "/**/docker-compose.yml",
            "/**/docker-compose.yaml",
            "/**/docker-compose.*.yml",
            "/**/docker-compose.*.yaml",
        ],
        "failed to configure sparse checkout patterns for repo cache",
    )?;
    run_git(
        local_dir,
        ["remote", "add", "origin", &git_url],
        "failed to add git remote for repo cache",
    )?;
    run_git(
        local_dir,
        [
            "fetch",
            "--depth",
            "1",
            "--filter=blob:none",
            "origin",
            &repo.pinned_ref,
        ],
        "failed to fetch pinned ref for repo cache",
    )?;
    run_git(
        local_dir,
        ["checkout", "--force", "FETCH_HEAD"],
        "failed to checkout pinned ref in repo cache",
    )?;
    Ok(())
}

fn run_git<const N: usize>(local_dir: &Path, args: [&str; N], label: &str) -> Result<(), String> {
    let output = Command::new("git")
        .current_dir(local_dir)
        .args(args)
        .output()
        .map_err(|error| format!("{label}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
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
            ownership: "community".to_owned(),
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
            r#"#!/bin/sh
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
            r#"#!/bin/sh
exit 0
"#,
        );

        let _path_guard = PathEnvGuard::new(&workspace.to_string_lossy());

        let repo = ShortlistRepo {
            repo: "acme/example".to_owned(),
            url: "https://example.com/acme/example".to_owned(),
            pinned_ref: "v1.2.3".to_owned(),
            ownership: "community".to_owned(),
            category: "tooling".to_owned(),
            subtype: "utility".to_owned(),
            status: "active".to_owned(),
            surfaces_present: Vec::new(),
            admission_paths: Vec::new(),
            rationale: String::new(),
        };

        let result = materialize_repo(&repo, &local_dir);

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(fs::read_to_string(marker_path).unwrap(), "v1.2.3\n");
        fs::remove_dir_all(workspace).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn materialize_repo_propagates_download_error_from_curl() {
        let workspace = unique_temp_dir();
        let local_dir = workspace.join("repo");
        write_mock_command(
            &workspace,
            "curl",
            r#"#!/bin/sh
echo "curl failed" >&2
exit 1
"#,
        );
        write_mock_command(&workspace, "tar", "#!/usr/bin/env sh\nexit 0\n");
        write_mock_command(
            &workspace,
            "git",
            r#"#!/bin/sh
echo "git fallback failed" >&2
exit 1
"#,
        );
        let _path_guard = PathEnvGuard::new(&workspace.to_string_lossy());

        let repo = ShortlistRepo {
            repo: "acme/example".to_owned(),
            url: "https://example.com/acme/example".to_owned(),
            pinned_ref: "v1.2.3".to_owned(),
            ownership: "community".to_owned(),
            category: "tooling".to_owned(),
            subtype: "utility".to_owned(),
            status: "active".to_owned(),
            surfaces_present: Vec::new(),
            admission_paths: Vec::new(),
            rationale: String::new(),
        };

        let result = materialize_repo(&repo, &local_dir);

        let error = result.unwrap_err();
        assert!(error.contains(
            "via archive (failed to download https://codeload.github.com/acme/example/tar.gz/v1.2.3"
        ));
        assert!(error.contains("git fallback failed"));
        fs::remove_dir_all(workspace).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn materialize_repo_falls_back_to_git_when_archive_download_fails() {
        let workspace = unique_temp_dir();
        let local_dir = workspace.join("repo");
        let marker_path = local_dir.join(".lintai-external-validation-ref");
        write_mock_command(
            &workspace,
            "curl",
            r#"#!/bin/sh
echo "curl failed" >&2
exit 1
"#,
        );
        write_mock_command(&workspace, "tar", "#!/usr/bin/env sh\nexit 1\n");
        write_mock_command(
            &workspace,
            "git",
            r#"#!/bin/sh
set -eu
cmd="$1"
shift
case "$cmd" in
  init)
    ;;
  sparse-checkout)
    ;;
  remote)
    ;;
  fetch)
    echo "fetched" > FETCH_HEAD
    ;;
  checkout)
    echo "ok" > checked-out.txt
    ;;
esac
exit 0
"#,
        );
        let _path_guard = PathEnvGuard::new(&workspace.to_string_lossy());

        let repo = ShortlistRepo {
            repo: "acme/example".to_owned(),
            url: "https://example.com/acme/example".to_owned(),
            pinned_ref: "v1.2.3".to_owned(),
            ownership: "community".to_owned(),
            category: "tooling".to_owned(),
            subtype: "utility".to_owned(),
            status: "active".to_owned(),
            surfaces_present: Vec::new(),
            admission_paths: Vec::new(),
            rationale: String::new(),
        };

        materialize_repo(&repo, &local_dir).unwrap();
        assert_eq!(fs::read_to_string(marker_path).unwrap(), "v1.2.3\n");
        assert_eq!(
            fs::read_to_string(local_dir.join("checked-out.txt")).unwrap(),
            "ok\n"
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
