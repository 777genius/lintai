use lintai_engine::normalize_path_string;

pub fn validate_path_within_project(
    target: &std::path::Path,
    project_root: Option<&std::path::Path>,
) -> Result<(), String> {
    let Some(project_root) = project_root else {
        return Ok(());
    };

    let absolute_target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("cwd resolution failed: {error}"))?
            .join(target)
    };
    let normalized_target = normalize_path_string(&absolute_target);
    let normalized_root = normalize_path_string(project_root);

    if normalized_target == normalized_root
        || normalized_target.starts_with(&(normalized_root.clone() + "/"))
    {
        if absolute_target.exists() {
            let canonical_root = std::fs::canonicalize(project_root)
                .map_err(|error| format!("project root resolution failed: {error}"))?;
            let canonical_target = std::fs::canonicalize(&absolute_target)
                .map_err(|error| format!("target resolution failed: {error}"))?;
            if canonical_target != canonical_root && !canonical_target.starts_with(&canonical_root)
            {
                return Err(format!(
                    "path {} resolves outside project root {}",
                    absolute_target.display(),
                    project_root.display()
                ));
            }
        }
        Ok(())
    } else {
        Err(format!(
            "path {} is outside project root {}",
            absolute_target.display(),
            project_root.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::validate_path_within_project;
    use lintai_engine::normalize_path_string;

    #[test]
    fn accepts_paths_within_project_root() {
        let project_root = Path::new("/tmp/lintai");
        let target = Path::new("/tmp/lintai/docs/SKILL.md");

        assert!(validate_path_within_project(target, Some(project_root)).is_ok());
    }

    #[test]
    fn rejects_paths_outside_project_root() {
        let project_root = Path::new("/tmp/lintai");
        let target = Path::new("/tmp/elsewhere/SKILL.md");

        let error = validate_path_within_project(target, Some(project_root)).unwrap_err();
        assert!(error.contains("outside project root"));
    }

    #[test]
    fn rejects_parent_directory_escape_from_project_root() {
        let project_root = Path::new("/tmp/lintai");
        let target = Path::new("/tmp/lintai/../OTHER.md");

        let error = validate_path_within_project(target, Some(project_root)).unwrap_err();
        assert!(error.contains("outside project root"));
    }

    #[test]
    fn normalizes_current_directory_components() {
        let normalized = normalize_path_string(Path::new("/tmp/lintai/./docs/SKILL.md"));
        assert_eq!(normalized, "/tmp/lintai/docs/SKILL.md");
    }

    #[test]
    fn rejects_symlink_target_outside_project_root() {
        let temp_dir = unique_temp_dir("lintai-path-symlink");
        let outside_path = unique_temp_dir("lintai-path-symlink-target").join("outside.md");
        std::fs::create_dir_all(temp_dir.join("docs")).unwrap();
        std::fs::create_dir_all(outside_path.parent().unwrap()).unwrap();
        std::fs::write(&outside_path, b"# outside\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_path, temp_dir.join("docs/SKILL.md")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&outside_path, temp_dir.join("docs/SKILL.md")).unwrap();

        let error = validate_path_within_project(&temp_dir.join("docs/SKILL.md"), Some(&temp_dir))
            .unwrap_err();
        assert!(error.contains("resolves outside project root"));
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{nanos}-{sequence}",
            std::process::id()
        ))
    }
}
