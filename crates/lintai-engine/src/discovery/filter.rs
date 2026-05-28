use std::path::Path;

pub(super) const DEFAULT_EXCLUDED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    "vendor",
];

fn should_skip_path(path: &Path) -> bool {
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        DEFAULT_EXCLUDED_DIRS.contains(&value.as_ref())
    })
}

fn is_scan_root(path: &Path, scan_root: &Path) -> bool {
    if path == scan_root {
        return true;
    }

    match (
        std::fs::canonicalize(path),
        std::fs::canonicalize(scan_root),
    ) {
        (Ok(path), Ok(scan_root)) => path == scan_root,
        _ => false,
    }
}

fn is_nested_repository_root(path: &Path, scan_root: Option<&Path>) -> bool {
    let git_marker = path.join(".git");
    if !git_marker.is_dir() && !git_marker.is_file() {
        return false;
    }

    if scan_root.is_some_and(|scan_root| is_scan_root(path, scan_root)) {
        return false;
    }

    true
}

pub(super) fn should_visit_path(
    path: &Path,
    project_root: Option<&Path>,
    scan_root: Option<&Path>,
) -> bool {
    if should_skip_path(path) {
        return false;
    }
    if is_nested_repository_root(path, scan_root) {
        return false;
    }

    let Some(project_root) = project_root else {
        return true;
    };

    match std::fs::canonicalize(path) {
        Ok(canonical_path) => {
            canonical_path == project_root || canonical_path.starts_with(project_root)
        }
        Err(_) => true,
    }
}
