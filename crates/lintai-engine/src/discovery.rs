use std::io;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use crate::EngineConfig;

const DEFAULT_EXCLUDED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    "vendor",
];

pub(crate) fn collect_files(path: &Path, config: &EngineConfig) -> io::Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    let canonical_project_root = config
        .project_root
        .as_deref()
        .map(std::fs::canonicalize)
        .transpose()?;
    let mut files = Vec::new();
    let mut walker = WalkBuilder::new(path);
    walker.hidden(false);
    walker.follow_links(config.follow_symlinks);
    walker.parents(false);
    walker.git_ignore(true);
    walker.git_global(false);
    walker.git_exclude(true);
    if let Some(project_root) = canonical_project_root {
        walker.filter_entry(move |entry| {
            should_visit_path(entry.path(), Some(project_root.as_path()))
        });
    } else {
        walker.filter_entry(|entry| should_visit_path(entry.path(), None));
    }

    for entry in walker.build() {
        let entry = entry.map_err(io::Error::other)?;
        let entry_path = entry.path();
        if entry_path.is_file() {
            files.push(entry_path.to_path_buf());
        }
    }
    Ok(files)
}

pub(crate) fn scan_base(path: &Path, config: &EngineConfig) -> PathBuf {
    if let Some(project_root) = config.project_root.as_ref() {
        return project_root.clone();
    }

    if path.is_file() {
        path.parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    } else {
        path.to_path_buf()
    }
}

fn should_skip_path(path: &Path) -> bool {
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        DEFAULT_EXCLUDED_DIRS.contains(&value.as_ref())
    })
}

fn should_visit_path(path: &Path, project_root: Option<&Path>) -> bool {
    if should_skip_path(path) {
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
