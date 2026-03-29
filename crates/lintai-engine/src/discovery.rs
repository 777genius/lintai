use std::io;
use std::path::{Path, PathBuf};

#[path = "discovery/filter.rs"]
mod filter;
#[path = "discovery/walk.rs"]
mod walk;

pub(crate) fn collect_files(path: &Path, config: &crate::EngineConfig) -> io::Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    let canonical_project_root = config
        .project_root
        .as_deref()
        .map(std::fs::canonicalize)
        .transpose()?;
    let mut files = Vec::new();
    for entry in walk::build_walker(
        path,
        config.follow_symlinks,
        canonical_project_root.as_deref(),
    ) {
        let entry = entry.map_err(io::Error::other)?;
        let entry_path = entry.path();
        if entry_path.is_file() {
            files.push(entry_path.to_path_buf());
        }
    }
    Ok(files)
}

pub(crate) fn scan_base(path: &Path, config: &crate::EngineConfig) -> PathBuf {
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
