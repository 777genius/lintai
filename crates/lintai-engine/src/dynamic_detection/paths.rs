use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::normalize::normalize_path;

pub(crate) fn resolve_manifest_target_path(
    base_path: &Path,
    plugin_root_fs: &Path,
    target: &str,
    normalized_to_path: &BTreeMap<String, PathBuf>,
) -> Option<String> {
    let resolved = plugin_root_fs.join(target);
    let normalized = normalize_path(base_path, &resolved);
    (is_repo_local_normalized_path(&normalized) && normalized_to_path.contains_key(&normalized))
        .then_some(normalized)
}

pub(crate) fn resolve_manifest_target_directory(
    base_path: &Path,
    plugin_root_fs: &Path,
    target: &str,
) -> Option<String> {
    let resolved = plugin_root_fs.join(target);
    if !resolved.is_dir() {
        return None;
    }
    let normalized = normalize_path(base_path, &resolved);
    is_repo_local_normalized_path(&normalized).then_some(normalized)
}

pub(crate) fn is_repo_local_normalized_path(path: &str) -> bool {
    !path.starts_with('/') && !path.starts_with("../") && path != ".."
}
