use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::normalize::normalize_path;

use super::paths::is_repo_local_normalized_path;

pub(crate) fn resolve_manifest_markdown_targets(
    base_path: &Path,
    plugin_root_fs: &Path,
    target: &str,
    normalized_to_path: &BTreeMap<String, PathBuf>,
) -> Vec<String> {
    if has_glob_metacharacters(target) {
        return match_manifest_markdown_glob_targets(
            base_path,
            plugin_root_fs,
            target,
            normalized_to_path,
        );
    }

    let resolved = plugin_root_fs.join(target);
    if resolved.is_file() {
        let normalized = normalize_path(base_path, &resolved);
        return (is_repo_local_normalized_path(&normalized)
            && normalized.ends_with(".md")
            && normalized_to_path.contains_key(&normalized))
        .then_some(normalized)
        .into_iter()
        .collect();
    }

    if resolved.is_dir() {
        let normalized_dir = normalize_path(base_path, &resolved);
        if !is_repo_local_normalized_path(&normalized_dir) {
            return Vec::new();
        }
        let prefix = format!("{normalized_dir}/");
        return normalized_to_path
            .keys()
            .filter(|normalized| normalized.starts_with(&prefix) && normalized.ends_with(".md"))
            .cloned()
            .collect();
    }

    Vec::new()
}

pub(crate) fn has_glob_metacharacters(target: &str) -> bool {
    target.contains('*') || target.contains('?') || target.contains('[')
}

pub(crate) fn match_manifest_markdown_glob_targets(
    base_path: &Path,
    plugin_root_fs: &Path,
    target: &str,
    normalized_to_path: &BTreeMap<String, PathBuf>,
) -> Vec<String> {
    let normalized_pattern = normalize_path(base_path, &plugin_root_fs.join(target));
    if !is_repo_local_normalized_path(&normalized_pattern) {
        return Vec::new();
    }
    let Ok(glob) = globset::Glob::new(&normalized_pattern) else {
        return Vec::new();
    };
    let matcher = glob.compile_matcher();
    normalized_to_path
        .keys()
        .filter(|normalized| normalized.ends_with(".md") && matcher.is_match(normalized.as_str()))
        .cloned()
        .collect()
}
