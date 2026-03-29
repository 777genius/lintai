use super::super::*;
use super::walk::walk_root;

pub(crate) fn inventory_lintable_root(
    root: &KnownRoot,
    workspace: &WorkspaceConfig,
) -> Result<LintableInventoryStats, String> {
    let detector = FileTypeDetector::new(&workspace.engine_config);
    let base_path = absolute_base_for_scan(&root.path, workspace);
    let canonical_project_root = workspace
        .engine_config
        .project_root
        .as_deref()
        .map(std::fs::canonicalize)
        .transpose()
        .map_err(|error| format!("project root resolution failed: {error}"))?;

    let mut inventory = LintableInventoryStats::default();
    for entry in walk_root(
        &root.path,
        workspace.engine_config.follow_symlinks,
        canonical_project_root.as_deref(),
    ) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                inventory.unreadable_files += 1;
                continue;
            }
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let normalized_path = normalize_known_path(&base_path, path);
        let file_config = workspace.engine_config.resolve_for(&normalized_path);
        if !file_config.included {
            inventory.excluded_files += 1;
            continue;
        }

        if detector.detect(path, &normalized_path).is_none() {
            inventory.unrecognized_files += 1;
            continue;
        }

        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => {
                inventory.unreadable_files += 1;
                continue;
            }
        };
        if looks_binary(&bytes) {
            inventory.binary_files += 1;
            continue;
        }
        if String::from_utf8(bytes).is_err() {
            inventory.unreadable_files += 1;
        }
    }

    Ok(inventory)
}

pub(crate) fn absolute_base_for_scan(target: &Path, workspace: &WorkspaceConfig) -> PathBuf {
    if let Some(project_root) = workspace.engine_config.project_root.as_ref() {
        return project_root.clone();
    }

    if target.is_file() {
        return target
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    }

    target.to_path_buf()
}

pub(super) fn normalize_known_path(base_path: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(base_path).unwrap_or(path);
    normalize_path_string(relative)
}

pub(super) fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(1024).any(|byte| *byte == 0)
}
