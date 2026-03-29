use super::super::*;
use super::inventory::normalize_known_path;
use super::walk::walk_root;

pub(crate) fn workspace_for_known_root(
    root: &KnownRoot,
    base_workspace: &WorkspaceConfig,
) -> Result<WorkspaceConfig, String> {
    let mut workspace = base_workspace.clone();
    if matches!(root.scope, KnownRootScope::Global) {
        workspace
            .engine_config
            .set_project_root(Some(scan_root_base(root)));
    }

    let Some(artifact_kind) = root.artifact_kind_hint else {
        return Ok(workspace);
    };
    let patterns = match artifact_kind {
        ArtifactKind::McpConfig => mcp_detection_override_patterns(root, &workspace)?,
        ArtifactKind::Instructions | ArtifactKind::CursorRules => {
            markdown_detection_override_patterns(root, &workspace)
        }
        _ => return Ok(workspace),
    };
    if patterns.is_empty() {
        return Ok(workspace);
    }
    if matches!(
        artifact_kind,
        ArtifactKind::CursorRules | ArtifactKind::Instructions
    ) {
        workspace
            .engine_config
            .add_include_patterns(&patterns)
            .map_err(|error| format!("include override failed: {error}"))?;
    }

    workspace
        .engine_config
        .add_detection_override_for_kind(&patterns, artifact_kind)
        .map_err(|error| format!("detection override failed: {error}"))?;
    Ok(workspace)
}

fn scan_root_base(root: &KnownRoot) -> PathBuf {
    if root.path.is_file() {
        return root
            .path
            .parent()
            .map_or_else(|| root.path.clone(), Path::to_path_buf);
    }
    root.path
        .parent()
        .map_or_else(|| root.path.clone(), Path::to_path_buf)
}

fn mcp_detection_override_patterns(
    root: &KnownRoot,
    workspace: &WorkspaceConfig,
) -> Result<Vec<String>, String> {
    let Some(base_path) = workspace.engine_config.project_root.as_deref() else {
        return Ok(Vec::new());
    };
    let detector = FileTypeDetector::new(&workspace.engine_config);
    let mut patterns = BTreeSet::new();

    for path in mcp_candidate_files(root, workspace)? {
        let normalized_path = normalize_known_path(base_path, &path);
        if detector.detect(&path, &normalized_path).is_some() {
            continue;
        }
        if !is_mcp_like_json_file(&path)? {
            continue;
        }
        patterns.insert(normalized_path);
    }

    Ok(patterns.into_iter().collect())
}

fn markdown_detection_override_patterns(
    root: &KnownRoot,
    workspace: &WorkspaceConfig,
) -> Vec<String> {
    let Some(base_path) = workspace.engine_config.project_root.as_deref() else {
        return Vec::new();
    };
    let detector = FileTypeDetector::new(&workspace.engine_config);
    let mut patterns = BTreeSet::new();

    if root.path.is_file() {
        let normalized_path = normalize_known_path(base_path, &root.path);
        if detector.detect(&root.path, &normalized_path).is_none() {
            patterns.insert(normalized_path);
        }
        return patterns.into_iter().collect();
    }

    let canonical_project_root = workspace
        .engine_config
        .project_root
        .as_deref()
        .and_then(|project_root| std::fs::canonicalize(project_root).ok());
    for entry in walk_root(
        &root.path,
        workspace.engine_config.follow_symlinks,
        canonical_project_root.as_deref(),
    ) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if !path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
        {
            continue;
        }

        let normalized_path = normalize_known_path(base_path, path);
        if detector.detect(path, &normalized_path).is_some() {
            continue;
        }
        patterns.insert(normalized_path);
    }

    patterns.into_iter().collect()
}

fn mcp_candidate_files(
    root: &KnownRoot,
    workspace: &WorkspaceConfig,
) -> Result<Vec<PathBuf>, String> {
    if root.path.is_file() {
        return Ok(vec![root.path.clone()]);
    }

    let canonical_project_root = workspace
        .engine_config
        .project_root
        .as_deref()
        .map(std::fs::canonicalize)
        .transpose()
        .map_err(|error| format!("project root resolution failed: {error}"))?;
    let mut candidates = Vec::new();
    for entry in walk_root(
        &root.path,
        workspace.engine_config.follow_symlinks,
        canonical_project_root.as_deref(),
    ) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            candidates.push(path.to_path_buf());
        }
    }
    Ok(candidates)
}

fn is_mcp_like_json_file(path: &Path) -> Result<bool, String> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => return Ok(false),
    };
    let value = match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    Ok(matches_mcp_like_json_value(&value))
}

fn matches_mcp_like_json_value(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.keys().any(|key| is_mcp_like_top_level_key(key))
}

fn is_mcp_like_top_level_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("mcpServers")
        || key.eq_ignore_ascii_case("mcpservers")
        || key.eq_ignore_ascii_case("servers")
        || key.eq_ignore_ascii_case("command")
        || key.eq_ignore_ascii_case("args")
        || key.eq_ignore_ascii_case("env")
        || key.eq_ignore_ascii_case("url")
        || key.eq_ignore_ascii_case("headers")
        || key.eq_ignore_ascii_case("transport")
        || key.eq_ignore_ascii_case("type")
        || key.eq_ignore_ascii_case("cwd")
}
