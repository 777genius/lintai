use super::*;

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

pub(crate) fn merge_summary_with_absolute_paths(
    aggregate: &mut ScanSummary,
    mut summary: ScanSummary,
    absolute_base: &Path,
) {
    rewrite_summary_paths(&mut summary, absolute_base);

    aggregate.scanned_files += summary.scanned_files;
    aggregate.skipped_files += summary.skipped_files;
    aggregate.findings.extend(summary.findings);
    aggregate.diagnostics.extend(summary.diagnostics);
    aggregate.runtime_errors.extend(summary.runtime_errors);
    aggregate.provider_metrics.extend(summary.provider_metrics);
}

fn normalize_known_path(base_path: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(base_path).unwrap_or(path);
    normalize_path_string(relative)
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

fn walk_root<'a>(
    root: &'a Path,
    follow_symlinks: bool,
    canonical_project_root: Option<&'a Path>,
) -> ignore::Walk {
    let mut walker = WalkBuilder::new(root);
    walker.hidden(false);
    walker.follow_links(follow_symlinks);
    walker.git_ignore(true);
    walker.git_global(false);
    walker.git_exclude(true);
    if let Some(project_root) = canonical_project_root {
        let project_root = project_root.to_path_buf();
        walker.filter_entry(move |entry| {
            should_visit_path(entry.path(), Some(project_root.as_path()))
        });
    } else {
        walker.filter_entry(|entry| should_visit_path(entry.path(), None));
    }
    walker.build()
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

fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(1024).any(|byte| *byte == 0)
}

fn rewrite_summary_paths(summary: &mut ScanSummary, absolute_base: &Path) {
    for finding in &mut summary.findings {
        rewrite_finding_paths(finding, absolute_base);
    }
    for diagnostic in &mut summary.diagnostics {
        diagnostic.normalized_path = absolutize_path(absolute_base, &diagnostic.normalized_path);
    }
    for error in &mut summary.runtime_errors {
        error.normalized_path = absolutize_path(absolute_base, &error.normalized_path);
    }
    for metric in &mut summary.provider_metrics {
        metric.normalized_path = absolutize_path(absolute_base, &metric.normalized_path);
    }
}

fn rewrite_finding_paths(finding: &mut Finding, absolute_base: &Path) {
    let location_path = absolutize_path(absolute_base, &finding.location.normalized_path);
    finding.location.normalized_path = location_path.clone();
    finding.stable_key.normalized_path = location_path;

    for evidence in &mut finding.evidence {
        if let Some(location) = &mut evidence.location {
            location.normalized_path = absolutize_path(absolute_base, &location.normalized_path);
        }
    }

    for related in &mut finding.related {
        related.normalized_path = absolutize_path(absolute_base, &related.normalized_path);
    }
}

fn absolutize_path(absolute_base: &Path, normalized_path: &str) -> String {
    normalize_path_string(&absolute_base.join(normalized_path))
}
