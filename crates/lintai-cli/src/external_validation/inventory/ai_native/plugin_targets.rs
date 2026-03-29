use super::super::super::*;
use super::super::common::is_generic_validation_excluded_path;
use super::semantic::contains_semantic_plugin_hook_commands;

pub(crate) fn admitted_plugin_execution_targets(
    repo_root: &Path,
    manifest_relative: &Path,
    text: &str,
) -> Result<Vec<String>, String> {
    let mut admitted = Vec::new();
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return Ok(admitted);
    };
    let Some(object) = value.as_object() else {
        return Ok(admitted);
    };
    let Some(dot_cursor_plugin_dir) = manifest_relative.parent() else {
        return Ok(admitted);
    };
    let Some(plugin_root_relative) = dot_cursor_plugin_dir.parent() else {
        return Ok(admitted);
    };
    let plugin_root_fs = repo_root.join(plugin_root_relative);

    for key in ["hooks", "agents", "commands"] {
        let Some(target_value) = object.get(key) else {
            continue;
        };
        for target in manifest_target_strings(target_value) {
            let resolved = plugin_root_fs.join(&target);
            if key == "commands" && has_glob_metacharacters(&target) {
                let normalized_pattern =
                    normalize_rel_path(resolved.strip_prefix(repo_root).unwrap_or(&resolved));
                if !is_repo_local_validation_path(&normalized_pattern) {
                    continue;
                }
                let Ok(glob) = globset::Glob::new(&normalized_pattern) else {
                    continue;
                };
                let matcher = glob.compile_matcher();
                let mut builder = WalkBuilder::new(repo_root);
                builder
                    .hidden(false)
                    .git_ignore(false)
                    .git_exclude(false)
                    .parents(false);
                for result in builder.build() {
                    let entry = result.map_err(|error| {
                        format!(
                            "plugin command glob walk failed for {}: {error}",
                            repo_root.display()
                        )
                    })?;
                    if !entry
                        .file_type()
                        .is_some_and(|file_type| file_type.is_file())
                    {
                        continue;
                    }
                    let normalized =
                        normalize_rel_path(entry.path().strip_prefix(repo_root).map_err(
                            |error| format!("failed to relativize plugin command target: {error}"),
                        )?);
                    if normalized.ends_with(".md")
                        && matcher.is_match(normalized.as_str())
                        && !is_generic_validation_excluded_path(&normalized)
                    {
                        admitted.push(normalized);
                    }
                }
                continue;
            }

            if !resolved.exists() {
                continue;
            }
            if resolved.is_file() {
                let normalized = normalize_rel_path(
                    resolved
                        .strip_prefix(repo_root)
                        .map_err(|error| format!("failed to relativize plugin target: {error}"))?,
                );
                if is_generic_validation_excluded_path(&normalized) {
                    continue;
                }
                match key {
                    "hooks" => {
                        let file_text = fs::read_to_string(&resolved).map_err(|error| {
                            format!(
                                "failed to read plugin execution target {}: {error}",
                                resolved.display()
                            )
                        })?;
                        if contains_semantic_plugin_hook_commands(&file_text) {
                            admitted.push(normalized);
                        }
                    }
                    "commands" => {
                        if normalized.ends_with(".md") {
                            admitted.push(normalized);
                        }
                    }
                    _ => {}
                }
                continue;
            }
            if resolved.is_dir() && matches!(key, "agents" | "commands") {
                let mut builder = WalkBuilder::new(&resolved);
                builder
                    .hidden(false)
                    .git_ignore(false)
                    .git_exclude(false)
                    .parents(false);
                for result in builder.build() {
                    let entry = result.map_err(|error| {
                        format!(
                            "plugin target walk failed for {}: {error}",
                            resolved.display()
                        )
                    })?;
                    if !entry
                        .file_type()
                        .is_some_and(|file_type| file_type.is_file())
                    {
                        continue;
                    }
                    if entry.path().extension().and_then(|ext| ext.to_str()) != Some("md") {
                        continue;
                    }
                    let normalized =
                        normalize_rel_path(entry.path().strip_prefix(repo_root).map_err(
                            |error| format!("failed to relativize plugin markdown target: {error}"),
                        )?);
                    if !is_generic_validation_excluded_path(&normalized) {
                        admitted.push(normalized);
                    }
                }
            }
        }
    }

    admitted.sort();
    admitted.dedup();
    Ok(admitted)
}

pub(crate) fn manifest_target_strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn has_glob_metacharacters(target: &str) -> bool {
    target.contains('*') || target.contains('?') || target.contains('[')
}

pub(crate) fn is_repo_local_validation_path(path: &str) -> bool {
    !path.starts_with('/') && !path.starts_with("../") && path != ".."
}
