use super::super::*;
use super::common::{is_generic_validation_excluded_path, json_descendants};

pub(crate) fn admitted_ai_native_paths(repo_root: &Path) -> Result<Vec<String>, String> {
    let mut admitted = Vec::new();
    let mut builder = WalkBuilder::new(repo_root);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .parents(false);
    for result in builder.build() {
        let entry = result.map_err(|error| format!("ai-native admission walk failed: {error}"))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(repo_root)
            .map_err(|error| format!("failed to relativize ai-native path: {error}"))?;
        let normalized = normalize_rel_path(relative);
        if is_generic_validation_excluded_path(&normalized) {
            continue;
        }
        if is_ai_native_docker_config_path(&normalized) {
            let text = fs::read_to_string(entry.path()).map_err(|error| {
                format!(
                    "failed to read candidate AI-native docker config {}: {error}",
                    entry.path().display()
                )
            })?;
            if contains_semantic_docker_mcp_launch(&text) {
                admitted.push(normalized);
            }
            continue;
        }
        if is_ai_native_claude_settings_path(&normalized) {
            let text = fs::read_to_string(entry.path()).map_err(|error| {
                format!(
                    "failed to read candidate Claude settings {}: {error}",
                    entry.path().display()
                )
            })?;
            if contains_semantic_claude_command_settings(&text) {
                admitted.push(normalized);
            }
            continue;
        }
        if normalized.ends_with(".cursor-plugin/plugin.json") {
            let text = fs::read_to_string(entry.path()).map_err(|error| {
                format!(
                    "failed to read candidate plugin manifest {}: {error}",
                    entry.path().display()
                )
            })?;
            admitted.extend(admitted_plugin_execution_targets(
                repo_root, relative, &text,
            )?);
        }
    }
    admitted.sort();
    admitted.dedup();
    if admitted.is_empty() {
        return Err(
            "no AI-native docker or plugin execution paths passed discovery admission".to_owned(),
        );
    }
    Ok(admitted)
}

pub(crate) fn is_ai_native_docker_config_path(normalized_path: &str) -> bool {
    normalized_path.ends_with("gemini-extension.json")
        || normalized_path.ends_with("gemini.settings.json")
        || normalized_path.ends_with("vscode.settings.json")
}

pub(crate) fn is_ai_native_claude_settings_path(normalized_path: &str) -> bool {
    normalized_path == ".claude/settings.json" || normalized_path == "claude/settings.json"
}

pub(crate) fn gemini_surface_label(normalized_path: &str) -> &'static str {
    if normalized_path.ends_with(".gemini/settings.json") {
        ".gemini/settings.json"
    } else if normalized_path.ends_with("gemini.settings.json") {
        "gemini.settings.json"
    } else if normalized_path.ends_with("vscode.settings.json") {
        "vscode.settings.json"
    } else {
        "gemini-extension.json"
    }
}

pub(crate) fn contains_semantic_docker_mcp_launch(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    json_descendants(&value).any(|candidate| {
        let Some(object) = candidate.as_object() else {
            return false;
        };
        let Some(command) = object.get("command").and_then(Value::as_str) else {
            return false;
        };
        if !command.eq_ignore_ascii_case("docker") {
            return false;
        }
        object
            .get("args")
            .and_then(Value::as_array)
            .and_then(|args| args.first())
            .and_then(Value::as_str)
            .is_some_and(|arg| arg.eq_ignore_ascii_case("run"))
    })
}

pub(crate) fn contains_semantic_gemini_mcp_config(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object
        .get("mcpServers")
        .and_then(Value::as_object)
        .is_some_and(|servers| {
            servers.values().any(|server| {
                server
                    .as_object()
                    .and_then(|entry| entry.get("command"))
                    .and_then(Value::as_str)
                    .is_some()
            })
        })
}

pub(crate) fn contains_semantic_claude_command_settings(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    json_descendants(&value).any(|candidate| {
        let Some(object) = candidate.as_object() else {
            return false;
        };
        let Some(kind) = object.get("type").and_then(Value::as_str) else {
            return false;
        };
        kind.eq_ignore_ascii_case("command")
            && object.get("command").and_then(Value::as_str).is_some()
    })
}

pub(crate) fn contains_semantic_plugin_hook_commands(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object
        .get("hooks")
        .and_then(Value::as_object)
        .is_some_and(|hooks| {
            hooks.values().any(|entries| {
                entries.as_array().is_some_and(|entries| {
                    entries.iter().any(|entry| {
                        entry
                            .as_object()
                            .and_then(|entry| entry.get("command"))
                            .and_then(Value::as_str)
                            .is_some()
                    })
                })
            })
        })
}

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
