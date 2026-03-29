use super::super::super::*;
use super::super::common::is_generic_validation_excluded_path;
use super::plugin_targets::admitted_plugin_execution_targets;
use super::semantic::{
    contains_semantic_claude_command_settings, contains_semantic_docker_mcp_launch,
};

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
