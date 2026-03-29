use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lintai_api::{ArtifactKind, SourceFormat};
use serde_json::Value;

use crate::normalize::normalize_path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DynamicDetectionOverride {
    pub(crate) normalized_path: String,
    pub(crate) kind: ArtifactKind,
    pub(crate) format: SourceFormat,
}

pub(crate) fn dynamic_detection_overrides(
    base_path: &Path,
    files: &[PathBuf],
) -> Vec<DynamicDetectionOverride> {
    let mut overrides = manifest_backed_plugin_detection_patterns(base_path, files)
        .into_iter()
        .map(|override_spec| (override_spec.normalized_path.clone(), override_spec))
        .collect::<BTreeMap<_, _>>();
    for override_spec in gemini_mcp_detection_patterns(base_path, files) {
        overrides.insert(override_spec.normalized_path.clone(), override_spec);
    }
    overrides.into_values().collect()
}

fn manifest_backed_plugin_detection_patterns(
    base_path: &Path,
    files: &[PathBuf],
) -> Vec<DynamicDetectionOverride> {
    let normalized_to_path = files
        .iter()
        .map(|path| (normalize_path(base_path, path), path.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut overrides = BTreeMap::new();

    for (normalized_manifest_path, manifest_path) in &normalized_to_path {
        if !normalized_manifest_path.ends_with(".cursor-plugin/plugin.json") {
            continue;
        }

        let Ok(text) = std::fs::read_to_string(manifest_path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Some(object) = value.as_object() else {
            continue;
        };
        let Some(plugin_root_fs) = manifest_path.parent().and_then(Path::parent) else {
            continue;
        };

        if let Some(target) = object.get("hooks").and_then(Value::as_str)
            && let Some(normalized_target) =
                resolve_manifest_target_path(base_path, plugin_root_fs, target, &normalized_to_path)
            && let Some(target_path) = normalized_to_path.get(&normalized_target)
            && let Ok(target_text) = std::fs::read_to_string(target_path)
            && contains_semantic_plugin_hook_commands(&target_text)
        {
            overrides.insert(
                normalized_target.clone(),
                DynamicDetectionOverride {
                    normalized_path: normalized_target,
                    kind: ArtifactKind::CursorPluginHooks,
                    format: SourceFormat::Json,
                },
            );
        }

        if let Some(target) = object.get("agents").and_then(Value::as_str)
            && let Some(normalized_dir) =
                resolve_manifest_target_directory(base_path, plugin_root_fs, target)
        {
            let prefix = format!("{normalized_dir}/");
            for normalized_file in normalized_to_path.keys() {
                if normalized_file.starts_with(&prefix) && normalized_file.ends_with(".md") {
                    overrides.insert(
                        normalized_file.clone(),
                        DynamicDetectionOverride {
                            normalized_path: normalized_file.clone(),
                            kind: ArtifactKind::CursorPluginAgent,
                            format: SourceFormat::Markdown,
                        },
                    );
                }
            }
        }

        if let Some(targets) = object.get("commands") {
            for target in manifest_target_strings(targets) {
                for normalized_target in resolve_manifest_markdown_targets(
                    base_path,
                    plugin_root_fs,
                    &target,
                    &normalized_to_path,
                ) {
                    overrides.insert(
                        normalized_target.clone(),
                        DynamicDetectionOverride {
                            normalized_path: normalized_target,
                            kind: ArtifactKind::CursorPluginCommand,
                            format: SourceFormat::Markdown,
                        },
                    );
                }
            }
        }
    }

    overrides.into_values().collect()
}

fn gemini_mcp_detection_patterns(
    base_path: &Path,
    files: &[PathBuf],
) -> Vec<DynamicDetectionOverride> {
    let normalized_to_path = files
        .iter()
        .map(|path| (normalize_path(base_path, path), path.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut overrides = BTreeMap::new();

    for (normalized_path, file_path) in &normalized_to_path {
        if !is_gemini_mcp_config_candidate_path(normalized_path) {
            continue;
        }

        let Ok(text) = std::fs::read_to_string(file_path) else {
            continue;
        };
        if !contains_semantic_gemini_mcp_config(&text) {
            continue;
        }

        overrides.insert(
            normalized_path.clone(),
            DynamicDetectionOverride {
                normalized_path: normalized_path.clone(),
                kind: ArtifactKind::McpConfig,
                format: SourceFormat::Json,
            },
        );
    }

    overrides.into_values().collect()
}

fn resolve_manifest_target_path(
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

fn resolve_manifest_target_directory(
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

fn manifest_target_strings(value: &Value) -> Vec<String> {
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

fn resolve_manifest_markdown_targets(
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

fn match_manifest_markdown_glob_targets(
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

fn has_glob_metacharacters(target: &str) -> bool {
    target.contains('*') || target.contains('?') || target.contains('[')
}

fn contains_semantic_plugin_hook_commands(text: &str) -> bool {
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

fn contains_semantic_gemini_mcp_config(text: &str) -> bool {
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

fn is_repo_local_normalized_path(path: &str) -> bool {
    !path.starts_with('/') && !path.starts_with("../") && path != ".."
}

fn is_gemini_mcp_config_candidate_path(normalized_path: &str) -> bool {
    normalized_path.ends_with("gemini-extension.json")
        || normalized_path.ends_with("gemini.settings.json")
        || normalized_path.ends_with(".gemini/settings.json")
        || normalized_path.ends_with("vscode.settings.json")
}
