use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lintai_api::{ArtifactKind, SourceFormat};
use serde_json::Value;

use crate::normalize::normalize_path;

use super::DynamicDetectionOverride;
use super::glob::resolve_manifest_markdown_targets;
use super::paths::{resolve_manifest_target_directory, resolve_manifest_target_path};

pub(crate) fn manifest_backed_plugin_detection_patterns(
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
