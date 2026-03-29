use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lintai_api::{ArtifactKind, SourceFormat};
use serde_json::Value;

use crate::normalize::normalize_path;

use super::DynamicDetectionOverride;

pub(crate) fn gemini_mcp_detection_patterns(
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

pub(crate) fn is_gemini_mcp_config_candidate_path(normalized_path: &str) -> bool {
    normalized_path.ends_with("gemini-extension.json")
        || normalized_path.ends_with("gemini.settings.json")
        || normalized_path.ends_with(".gemini/settings.json")
        || normalized_path.ends_with("vscode.settings.json")
}
