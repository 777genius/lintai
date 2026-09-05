use std::path::{Path, PathBuf};

use lintai_api::{ArtifactKind, SourceFormat};
use serde_json::Value;

use crate::normalize::normalize_path;

use super::DynamicDetectionOverride;

const AGENT_PLUGINS_V1_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";

pub(crate) fn agent_plugin_detection_patterns(
    base_path: &Path,
    files: &[PathBuf],
) -> Vec<DynamicDetectionOverride> {
    files
        .iter()
        .filter_map(|manifest_path| {
            if manifest_path.file_name().and_then(|name| name.to_str()) != Some("plugin.json") {
                return None;
            }

            let text = std::fs::read_to_string(manifest_path).ok()?;
            let value = serde_json::from_str::<Value>(&text).ok()?;
            if value.get("$schema").and_then(Value::as_str) != Some(AGENT_PLUGINS_V1_SCHEMA) {
                return None;
            }

            Some(DynamicDetectionOverride {
                normalized_path: normalize_path(base_path, manifest_path),
                kind: ArtifactKind::AgentPluginManifest,
                format: SourceFormat::Json,
            })
        })
        .collect()
}
