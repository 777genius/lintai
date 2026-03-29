#[path = "dynamic_detection/gemini.rs"]
mod gemini;
#[path = "dynamic_detection/glob.rs"]
mod glob;
#[path = "dynamic_detection/paths.rs"]
mod paths;
#[path = "dynamic_detection/plugin_manifest.rs"]
mod plugin_manifest;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lintai_api::{ArtifactKind, SourceFormat};

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
    let mut overrides =
        plugin_manifest::manifest_backed_plugin_detection_patterns(base_path, files)
            .into_iter()
            .map(|override_spec| (override_spec.normalized_path.clone(), override_spec))
            .collect::<BTreeMap<_, _>>();
    for override_spec in gemini::gemini_mcp_detection_patterns(base_path, files) {
        overrides.insert(override_spec.normalized_path.clone(), override_spec);
    }
    overrides.into_values().collect()
}
