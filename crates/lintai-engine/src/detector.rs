use lintai_adapters::{DetectionRuleSpec, detection_rules};
use lintai_api::{ArtifactKind, SourceFormat};
use serde::Serialize;

use crate::config::EngineConfig;

#[path = "detector/match.rs"]
mod match_impl;
#[cfg(test)]
#[path = "detector/tests.rs"]
mod tests;

#[derive(Clone, Debug)]
pub struct DetectionRule {
    pub priority: u8,
    pub file_name: Option<&'static str>,
    pub file_name_fragment: Option<&'static str>,
    pub suffix: Option<&'static str>,
    pub parent_dir: Option<&'static str>,
    pub path_fragment: Option<&'static str>,
    pub artifact_kind: ArtifactKind,
    pub format: SourceFormat,
}

#[derive(Clone, Debug)]
pub struct FileTypeDetector {
    rules: Vec<DetectionRule>,
    overrides: Vec<crate::config::DetectionOverride>,
}

impl Default for FileTypeDetector {
    fn default() -> Self {
        Self::new(&EngineConfig::default())
    }
}

impl FileTypeDetector {
    pub fn new(config: &EngineConfig) -> Self {
        Self {
            rules: detection_rules()
                .into_iter()
                .map(DetectionRule::from)
                .collect(),
            overrides: config.detection_overrides.clone(),
        }
    }
}

impl From<DetectionRuleSpec> for DetectionRule {
    fn from(value: DetectionRuleSpec) -> Self {
        Self {
            priority: value.priority,
            file_name: value.file_name,
            file_name_fragment: value.file_name_fragment,
            suffix: value.suffix,
            parent_dir: value.parent_dir,
            path_fragment: value.path_fragment,
            artifact_kind: value.artifact_kind,
            format: value.format,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DetectedArtifact {
    pub kind: ArtifactKind,
    pub format: SourceFormat,
}
