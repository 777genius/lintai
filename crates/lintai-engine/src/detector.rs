use std::path::Path;

use lintai_adapters::{DetectionRuleSpec, detection_rules};
use lintai_api::{ArtifactKind, SourceFormat};
use serde::Serialize;

use crate::config::EngineConfig;

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

impl FileTypeDetector {
    pub fn detect(&self, path: &Path, normalized_path: &str) -> Option<DetectedArtifact> {
        for override_rule in &self.overrides {
            if override_rule.matcher.is_match(normalized_path) {
                return Some(DetectedArtifact {
                    kind: override_rule.kind,
                    format: override_rule.format,
                });
            }
        }

        let file_name = path.file_name().and_then(|value| value.to_str());
        let parent_dir = path
            .parent()
            .and_then(|value| value.file_name())
            .and_then(|value| value.to_str());
        let path_string = path.to_string_lossy();

        for rule in &self.rules {
            let file_name_match = rule
                .file_name
                .is_none_or(|expected| file_name == Some(expected));
            let file_name_fragment_match = rule
                .file_name_fragment
                .is_none_or(|fragment| file_name.is_some_and(|name| name.contains(fragment)));
            let suffix_match = rule
                .suffix
                .is_none_or(|suffix| path_string.ends_with(suffix));
            let parent_match = rule
                .parent_dir
                .is_none_or(|expected| parent_dir == Some(expected));
            let fragment_match = rule
                .path_fragment
                .is_none_or(|fragment| path_string.contains(fragment));

            if file_name_match
                && file_name_fragment_match
                && suffix_match
                && parent_match
                && fragment_match
            {
                return Some(DetectedArtifact {
                    kind: rule.artifact_kind,
                    format: rule.format,
                });
            }
        }

        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DetectedArtifact {
    pub kind: ArtifactKind,
    pub format: SourceFormat,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use lintai_api::ArtifactKind;

    use super::FileTypeDetector;

    #[test]
    fn detects_v0_1_file_types() {
        let detector = FileTypeDetector::default();

        assert_eq!(
            detector
                .detect(Path::new("/tmp/SKILL.md"), "SKILL.md")
                .unwrap()
                .kind,
            ArtifactKind::Skill
        );
        assert_eq!(
            detector
                .detect(
                    Path::new("/tmp/.cursor/rules/demo.mdc"),
                    ".cursor/rules/demo.mdc"
                )
                .unwrap()
                .kind,
            ArtifactKind::CursorRules
        );
        assert_eq!(
            detector
                .detect(
                    Path::new("/tmp/project/.cursor-plugin/plugin.json"),
                    ".cursor-plugin/plugin.json"
                )
                .unwrap()
                .kind,
            ArtifactKind::CursorPluginManifest
        );
        assert_eq!(
            detector
                .detect(
                    Path::new("/tmp/project/.cursor-plugin/hooks.json"),
                    ".cursor-plugin/hooks.json"
                )
                .unwrap()
                .kind,
            ArtifactKind::CursorPluginHooks
        );
        assert_eq!(
            detector
                .detect(Path::new("/tmp/project/.mcp.json"), ".mcp.json")
                .unwrap()
                .kind,
            ArtifactKind::McpConfig
        );
        assert_eq!(
            detector
                .detect(
                    Path::new("/tmp/project/.claude/mcp/chrome-devtools.json"),
                    ".claude/mcp/chrome-devtools.json"
                )
                .unwrap()
                .kind,
            ArtifactKind::McpConfig
        );
        assert_eq!(
            detector
                .detect(
                    Path::new("/tmp/project/pkg/mcp/testdata/toolsets-full-tools.json"),
                    "pkg/mcp/testdata/toolsets-full-tools.json"
                )
                .unwrap()
                .kind,
            ArtifactKind::ToolDescriptorJson
        );
        assert_eq!(
            detector
                .detect(
                    Path::new("/tmp/project/.cursor-plugin/commands/setup.md"),
                    ".cursor-plugin/commands/setup.md"
                )
                .unwrap()
                .kind,
            ArtifactKind::CursorPluginCommand
        );
        assert_eq!(
            detector
                .detect(
                    Path::new("/tmp/project/.cursor-plugin/agents/reviewer.md"),
                    ".cursor-plugin/agents/reviewer.md"
                )
                .unwrap()
                .kind,
            ArtifactKind::CursorPluginAgent
        );
        assert!(
            detector
                .detect(Path::new("/tmp/project/tsconfig.json"), "tsconfig.json")
                .is_none()
        );
    }
}
