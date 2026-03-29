use std::path::Path;

use super::{DetectedArtifact, FileTypeDetector};

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
