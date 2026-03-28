use lintai_api::{ArtifactKind, SourceFormat};

use crate::surface::all_surface_specs;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetectionRuleSpec {
    pub priority: u8,
    pub file_name: Option<&'static str>,
    pub file_name_fragment: Option<&'static str>,
    pub suffix: Option<&'static str>,
    pub parent_dir: Option<&'static str>,
    pub path_fragment: Option<&'static str>,
    pub artifact_kind: ArtifactKind,
    pub format: SourceFormat,
}

pub fn detection_rules() -> Vec<DetectionRuleSpec> {
    let mut rules: Vec<_> = all_surface_specs()
        .iter()
        .flat_map(|spec| spec.detection_rules.iter().copied())
        .collect();
    rules.sort_by_key(|rule| rule.priority);
    rules
}
