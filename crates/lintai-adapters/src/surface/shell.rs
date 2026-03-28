use lintai_api::{ArtifactKind, SourceFormat};

use super::{SurfaceSpec, parse_shell_surface};
use crate::detection::DetectionRuleSpec;

const CURSOR_HOOK_SCRIPT_RULES: &[DetectionRuleSpec] = &[DetectionRuleSpec {
    priority: 4,
    file_name: None,
    file_name_fragment: None,
    suffix: Some(".sh"),
    parent_dir: Some("hooks"),
    path_fragment: Some(".cursor-plugin/hooks/"),
    artifact_kind: ArtifactKind::CursorHookScript,
    format: SourceFormat::Shell,
}];

pub(super) const SURFACE_SPECS: [SurfaceSpec; 1] = [SurfaceSpec {
    id: "cursor_hook_script_shell",
    artifact_kind: ArtifactKind::CursorHookScript,
    format: SourceFormat::Shell,
    detection_rules: CURSOR_HOOK_SCRIPT_RULES,
    parse_fn: parse_shell_surface,
}];
