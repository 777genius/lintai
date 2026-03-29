use lintai_api::{ArtifactKind, SourceFormat};

use super::{SurfaceSpec, parse_markdown_surface};
use crate::detection::DetectionRuleSpec;

const SKILL_RULES: &[DetectionRuleSpec] = &[DetectionRuleSpec {
    priority: 0,
    file_name: Some("SKILL.md"),
    file_name_fragment: None,
    suffix: None,
    parent_dir: None,
    path_fragment: None,
    artifact_kind: ArtifactKind::Skill,
    format: SourceFormat::Markdown,
}];

const INSTRUCTIONS_RULES: &[DetectionRuleSpec] = &[
    DetectionRuleSpec {
        priority: 0,
        file_name: Some("CLAUDE.md"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::Instructions,
        format: SourceFormat::Markdown,
    },
    DetectionRuleSpec {
        priority: 0,
        file_name: Some("AGENTS.md"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::Instructions,
        format: SourceFormat::Markdown,
    },
    DetectionRuleSpec {
        priority: 1,
        file_name: Some("copilot-instructions.md"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: Some(".github/"),
        artifact_kind: ArtifactKind::Instructions,
        format: SourceFormat::Markdown,
    },
    DetectionRuleSpec {
        priority: 1,
        file_name: None,
        file_name_fragment: None,
        suffix: Some(".instructions.md"),
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::Instructions,
        format: SourceFormat::Markdown,
    },
    DetectionRuleSpec {
        priority: 1,
        file_name: None,
        file_name_fragment: None,
        suffix: Some(".agent.md"),
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::Instructions,
        format: SourceFormat::Markdown,
    },
];

const CURSOR_RULES_RULES: &[DetectionRuleSpec] = &[
    DetectionRuleSpec {
        priority: 3,
        file_name: None,
        file_name_fragment: None,
        suffix: Some(".mdc"),
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::CursorRules,
        format: SourceFormat::Markdown,
    },
    DetectionRuleSpec {
        priority: 3,
        file_name: Some(".cursorrules"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::CursorRules,
        format: SourceFormat::Markdown,
    },
];

const CURSOR_PLUGIN_COMMAND_RULES: &[DetectionRuleSpec] = &[DetectionRuleSpec {
    priority: 4,
    file_name: None,
    file_name_fragment: None,
    suffix: Some(".md"),
    parent_dir: Some("commands"),
    path_fragment: Some(".cursor-plugin/commands/"),
    artifact_kind: ArtifactKind::CursorPluginCommand,
    format: SourceFormat::Markdown,
}];

const CURSOR_PLUGIN_AGENT_RULES: &[DetectionRuleSpec] = &[DetectionRuleSpec {
    priority: 4,
    file_name: None,
    file_name_fragment: None,
    suffix: Some(".md"),
    parent_dir: Some("agents"),
    path_fragment: Some(".cursor-plugin/agents/"),
    artifact_kind: ArtifactKind::CursorPluginAgent,
    format: SourceFormat::Markdown,
}];

pub(super) const SURFACE_SPECS: [SurfaceSpec; 5] = [
    SurfaceSpec {
        id: "skill_markdown",
        artifact_kind: ArtifactKind::Skill,
        format: SourceFormat::Markdown,
        detection_rules: SKILL_RULES,
        parse_fn: parse_markdown_surface,
    },
    SurfaceSpec {
        id: "instructions_markdown",
        artifact_kind: ArtifactKind::Instructions,
        format: SourceFormat::Markdown,
        detection_rules: INSTRUCTIONS_RULES,
        parse_fn: parse_markdown_surface,
    },
    SurfaceSpec {
        id: "cursor_rules_markdown",
        artifact_kind: ArtifactKind::CursorRules,
        format: SourceFormat::Markdown,
        detection_rules: CURSOR_RULES_RULES,
        parse_fn: parse_markdown_surface,
    },
    SurfaceSpec {
        id: "cursor_plugin_command_markdown",
        artifact_kind: ArtifactKind::CursorPluginCommand,
        format: SourceFormat::Markdown,
        detection_rules: CURSOR_PLUGIN_COMMAND_RULES,
        parse_fn: parse_markdown_surface,
    },
    SurfaceSpec {
        id: "cursor_plugin_agent_markdown",
        artifact_kind: ArtifactKind::CursorPluginAgent,
        format: SourceFormat::Markdown,
        detection_rules: CURSOR_PLUGIN_AGENT_RULES,
        parse_fn: parse_markdown_surface,
    },
];
