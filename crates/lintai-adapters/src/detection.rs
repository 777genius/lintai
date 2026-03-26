use lintai_api::{ArtifactKind, SourceFormat};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectionRuleSpec {
    pub priority: u8,
    pub file_name: Option<&'static str>,
    pub suffix: Option<&'static str>,
    pub parent_dir: Option<&'static str>,
    pub path_fragment: Option<&'static str>,
    pub artifact_kind: ArtifactKind,
    pub format: SourceFormat,
}

pub fn detection_rules() -> Vec<DetectionRuleSpec> {
    let mut rules = vec![
        DetectionRuleSpec {
            priority: 0,
            file_name: Some("SKILL.md"),
            suffix: None,
            parent_dir: None,
            path_fragment: None,
            artifact_kind: ArtifactKind::Skill,
            format: SourceFormat::Markdown,
        },
        DetectionRuleSpec {
            priority: 0,
            file_name: Some("CLAUDE.md"),
            suffix: None,
            parent_dir: None,
            path_fragment: None,
            artifact_kind: ArtifactKind::Instructions,
            format: SourceFormat::Markdown,
        },
        DetectionRuleSpec {
            priority: 1,
            file_name: Some("mcp.json"),
            suffix: None,
            parent_dir: None,
            path_fragment: None,
            artifact_kind: ArtifactKind::McpConfig,
            format: SourceFormat::Json,
        },
        DetectionRuleSpec {
            priority: 1,
            file_name: Some("plugin.json"),
            suffix: None,
            parent_dir: None,
            path_fragment: Some(".cursor-plugin/"),
            artifact_kind: ArtifactKind::CursorPluginManifest,
            format: SourceFormat::Json,
        },
        DetectionRuleSpec {
            priority: 1,
            file_name: Some("hooks.json"),
            suffix: None,
            parent_dir: None,
            path_fragment: Some(".cursor-plugin/"),
            artifact_kind: ArtifactKind::CursorPluginHooks,
            format: SourceFormat::Json,
        },
        DetectionRuleSpec {
            priority: 2,
            file_name: None,
            suffix: Some(".mdc"),
            parent_dir: None,
            path_fragment: None,
            artifact_kind: ArtifactKind::CursorRules,
            format: SourceFormat::Markdown,
        },
        DetectionRuleSpec {
            priority: 2,
            file_name: Some(".cursorrules"),
            suffix: None,
            parent_dir: None,
            path_fragment: None,
            artifact_kind: ArtifactKind::CursorRules,
            format: SourceFormat::Markdown,
        },
        DetectionRuleSpec {
            priority: 3,
            file_name: None,
            suffix: Some(".sh"),
            parent_dir: Some("hooks"),
            path_fragment: Some(".cursor-plugin/hooks/"),
            artifact_kind: ArtifactKind::CursorHookScript,
            format: SourceFormat::Shell,
        },
        DetectionRuleSpec {
            priority: 3,
            file_name: None,
            suffix: Some(".md"),
            parent_dir: Some("commands"),
            path_fragment: Some(".cursor-plugin/commands/"),
            artifact_kind: ArtifactKind::CursorPluginCommand,
            format: SourceFormat::Markdown,
        },
        DetectionRuleSpec {
            priority: 3,
            file_name: None,
            suffix: Some(".md"),
            parent_dir: Some("agents"),
            path_fragment: Some(".cursor-plugin/agents/"),
            artifact_kind: ArtifactKind::CursorPluginAgent,
            format: SourceFormat::Markdown,
        },
    ];
    rules.sort_by_key(|rule| rule.priority);
    rules
}
