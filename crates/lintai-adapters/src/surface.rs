use lintai_api::{
    ArtifactKind, DocumentSemantics, FrontmatterSemantics, JsonSemantics, MarkdownSemantics,
    ParsedDocument, RegionKind, ShellSemantics, SourceFormat, Span, TextRegion, YamlSemantics,
};
use lintai_parse::parse;

use crate::detection::DetectionRuleSpec;
use crate::{ParseError, ParsedArtifact};

pub(crate) struct SurfaceSpec {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) id: &'static str,
    pub(crate) artifact_kind: ArtifactKind,
    pub(crate) format: SourceFormat,
    pub(crate) detection_rules: &'static [DetectionRuleSpec],
    pub(crate) parse_fn: fn(&str) -> Result<ParsedArtifact, ParseError>,
}

pub(crate) fn surface_spec(
    artifact_kind: ArtifactKind,
    format: SourceFormat,
) -> Option<&'static SurfaceSpec> {
    ALL_SURFACE_SPECS
        .iter()
        .find(|spec| spec.artifact_kind == artifact_kind && spec.format == format)
}

pub(crate) fn all_surface_specs() -> &'static [SurfaceSpec] {
    ALL_SURFACE_SPECS
}

fn parse_markdown_surface(content: &str) -> Result<ParsedArtifact, ParseError> {
    let parsed = parse::markdown::parse(content)?;
    let mut markdown_semantics = MarkdownSemantics::new(None);
    if let (Some(format), Some(value)) = (parsed.frontmatter_format, parsed.frontmatter_value) {
        markdown_semantics.frontmatter = Some(FrontmatterSemantics::new(format, value));
    }
    Ok(ParsedArtifact::new(
        parsed.document,
        Some(DocumentSemantics::Markdown(markdown_semantics)),
    )
    .with_diagnostics(parsed.diagnostics))
}

fn parse_json_surface(content: &str) -> Result<ParsedArtifact, ParseError> {
    let parsed = parse::json::parse(content)?;
    Ok(ParsedArtifact::new(
        parsed.document,
        Some(DocumentSemantics::Json(JsonSemantics::new(parsed.value))),
    ))
}

fn parse_yaml_surface(content: &str) -> Result<ParsedArtifact, ParseError> {
    let parsed = parse::yaml::parse(content)?;
    Ok(ParsedArtifact::new(
        parsed.document,
        Some(DocumentSemantics::Yaml(YamlSemantics::new(parsed.value))),
    ))
}

fn parse_shell_surface(content: &str) -> Result<ParsedArtifact, ParseError> {
    let parsed = parse::shell::parse(content);
    Ok(ParsedArtifact::new(
        parsed.document,
        Some(DocumentSemantics::Shell(ShellSemantics::new(parsed.lines))),
    ))
}

pub(crate) fn fallback_parse(content: &str) -> ParsedArtifact {
    ParsedArtifact::new(
        ParsedDocument::new(
            vec![TextRegion::new(
                Span::new(0, content.len()),
                RegionKind::Normal,
            )],
            None,
        ),
        None,
    )
}

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

const INSTRUCTIONS_RULES: &[DetectionRuleSpec] = &[DetectionRuleSpec {
    priority: 0,
    file_name: Some("CLAUDE.md"),
    file_name_fragment: None,
    suffix: None,
    parent_dir: None,
    path_fragment: None,
    artifact_kind: ArtifactKind::Instructions,
    format: SourceFormat::Markdown,
}];

const MCP_CONFIG_RULES: &[DetectionRuleSpec] = &[
    DetectionRuleSpec {
        priority: 1,
        file_name: Some("mcp.json"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: Some(".cursor/"),
        artifact_kind: ArtifactKind::McpConfig,
        format: SourceFormat::Json,
    },
    DetectionRuleSpec {
        priority: 1,
        file_name: Some("mcp.json"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: Some(".vscode/"),
        artifact_kind: ArtifactKind::McpConfig,
        format: SourceFormat::Json,
    },
    DetectionRuleSpec {
        priority: 1,
        file_name: Some("mcp.json"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: Some(".roo/"),
        artifact_kind: ArtifactKind::McpConfig,
        format: SourceFormat::Json,
    },
    DetectionRuleSpec {
        priority: 1,
        file_name: Some("mcp.json"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: Some(".kiro/settings/"),
        artifact_kind: ArtifactKind::McpConfig,
        format: SourceFormat::Json,
    },
    DetectionRuleSpec {
        priority: 1,
        file_name: Some("mcp.json"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::McpConfig,
        format: SourceFormat::Json,
    },
    DetectionRuleSpec {
        priority: 1,
        file_name: Some(".mcp.json"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::McpConfig,
        format: SourceFormat::Json,
    },
    DetectionRuleSpec {
        priority: 1,
        file_name: None,
        file_name_fragment: None,
        suffix: Some(".json"),
        parent_dir: None,
        path_fragment: Some(".claude/mcp/"),
        artifact_kind: ArtifactKind::McpConfig,
        format: SourceFormat::Json,
    },
];

const SERVER_REGISTRY_RULES: &[DetectionRuleSpec] = &[DetectionRuleSpec {
    priority: 1,
    file_name: Some("server.json"),
    file_name_fragment: None,
    suffix: None,
    parent_dir: None,
    path_fragment: None,
    artifact_kind: ArtifactKind::ServerRegistryConfig,
    format: SourceFormat::Json,
}];

const CLAUDE_SETTINGS_RULES: &[DetectionRuleSpec] = &[
    DetectionRuleSpec {
        priority: 1,
        file_name: Some("settings.json"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: Some(".claude"),
        path_fragment: None,
        artifact_kind: ArtifactKind::ClaudeSettings,
        format: SourceFormat::Json,
    },
    DetectionRuleSpec {
        priority: 1,
        file_name: Some("settings.json"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: Some("claude"),
        path_fragment: None,
        artifact_kind: ArtifactKind::ClaudeSettings,
        format: SourceFormat::Json,
    },
];

const CURSOR_PLUGIN_MANIFEST_RULES: &[DetectionRuleSpec] = &[DetectionRuleSpec {
    priority: 1,
    file_name: Some("plugin.json"),
    file_name_fragment: None,
    suffix: None,
    parent_dir: None,
    path_fragment: Some(".cursor-plugin/"),
    artifact_kind: ArtifactKind::CursorPluginManifest,
    format: SourceFormat::Json,
}];

const CURSOR_PLUGIN_HOOKS_RULES: &[DetectionRuleSpec] = &[DetectionRuleSpec {
    priority: 1,
    file_name: Some("hooks.json"),
    file_name_fragment: None,
    suffix: None,
    parent_dir: None,
    path_fragment: Some(".cursor-plugin/"),
    artifact_kind: ArtifactKind::CursorPluginHooks,
    format: SourceFormat::Json,
}];

const TOOL_DESCRIPTOR_RULES: &[DetectionRuleSpec] = &[
    DetectionRuleSpec {
        priority: 2,
        file_name: Some("tools.json"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::ToolDescriptorJson,
        format: SourceFormat::Json,
    },
    DetectionRuleSpec {
        priority: 2,
        file_name: None,
        file_name_fragment: Some("tools"),
        suffix: Some(".json"),
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::ToolDescriptorJson,
        format: SourceFormat::Json,
    },
    DetectionRuleSpec {
        priority: 2,
        file_name: None,
        file_name_fragment: None,
        suffix: Some(".tool.json"),
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::ToolDescriptorJson,
        format: SourceFormat::Json,
    },
    DetectionRuleSpec {
        priority: 2,
        file_name: None,
        file_name_fragment: None,
        suffix: Some(".tools.json"),
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::ToolDescriptorJson,
        format: SourceFormat::Json,
    },
];

const GITHUB_WORKFLOW_RULES: &[DetectionRuleSpec] = &[
    DetectionRuleSpec {
        priority: 2,
        file_name: None,
        file_name_fragment: None,
        suffix: Some(".yml"),
        parent_dir: None,
        path_fragment: Some(".github/workflows/"),
        artifact_kind: ArtifactKind::GitHubWorkflow,
        format: SourceFormat::Yaml,
    },
    DetectionRuleSpec {
        priority: 2,
        file_name: None,
        file_name_fragment: None,
        suffix: Some(".yaml"),
        parent_dir: None,
        path_fragment: Some(".github/workflows/"),
        artifact_kind: ArtifactKind::GitHubWorkflow,
        format: SourceFormat::Yaml,
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

static ALL_SURFACE_SPECS: &[SurfaceSpec] = &[
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
        id: "mcp_config_json",
        artifact_kind: ArtifactKind::McpConfig,
        format: SourceFormat::Json,
        detection_rules: MCP_CONFIG_RULES,
        parse_fn: parse_json_surface,
    },
    SurfaceSpec {
        id: "server_registry_json",
        artifact_kind: ArtifactKind::ServerRegistryConfig,
        format: SourceFormat::Json,
        detection_rules: SERVER_REGISTRY_RULES,
        parse_fn: parse_json_surface,
    },
    SurfaceSpec {
        id: "claude_settings_json",
        artifact_kind: ArtifactKind::ClaudeSettings,
        format: SourceFormat::Json,
        detection_rules: CLAUDE_SETTINGS_RULES,
        parse_fn: parse_json_surface,
    },
    SurfaceSpec {
        id: "cursor_plugin_manifest_json",
        artifact_kind: ArtifactKind::CursorPluginManifest,
        format: SourceFormat::Json,
        detection_rules: CURSOR_PLUGIN_MANIFEST_RULES,
        parse_fn: parse_json_surface,
    },
    SurfaceSpec {
        id: "cursor_plugin_hooks_json",
        artifact_kind: ArtifactKind::CursorPluginHooks,
        format: SourceFormat::Json,
        detection_rules: CURSOR_PLUGIN_HOOKS_RULES,
        parse_fn: parse_json_surface,
    },
    SurfaceSpec {
        id: "tool_descriptor_json",
        artifact_kind: ArtifactKind::ToolDescriptorJson,
        format: SourceFormat::Json,
        detection_rules: TOOL_DESCRIPTOR_RULES,
        parse_fn: parse_json_surface,
    },
    SurfaceSpec {
        id: "github_workflow_yaml",
        artifact_kind: ArtifactKind::GitHubWorkflow,
        format: SourceFormat::Yaml,
        detection_rules: GITHUB_WORKFLOW_RULES,
        parse_fn: parse_yaml_surface,
    },
    SurfaceSpec {
        id: "cursor_rules_markdown",
        artifact_kind: ArtifactKind::CursorRules,
        format: SourceFormat::Markdown,
        detection_rules: CURSOR_RULES_RULES,
        parse_fn: parse_markdown_surface,
    },
    SurfaceSpec {
        id: "cursor_hook_script_shell",
        artifact_kind: ArtifactKind::CursorHookScript,
        format: SourceFormat::Shell,
        detection_rules: CURSOR_HOOK_SCRIPT_RULES,
        parse_fn: parse_shell_surface,
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
