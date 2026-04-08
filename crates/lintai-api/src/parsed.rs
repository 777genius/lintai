use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Span;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Artifact {
    pub normalized_path: String,
    pub kind: ArtifactKind,
    pub format: SourceFormat,
}

impl Artifact {
    pub fn new(
        normalized_path: impl Into<String>,
        kind: ArtifactKind,
        format: SourceFormat,
    ) -> Self {
        Self {
            normalized_path: normalized_path.into(),
            kind,
            format,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Skill,
    Instructions,
    CursorRules,
    McpConfig,
    PackageManifest,
    NpmPackageLock,
    NpmShrinkwrap,
    PnpmLock,
    DevcontainerConfig,
    Dockerfile,
    DockerCompose,
    ClaudeSettings,
    ServerRegistryConfig,
    ToolDescriptorJson,
    GitHubWorkflow,
    CursorPluginManifest,
    CursorPluginHooks,
    CursorHookScript,
    CursorPluginCommand,
    CursorPluginAgent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "lowercase")]
pub enum SourceFormat {
    Markdown,
    Json,
    Yaml,
    Shell,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct ParsedDocument {
    pub regions: Vec<TextRegion>,
    pub raw_frontmatter: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub enum DocumentSemantics {
    Markdown(MarkdownSemantics),
    Json(JsonSemantics),
    Yaml(YamlSemantics),
    Shell(ShellSemantics),
}

impl DocumentSemantics {
    pub fn as_markdown(&self) -> Option<&MarkdownSemantics> {
        match self {
            Self::Markdown(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_json(&self) -> Option<&JsonSemantics> {
        match self {
            Self::Json(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_shell(&self) -> Option<&ShellSemantics> {
        match self {
            Self::Shell(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_yaml(&self) -> Option<&YamlSemantics> {
        match self {
            Self::Yaml(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct MarkdownSemantics {
    pub frontmatter: Option<FrontmatterSemantics>,
}

impl MarkdownSemantics {
    pub fn new(frontmatter: Option<FrontmatterSemantics>) -> Self {
        Self { frontmatter }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct FrontmatterSemantics {
    pub format: FrontmatterFormat,
    pub value: Value,
}

impl FrontmatterSemantics {
    pub fn new(format: FrontmatterFormat, value: Value) -> Self {
        Self { format, value }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FrontmatterFormat {
    Yaml,
    Toml,
    Json,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct JsonSemantics {
    pub value: Value,
}

impl JsonSemantics {
    pub fn new(value: Value) -> Self {
        Self { value }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct YamlSemantics {
    pub value: Value,
}

impl YamlSemantics {
    pub fn new(value: Value) -> Self {
        Self { value }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct ShellSemantics {
    pub lines: Vec<String>,
}

impl ShellSemantics {
    pub fn new(lines: Vec<String>) -> Self {
        Self { lines }
    }
}

impl ParsedDocument {
    pub fn new(regions: Vec<TextRegion>, raw_frontmatter: Option<String>) -> Self {
        Self {
            regions,
            raw_frontmatter,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct TextRegion {
    pub span: Span,
    pub kind: RegionKind,
}

impl TextRegion {
    pub fn new(span: Span, kind: RegionKind) -> Self {
        Self { span, kind }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub enum RegionKind {
    Normal,
    Heading,
    CodeBlock,
    Frontmatter,
    Blockquote,
    HtmlComment,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn constructors_roundtrip_common_types() {
        let artifact = Artifact::new("repo/file.md", ArtifactKind::Instructions, SourceFormat::Markdown);
        assert_eq!(artifact.normalized_path, "repo/file.md");
        assert_eq!(artifact.kind, ArtifactKind::Instructions);
        assert_eq!(artifact.format, SourceFormat::Markdown);

        let region = TextRegion::new(Span::new(1, 2), RegionKind::Heading);
        assert_eq!(region.span, Span::new(1, 2));
        assert_eq!(region.kind, RegionKind::Heading);

        let parsed = ParsedDocument::new(vec![region.clone()], Some("front".to_string()));
        assert_eq!(parsed.regions, vec![region]);
        assert_eq!(parsed.raw_frontmatter.as_deref(), Some("front"));
    }

    #[test]
    fn document_semantics_as_conversions() {
        let markdown = DocumentSemantics::Markdown(MarkdownSemantics::new(Some(FrontmatterSemantics::new(
            FrontmatterFormat::Yaml,
            json!({"capabilities": true}),
        ))));
        let json = DocumentSemantics::Json(JsonSemantics::new(json!({"ok": true})));
        let yaml = DocumentSemantics::Yaml(YamlSemantics::new(json!({"ok": false})));
        let shell = DocumentSemantics::Shell(ShellSemantics::new(vec!["echo".into()]));

        assert!(markdown.as_markdown().is_some());
        assert!(json.as_json().is_some());
        assert!(yaml.as_yaml().is_some());
        assert!(shell.as_shell().is_some());

        assert!(json.as_markdown().is_none());
        assert!(shell.as_json().is_none());
        assert!(markdown.as_yaml().is_none());
        assert!(yaml.as_shell().is_none());
    }

    #[test]
    fn syntax_and_frontmatter_constructors_set_expected_values() {
        let frontmatter = FrontmatterSemantics::new(FrontmatterFormat::Toml, json!({"rule":"x"}));
        assert_eq!(frontmatter.format, FrontmatterFormat::Toml);
        assert_eq!(frontmatter.value, json!({"rule":"x"}));

        let markdown = MarkdownSemantics::new(Some(frontmatter.clone()));
        assert_eq!(markdown.frontmatter, Some(frontmatter));

        let json = JsonSemantics::new(json!({"a":1}));
        assert_eq!(json.value["a"], 1);

        let yaml = YamlSemantics::new(json!({"b":2}));
        assert_eq!(yaml.value["b"], 2);

        let shell = ShellSemantics::new(vec!["cmd".into(), "arg".into()]);
        assert_eq!(shell.lines, vec!["cmd", "arg"]);
    }
}
