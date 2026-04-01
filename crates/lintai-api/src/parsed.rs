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
    Dockerfile,
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
