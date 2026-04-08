use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Artifact, DocumentSemantics, Location, ParsedDocument};

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[non_exhaustive]
pub struct ScanContext {
    pub artifact: Artifact,
    pub content: String,
    pub document: ParsedDocument,
    pub semantics: Option<DocumentSemantics>,
}

impl ScanContext {
    pub fn new(
        artifact: Artifact,
        content: impl Into<String>,
        document: ParsedDocument,
        semantics: Option<DocumentSemantics>,
    ) -> Self {
        Self {
            artifact,
            content: content.into(),
            document,
            semantics,
        }
    }
}

fn declared_capabilities_from_semantics(
    semantics: Option<&DocumentSemantics>,
) -> Option<CapabilityProfile> {
    let frontmatter = semantics
        .and_then(DocumentSemantics::as_markdown)
        .and_then(|markdown| markdown.frontmatter.as_ref())?;
    let capabilities = frontmatter.value.get("capabilities")?;
    serde_json::from_value::<CapabilityProfile>(capabilities.clone()).ok()
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(default)]
pub struct CapabilityProfile {
    pub network: Option<NetworkCapability>,
    pub exec: Option<ExecCapability>,
    pub fs: FileSystemCapability,
    pub secrets: SecretCapability,
    pub mcp: McpCapability,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkCapability {
    None,
    OutboundHttps,
    OutboundAny,
    Inbound,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecCapability {
    None,
    Shell,
    Subprocess,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct FileSystemCapability {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct SecretCapability {
    #[serde(default)]
    pub read_env: bool,
    #[serde(default)]
    pub read_files: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct McpCapability {
    #[serde(default)]
    pub allowed_operations: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityConflictMode {
    #[default]
    Warn,
    Deny,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[non_exhaustive]
pub struct WorkspaceArtifact {
    pub artifact: Artifact,
    pub location_hint: Option<Location>,
    pub content: String,
    pub document: ParsedDocument,
    pub semantics: Option<DocumentSemantics>,
    pub capabilities: Option<CapabilityProfile>,
    pub metadata: Option<Value>,
}

impl WorkspaceArtifact {
    pub fn new(
        artifact: Artifact,
        content: impl Into<String>,
        document: ParsedDocument,
        semantics: Option<DocumentSemantics>,
    ) -> Self {
        let semantics_ref = semantics.as_ref();
        Self {
            artifact,
            location_hint: None,
            content: content.into(),
            document,
            capabilities: declared_capabilities_from_semantics(semantics_ref),
            semantics,
            metadata: None,
        }
    }

    pub fn with_location_hint(mut self, location_hint: Location) -> Self {
        self.location_hint = Some(location_hint);
        self
    }

    pub fn with_capabilities(mut self, capabilities: Option<CapabilityProfile>) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[non_exhaustive]
pub struct WorkspaceScanContext {
    pub project_root: Option<String>,
    pub artifacts: Vec<WorkspaceArtifact>,
    pub project_capabilities: Option<CapabilityProfile>,
    pub capability_conflict_mode: CapabilityConflictMode,
}

impl WorkspaceScanContext {
    pub fn new(
        project_root: Option<String>,
        artifacts: Vec<WorkspaceArtifact>,
        project_capabilities: Option<CapabilityProfile>,
        capability_conflict_mode: CapabilityConflictMode,
    ) -> Self {
        Self {
            project_root,
            artifacts,
            project_capabilities,
            capability_conflict_mode,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Artifact, ArtifactKind, CapabilityConflictMode, CapabilityProfile, ExecCapability,
        FileSystemCapability, FrontmatterFormat, FrontmatterSemantics, JsonSemantics, MarkdownSemantics,
        Location, ParsedDocument, SecretCapability, SourceFormat, Span, WorkspaceArtifact,
        WorkspaceScanContext, YamlSemantics,
    };
    use serde_json::json;

    use super::*;

    #[test]
    fn scan_context_keeps_original_artifact_and_payload() {
        let artifact = Artifact::new("repo/file.md", ArtifactKind::Instructions, SourceFormat::Markdown);
        let document = ParsedDocument::new(vec![], None);
        let context = ScanContext::new(
            artifact.clone(),
            "hello",
            document.clone(),
            Some(DocumentSemantics::Yaml(YamlSemantics::new(json!({"k":"v"})))),
        );

        assert_eq!(context.artifact, artifact);
        assert_eq!(context.content, "hello");
        assert_eq!(context.document, document);
        assert!(matches!(context.semantics, Some(DocumentSemantics::Yaml(_))));
    }

    #[test]
    fn workspace_artifact_extracts_capabilities_from_markdown_frontmatter() {
        let artifact = WorkspaceArtifact::new(
            Artifact::new("repo/mcp.json", ArtifactKind::McpConfig, SourceFormat::Json),
            "{}",
            ParsedDocument::new(vec![], None),
            Some(DocumentSemantics::Markdown(MarkdownSemantics::new(Some(
                FrontmatterSemantics::new(
                    FrontmatterFormat::Yaml,
                    json!({"capabilities": {"exec":"none","network":"outbound_https"}}),
                ),
            )))),
        );

        let capabilities = artifact.capabilities.expect("expected parsed capabilities");
        assert_eq!(capabilities.exec, Some(ExecCapability::None));
        assert_eq!(capabilities.network, Some(NetworkCapability::OutboundHttps));
    }

    #[test]
    fn workspace_artifact_ignores_non_markdown_capabilities() {
        let artifact = WorkspaceArtifact::new(
            Artifact::new("repo/file.md", ArtifactKind::Instructions, SourceFormat::Markdown),
            "",
            ParsedDocument::new(vec![], None),
            Some(DocumentSemantics::Json(JsonSemantics::new(json!({"capabilities":{"exec":"none"}})))),
        );

        assert!(artifact.capabilities.is_none());
    }

    #[test]
    fn workspace_artifact_mutators_set_expected_fields() {
        let artifact = WorkspaceArtifact::new(
            Artifact::new("repo/file.md", ArtifactKind::Instructions, SourceFormat::Markdown),
            "{}",
            ParsedDocument::new(vec![], None),
            None,
        )
        .with_location_hint(Location::new("repo/file.md", Span::new(0, 2)))
        .with_capabilities(Some(CapabilityProfile {
            exec: Some(ExecCapability::Shell),
            network: Some(NetworkCapability::Inbound),
            fs: FileSystemCapability::default(),
            secrets: SecretCapability::default(),
            mcp: McpCapability::default(),
        }))
        .with_metadata(json!({"foo":"bar"}));

        assert!(artifact.location_hint.is_some());
        assert!(artifact.capabilities.is_some());
        assert!(artifact.metadata.is_some());
    }

    #[test]
    fn workspace_scan_context_constructor_keeps_values() {
        let project_root = Some("/tmp/project".to_string());
        let artifacts = vec![WorkspaceArtifact::new(
            Artifact::new("repo/file.md", ArtifactKind::Instructions, SourceFormat::Markdown),
            "",
            ParsedDocument::new(vec![], None),
            None,
        )];
        let context = WorkspaceScanContext::new(
            project_root.clone(),
            artifacts.clone(),
            Some(CapabilityProfile::default()),
            CapabilityConflictMode::Deny,
        );

        assert_eq!(context.project_root, project_root);
        assert_eq!(context.artifacts.len(), 1);
        assert_eq!(context.artifacts[0].artifact.normalized_path, "repo/file.md");
        assert!(context.project_capabilities.is_some());
        assert_eq!(context.capability_conflict_mode, CapabilityConflictMode::Deny);
    }
}
