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
