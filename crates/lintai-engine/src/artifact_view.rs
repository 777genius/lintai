use lintai_api::{Artifact, DocumentSemantics, ParsedDocument, ScanContext, WorkspaceArtifact};

#[doc(hidden)]
pub struct ArtifactContextRef<'a> {
    pub artifact: &'a Artifact,
    pub content: &'a str,
    pub document: &'a ParsedDocument,
    pub semantics: Option<&'a DocumentSemantics>,
}

impl<'a> ArtifactContextRef<'a> {
    pub(crate) fn from_scan_context(ctx: &'a ScanContext) -> Self {
        Self {
            artifact: &ctx.artifact,
            content: &ctx.content,
            document: &ctx.document,
            semantics: ctx.semantics.as_ref(),
        }
    }

    pub(crate) fn from_workspace_artifact(artifact: &'a WorkspaceArtifact) -> Self {
        Self {
            artifact: &artifact.artifact,
            content: &artifact.content,
            document: &artifact.document,
            semantics: artifact.semantics.as_ref(),
        }
    }
}
