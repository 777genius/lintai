use lintai_api::{
    Artifact, ArtifactKind, ParsedDocument, RegionKind, SourceFormat, Span, TextRegion,
};

use crate::{ParseError, ParsedArtifact, parse};

pub(crate) fn parse_document(
    artifact: &Artifact,
    content: &str,
) -> Result<ParsedArtifact, ParseError> {
    match (artifact.kind, artifact.format) {
        (ArtifactKind::Skill, SourceFormat::Markdown)
        | (ArtifactKind::Instructions, SourceFormat::Markdown)
        | (ArtifactKind::CursorRules, SourceFormat::Markdown)
        | (ArtifactKind::CursorPluginCommand, SourceFormat::Markdown)
        | (ArtifactKind::CursorPluginAgent, SourceFormat::Markdown) => parse::markdown::parse(content),
        (
            ArtifactKind::McpConfig
            | ArtifactKind::CursorPluginManifest
            | ArtifactKind::CursorPluginHooks,
            SourceFormat::Json,
        ) => parse::json::parse(content),
        (ArtifactKind::CursorHookScript, SourceFormat::Shell) => Ok(parse::shell::parse(content)),
        _ => Ok(ParsedArtifact::new(
            ParsedDocument::new(
                vec![TextRegion::new(
                    Span::new(0, content.len()),
                    RegionKind::Normal,
                )],
                None,
            ),
            None,
        )),
    }
}
