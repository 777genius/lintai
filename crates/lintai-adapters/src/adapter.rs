use lintai_api::{
    Artifact, ArtifactKind, DocumentSemantics, FrontmatterSemantics, JsonSemantics,
    MarkdownSemantics, ParsedDocument, RegionKind, ShellSemantics, SourceFormat, Span, TextRegion,
};
use lintai_parse::parse;

use crate::{ParseError, ParsedArtifact};

pub(crate) fn parse_document(
    artifact: &Artifact,
    content: &str,
) -> Result<ParsedArtifact, ParseError> {
    match (artifact.kind, artifact.format) {
        (ArtifactKind::Skill, SourceFormat::Markdown)
        | (ArtifactKind::Instructions, SourceFormat::Markdown)
        | (ArtifactKind::CursorRules, SourceFormat::Markdown)
        | (ArtifactKind::CursorPluginCommand, SourceFormat::Markdown)
        | (ArtifactKind::CursorPluginAgent, SourceFormat::Markdown) => {
            let parsed = parse::markdown::parse(content)?;
            let mut markdown_semantics = MarkdownSemantics::new(None);
            if let (Some(format), Some(value)) =
                (parsed.frontmatter_format, parsed.frontmatter_value)
            {
                markdown_semantics.frontmatter = Some(FrontmatterSemantics::new(format, value));
            }
            Ok(ParsedArtifact::new(
                parsed.document,
                Some(DocumentSemantics::Markdown(markdown_semantics)),
            ))
        }
        (
            ArtifactKind::McpConfig
            | ArtifactKind::CursorPluginManifest
            | ArtifactKind::CursorPluginHooks,
            SourceFormat::Json,
        ) => {
            let parsed = parse::json::parse(content)?;
            Ok(ParsedArtifact::new(
                parsed.document,
                Some(DocumentSemantics::Json(JsonSemantics::new(parsed.value))),
            ))
        }
        (ArtifactKind::CursorHookScript, SourceFormat::Shell) => {
            let parsed = parse::shell::parse(content);
            Ok(ParsedArtifact::new(
                parsed.document,
                Some(DocumentSemantics::Shell(ShellSemantics::new(parsed.lines))),
            ))
        }
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
