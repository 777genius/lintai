use std::sync::OnceLock;

use lintai_api::{
    ArtifactKind, DocumentSemantics, FrontmatterSemantics, JsonSemantics, MarkdownSemantics,
    ParsedDocument, RegionKind, ShellSemantics, SourceFormat, Span, TextRegion, YamlSemantics,
};
use lintai_parse::parse;

use crate::detection::DetectionRuleSpec;
use crate::{ParseError, ParsedArtifact};

mod json;
mod markdown;
mod shell;
mod yaml;

#[derive(Clone, Copy)]
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
    all_surface_specs()
        .iter()
        .find(|spec| spec.artifact_kind == artifact_kind && spec.format == format)
}

pub(crate) fn all_surface_specs() -> &'static [SurfaceSpec] {
    static ALL_SURFACE_SPECS: OnceLock<Vec<SurfaceSpec>> = OnceLock::new();

    ALL_SURFACE_SPECS
        .get_or_init(|| {
            let mut specs = Vec::with_capacity(
                markdown::SURFACE_SPECS.len()
                    + json::SURFACE_SPECS.len()
                    + yaml::SURFACE_SPECS.len()
                    + shell::SURFACE_SPECS.len(),
            );
            specs.extend_from_slice(&markdown::SURFACE_SPECS);
            specs.extend_from_slice(&json::SURFACE_SPECS);
            specs.extend_from_slice(&yaml::SURFACE_SPECS);
            specs.extend_from_slice(&shell::SURFACE_SPECS);
            specs
        })
        .as_slice()
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
