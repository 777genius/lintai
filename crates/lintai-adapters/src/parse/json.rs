use lintai_api::{DocumentSemantics, JsonSemantics, ParsedDocument, RegionKind, Span, TextRegion};
use serde_json::Value;

use crate::{ParseError, ParsedArtifact};

pub fn parse(input: &str) -> Result<ParsedArtifact, ParseError> {
    let value = serde_json::from_str::<Value>(input).map_err(|error| ParseError {
        message: format!("invalid JSON document: {error}"),
    })?;

    Ok(ParsedArtifact::new(
        ParsedDocument::new(
            vec![TextRegion::new(
                Span::new(0, input.len()),
                RegionKind::Normal,
            )],
            None,
        ),
        Some(DocumentSemantics::Json(JsonSemantics::new(value))),
    ))
}
