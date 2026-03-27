use lintai_api::{ParsedDocument, RegionKind, Span, TextRegion};
use serde_json::Value;

use crate::{JsonParse, ParseError};

pub fn parse(input: &str) -> Result<JsonParse, ParseError> {
    let value = serde_json::from_str::<Value>(input).map_err(|error| ParseError {
        message: format!("invalid JSON document: {error}"),
    })?;

    Ok(JsonParse::new(
        ParsedDocument::new(
            vec![TextRegion::new(
                Span::new(0, input.len()),
                RegionKind::Normal,
            )],
            None,
        ),
        value,
    ))
}
