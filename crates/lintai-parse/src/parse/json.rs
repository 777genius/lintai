use lintai_api::{ParsedDocument, RegionKind, Span, TextRegion};
use serde_json::Value;

use crate::limits::{ensure_document_byte_limit, ensure_value_shape_limits};
use crate::{JsonParse, ParseError};

pub fn parse(input: &str) -> Result<JsonParse, ParseError> {
    ensure_document_byte_limit(input, "JSON document")?;
    let value = serde_json::from_str::<Value>(input).map_err(|error| ParseError {
        message: format!("invalid JSON document: {error}"),
    })?;
    ensure_value_shape_limits(&value, "JSON document")?;

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
