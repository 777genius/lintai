use lintai_api::{ParsedDocument, RegionKind, Span, TextRegion};
use serde_json::Value;

use crate::limits::{ensure_document_byte_limit, ensure_value_shape_limits};
use crate::{ParseError, YamlParse};

pub fn parse(input: &str) -> Result<YamlParse, ParseError> {
    ensure_document_byte_limit(input, "YAML document")?;
    let value = serde_yaml_bw::from_str::<Value>(input).map_err(|error| ParseError {
        message: format!("invalid YAML document: {error}"),
    })?;
    ensure_value_shape_limits(&value, "YAML document")?;

    Ok(YamlParse::new(
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
