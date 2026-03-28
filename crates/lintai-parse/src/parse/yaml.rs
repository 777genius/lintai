use lintai_api::{ParsedDocument, RegionKind, Span, TextRegion};
use serde_json::Value;

use crate::{ParseError, YamlParse};

pub fn parse(input: &str) -> Result<YamlParse, ParseError> {
    let value = serde_yaml_bw::from_str::<Value>(input).map_err(|error| ParseError {
        message: format!("invalid YAML document: {error}"),
    })?;

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
