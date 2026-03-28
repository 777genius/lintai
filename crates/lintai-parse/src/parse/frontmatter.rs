use serde_json::Value;

use crate::{ParseDiagnostic, ParseError};

const MAX_FRONTMATTER_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extraction {
    pub raw: Option<String>,
    pub body_start: usize,
}

pub fn extract(input: &str) -> Result<Extraction, ParseError> {
    let trimmed = input.strip_prefix('\u{feff}').unwrap_or(input);
    let bom_offset = input.len() - trimmed.len();
    let Some(rest) = trimmed.strip_prefix("---\n") else {
        return Ok(Extraction {
            raw: None,
            body_start: 0,
        });
    };

    let mut search_offset = 0;
    for line in rest.split_inclusive('\n') {
        let line_start = search_offset;
        search_offset += line.len();
        if line == "---\n" || line == "---" {
            let raw = &rest[..line_start];
            if raw.len() > MAX_FRONTMATTER_BYTES {
                return Err(ParseError {
                    message: format!("frontmatter exceeds {} bytes", MAX_FRONTMATTER_BYTES),
                });
            }
            return Ok(Extraction {
                raw: Some(raw.trim_end_matches('\n').to_owned()),
                body_start: bom_offset + 4 + search_offset,
            });
        }
    }

    Err(ParseError {
        message: "unterminated frontmatter block".to_owned(),
    })
}

pub fn parse_yaml(raw: &str) -> Result<Value, ParseError> {
    serde_yaml_bw::from_str::<Value>(raw).map_err(|error| ParseError {
        message: format!("invalid YAML frontmatter: {error}"),
    })
}

pub fn recovery_diagnostic(error: &ParseError) -> ParseDiagnostic {
    ParseDiagnostic::new(format!(
        "frontmatter was ignored because YAML was invalid; markdown body was still scanned and frontmatter semantics were not applied ({})",
        error.message
    ))
}
