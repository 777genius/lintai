use lintai_api::{ParsedDocument, RegionKind, Span, TextRegion};
use serde_json::Value;

use crate::limits::{ensure_document_byte_limit, ensure_value_shape_limits};
use crate::{JsonParse, ParseError};

pub fn parse(input: &str) -> Result<JsonParse, ParseError> {
    ensure_document_byte_limit(input, "JSON document")?;
    let value = match serde_json::from_str::<Value>(input) {
        Ok(value) => value,
        Err(primary_error) => {
            let cleaned = strip_jsonc_comments(input);
            serde_json::from_str::<Value>(&cleaned).map_err(|_| ParseError {
                message: format!("invalid JSON document: {primary_error}"),
            })?
        }
    };
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

fn strip_jsonc_comments(input: &str) -> String {
    let mut cleaned = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if in_string {
            cleaned.push(ch);
            match ch {
                '\\' if !escaped => escaped = true,
                '"' if !escaped => in_string = false,
                _ => escaped = false,
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                escaped = false;
                cleaned.push(ch);
            }
            '/' if chars.peek() == Some(&'/') => {
                cleaned.push(' ');
                cleaned.push(' ');
                chars.next();
                while let Some(next) = chars.next() {
                    if matches!(next, '\n' | '\r') {
                        cleaned.push(next);
                        break;
                    }
                    cleaned.push(' ');
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                cleaned.push(' ');
                cleaned.push(' ');
                chars.next();
                while let Some(next) = chars.next() {
                    if next == '*' && chars.peek() == Some(&'/') {
                        cleaned.push(' ');
                        cleaned.push(' ');
                        chars.next();
                        break;
                    }
                    cleaned.push(if matches!(next, '\n' | '\r') {
                        next
                    } else {
                        ' '
                    });
                }
            }
            _ => cleaned.push(ch),
        }
    }

    cleaned
}
