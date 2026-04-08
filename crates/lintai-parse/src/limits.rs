use serde_json::Value;

use crate::ParseError;

pub(crate) const MAX_STRUCTURED_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STRUCTURED_VALUE_DEPTH: usize = 128;
const MAX_STRUCTURED_VALUE_NODES: usize = 1_000_000;

pub(crate) fn ensure_document_byte_limit(input: &str, label: &str) -> Result<(), ParseError> {
    if input.len() > MAX_STRUCTURED_DOCUMENT_BYTES {
        return Err(ParseError {
            message: format!("{label} exceeds {} bytes", MAX_STRUCTURED_DOCUMENT_BYTES),
        });
    }

    Ok(())
}

pub(crate) fn ensure_value_shape_limits(value: &Value, label: &str) -> Result<(), ParseError> {
    let mut nodes = 0usize;
    walk_value(value, 1, &mut nodes, label)
}

fn walk_value(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    label: &str,
) -> Result<(), ParseError> {
    if depth > MAX_STRUCTURED_VALUE_DEPTH {
        return Err(ParseError {
            message: format!("{label} exceeds max depth {}", MAX_STRUCTURED_VALUE_DEPTH),
        });
    }

    *nodes += 1;
    if *nodes > MAX_STRUCTURED_VALUE_NODES {
        return Err(ParseError {
            message: format!(
                "{label} exceeds max node count {}",
                MAX_STRUCTURED_VALUE_NODES
            ),
        });
    }

    match value {
        Value::Array(items) => {
            for item in items {
                walk_value(item, depth + 1, nodes, label)?;
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                walk_value(item, depth + 1, nodes, label)?;
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_structured_document() {
        let input = "x".repeat(MAX_STRUCTURED_DOCUMENT_BYTES + 1);
        let error = ensure_document_byte_limit(&input, "JSON document").unwrap_err();
        assert!(error.message.contains("JSON document exceeds"));
    }

    #[test]
    fn rejects_structured_values_that_are_too_deep() {
        let mut value = Value::Null;
        for _ in 0..MAX_STRUCTURED_VALUE_DEPTH {
            value = Value::Array(vec![value]);
        }

        let error = ensure_value_shape_limits(&value, "JSON document").unwrap_err();
        assert!(error.message.contains("JSON document exceeds max depth"));
    }

    #[test]
    fn rejects_structured_values_with_too_many_nodes() {
        let value = Value::Array(
            (0..=MAX_STRUCTURED_VALUE_NODES)
                .map(|_| Value::Null)
                .collect(),
        );

        let error = ensure_value_shape_limits(&value, "JSON document").unwrap_err();
        assert!(
            error
                .message
                .contains("JSON document exceeds max node count")
        );
    }
}
