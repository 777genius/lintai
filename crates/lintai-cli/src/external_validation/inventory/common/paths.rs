use super::super::super::*;

pub(crate) fn is_generic_validation_excluded_path(normalized_path: &str) -> bool {
    normalized_path
        .split('/')
        .flat_map(segment_tokens)
        .any(is_reserved_validation_token)
}

pub(crate) fn is_tool_json_excluded_path(normalized_path: &str) -> bool {
    is_generic_validation_excluded_path(normalized_path)
}

pub(super) fn is_fixture_like_path(normalized_path: &str) -> bool {
    normalized_path
        .split('/')
        .any(|segment| FIXTURE_PATH_SEGMENTS.contains(&segment.to_ascii_lowercase().as_str()))
}

fn is_reserved_validation_token(token: &str) -> bool {
    FIXTURE_PATH_SEGMENTS
        .iter()
        .any(|reserved| token.eq_ignore_ascii_case(reserved))
        || DOCISH_PATH_SEGMENTS
            .iter()
            .any(|reserved| token.eq_ignore_ascii_case(reserved))
}

fn segment_tokens(segment: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let bytes = segment.as_bytes();
    let mut start = 0usize;
    for index in 0..bytes.len() {
        let byte = bytes[index];
        let is_delimiter = matches!(byte, b'_' | b'-' | b'.');
        let is_camel_boundary =
            index > start && bytes[index - 1].is_ascii_lowercase() && byte.is_ascii_uppercase();
        if is_delimiter || is_camel_boundary {
            if start < index {
                tokens.push(&segment[start..index]);
            }
            start = if is_delimiter { index + 1 } else { index };
        }
    }
    if start < segment.len() {
        tokens.push(&segment[start..]);
    }
    tokens
        .into_iter()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_tokens_splits_by_delimiters_and_camel_case() {
        let tokens = segment_tokens("fooBar-baz_qux.qux");
        assert_eq!(tokens, vec!["foo", "Bar", "baz", "qux", "qux"]);
    }

    #[test]
    fn detects_generic_validation_excluded_paths() {
        assert!(is_generic_validation_excluded_path(
            "src/fixtures/tool.json"
        ));
        assert!(is_generic_validation_excluded_path(
            "docs/samples/example.md"
        ));
        assert!(!is_generic_validation_excluded_path("src/main.rs"));
    }

    #[test]
    fn tool_json_excluded_matches_generic_filter() {
        assert_eq!(
            is_tool_json_excluded_path("examples/fixture-data/config.json"),
            is_generic_validation_excluded_path("examples/fixture-data/config.json")
        );
    }

    #[test]
    fn fixture_like_paths_detect_nested_path_tokens() {
        assert!(is_fixture_like_path("src/fixture/config.json"));
        assert!(is_fixture_like_path("examples/testdata/mcptest.json"));
        assert!(!is_fixture_like_path("src/main/real.json"));
    }
}
