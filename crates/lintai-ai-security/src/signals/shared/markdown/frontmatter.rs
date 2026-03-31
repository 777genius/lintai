use lintai_api::Span;
use serde_json::Value;

const ALLOWED_TOOLS_KEYS: &[&str] = &["allowed-tools", "allowed_tools"];
const WILDCARD_TOOL_KEYS: &[&str] = &["allowed-tools", "allowed_tools", "tools"];

fn is_unscoped_bash_token(token: &str) -> bool {
    token.trim().eq_ignore_ascii_case("bash")
}

fn is_unscoped_websearch_token(token: &str) -> bool {
    token.trim().eq_ignore_ascii_case("websearch")
}

fn is_unscoped_webfetch_token(token: &str) -> bool {
    token.trim().eq_ignore_ascii_case("webfetch")
}

fn is_wildcard_tool_token(token: &str) -> bool {
    token.trim() == "*"
}

fn tool_has_unsafe_path_scope(token: &str, tool_name: &str) -> bool {
    let trimmed = token.trim();
    let Some(inner) = trimmed
        .strip_prefix(tool_name)
        .and_then(|remainder| remainder.strip_prefix('('))
        .and_then(|remainder| remainder.strip_suffix(')'))
    else {
        return false;
    };

    is_unsafe_tool_scope_path(inner)
}

fn is_unsafe_tool_scope_path(value: &str) -> bool {
    let normalized = value.trim();
    normalized.starts_with('/')
        || normalized.starts_with("~/")
        || normalized.starts_with("~\\")
        || normalized.contains("../")
        || normalized.contains("..\\")
        || normalized
            .as_bytes()
            .get(1)
            .is_some_and(|byte| *byte == b':')
}

fn normalize_tool_token(token: &str) -> &str {
    token
        .trim()
        .trim_start_matches(['[', '-'])
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '[' | ']'))
        .trim()
}

fn is_tool_separator(ch: char) -> bool {
    ch == ',' || ch.is_whitespace() || matches!(ch, '[' | ']')
}

fn for_each_allowed_tool_token(
    value: &str,
    mut callback: impl FnMut(&str, usize, usize) -> bool,
) -> bool {
    let mut token_start = None;
    let mut depth = 0usize;

    for (index, ch) in value
        .char_indices()
        .chain(std::iter::once((value.len(), ',')))
    {
        if index == value.len() {
            if let Some(start) = token_start.take() {
                let token = normalize_tool_token(&value[start..index]);
                if !token.is_empty() {
                    let leading_trim = value[start..index].find(token).unwrap_or(0);
                    let abs_start = start + leading_trim;
                    let abs_end = abs_start + token.len();
                    if callback(token, abs_start, abs_end) {
                        return true;
                    }
                }
            }
            break;
        }

        match ch {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ => {}
        }

        if depth == 0 && is_tool_separator(ch) {
            if let Some(start) = token_start.take() {
                let token = normalize_tool_token(&value[start..index]);
                if !token.is_empty() {
                    let leading_trim = value[start..index].find(token).unwrap_or(0);
                    let abs_start = start + leading_trim;
                    let abs_end = abs_start + token.len();
                    if callback(token, abs_start, abs_end) {
                        return true;
                    }
                }
            }
            continue;
        }

        if token_start.is_none() {
            token_start = Some(index);
        }
    }

    false
}

fn frontmatter_has_matching_tool(value: &Value, matcher: impl Fn(&str) -> bool + Copy) -> bool {
    match value {
        Value::String(raw) => for_each_allowed_tool_token(raw, |token, _, _| matcher(token)),
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(normalize_tool_token)
            .any(matcher),
        _ => false,
    }
}

pub(crate) fn frontmatter_has_unscoped_bash_allowed_tools(value: &Value) -> bool {
    frontmatter_has_matching_tool(value, is_unscoped_bash_token)
}

pub(crate) fn frontmatter_has_unscoped_websearch_allowed_tools(value: &Value) -> bool {
    frontmatter_has_matching_tool(value, is_unscoped_websearch_token)
}

pub(crate) fn frontmatter_has_unscoped_webfetch_allowed_tools(value: &Value) -> bool {
    frontmatter_has_matching_tool(value, is_unscoped_webfetch_token)
}

pub(crate) fn frontmatter_has_wildcard_tool_access(value: &Value) -> bool {
    frontmatter_has_matching_tool(value, is_wildcard_tool_token)
}

pub(crate) fn frontmatter_has_exact_allowed_tool(value: &Value, permission: &str) -> bool {
    frontmatter_has_matching_tool(value, |token| token == permission)
}

pub(crate) fn frontmatter_has_unsafe_path_allowed_tool(value: &Value, tool_name: &str) -> bool {
    frontmatter_has_matching_tool(value, |token| tool_has_unsafe_path_scope(token, tool_name))
}

pub(crate) fn frontmatter_has_key(value: &Value, key: &str) -> bool {
    value
        .as_object()
        .is_some_and(|mapping| mapping.contains_key(key))
}

pub(crate) fn cursor_rule_globs_requires_sequence(value: &Value) -> bool {
    match value {
        Value::Array(items) => items
            .iter()
            .any(|item| item.as_str().is_none_or(|text| text.trim().is_empty())),
        _ => true,
    }
}

pub(crate) fn copilot_apply_to_requires_string_or_sequence(value: &Value) -> bool {
    match value {
        Value::String(text) => text.trim().is_empty(),
        Value::Array(items) => {
            items.is_empty()
                || items
                    .iter()
                    .any(|item| item.as_str().is_none_or(|text| text.trim().is_empty()))
        }
        _ => true,
    }
}

fn match_tool_token_relative_span(
    text: &str,
    matcher: impl Fn(&str) -> bool + Copy,
) -> Option<Span> {
    let mut matched = None;
    let _ = for_each_allowed_tool_token(text, |token, start, end| {
        if matcher(token) {
            matched = Some(Span::new(start, end));
            true
        } else {
            false
        }
    });
    matched
}

fn matches_frontmatter_key(line: &str, keys: &[&str]) -> bool {
    let trimmed = line.trim_start();
    let lowered = trimmed.to_ascii_lowercase();
    keys.iter()
        .any(|key| lowered.starts_with(format!("{key}:").as_str()))
}

fn frontmatter_key_value_segment(line: &str) -> Option<(&str, usize)> {
    let trimmed = line.trim_start();
    let base_offset = line.len() - trimmed.len();
    let colon_offset = trimmed.find(':')?;
    let value_segment = &trimmed[colon_offset + 1..];
    let leading_trim = value_segment.len() - value_segment.trim_start().len();
    Some((
        value_segment.trim_start(),
        base_offset + colon_offset + 1 + leading_trim,
    ))
}

fn nested_frontmatter_item_segment(line: &str) -> (&str, usize) {
    let trimmed = line.trim_start();
    let base_offset = line.len() - trimmed.len();
    if let Some(remainder) = trimmed.strip_prefix('-') {
        let leading_trim = remainder.len() - remainder.trim_start().len();
        (remainder.trim_start(), base_offset + 1 + leading_trim)
    } else {
        (trimmed, base_offset)
    }
}

fn find_matching_tool_frontmatter_relative_span(
    text: &str,
    keys: &[&str],
    matcher: impl Fn(&str) -> bool + Copy,
) -> Option<Span> {
    let mut offset = 0usize;
    let mut lines = text.split_inclusive('\n').peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if matches_frontmatter_key(line, keys) {
            if let Some((segment, segment_offset)) = frontmatter_key_value_segment(line)
                && let Some(found) = match_tool_token_relative_span(segment, matcher)
            {
                return Some(Span::new(
                    offset + segment_offset + found.start_byte,
                    offset + segment_offset + found.end_byte,
                ));
            }

            let mut nested_offset = offset + line.len();
            while let Some(next_line) = lines.peek().copied() {
                let next_trimmed = next_line.trim_start();
                if next_trimmed.is_empty() {
                    nested_offset += next_line.len();
                    lines.next();
                    continue;
                }

                let next_indent = next_line.len() - next_trimmed.len();
                if next_indent <= indent {
                    break;
                }

                let (segment, segment_offset) = nested_frontmatter_item_segment(next_line);
                if let Some(found) = match_tool_token_relative_span(segment, matcher) {
                    return Some(Span::new(
                        nested_offset + segment_offset + found.start_byte,
                        nested_offset + segment_offset + found.end_byte,
                    ));
                }

                nested_offset += next_line.len();
                lines.next();
            }
        }
        offset += line.len();
    }

    None
}

pub(crate) fn find_unscoped_bash_allowed_tools_frontmatter_relative_span(
    text: &str,
) -> Option<Span> {
    find_matching_tool_frontmatter_relative_span(text, ALLOWED_TOOLS_KEYS, is_unscoped_bash_token)
}

pub(crate) fn find_unscoped_websearch_allowed_tools_frontmatter_relative_span(
    text: &str,
) -> Option<Span> {
    find_matching_tool_frontmatter_relative_span(
        text,
        ALLOWED_TOOLS_KEYS,
        is_unscoped_websearch_token,
    )
}

pub(crate) fn find_unscoped_webfetch_allowed_tools_frontmatter_relative_span(
    text: &str,
) -> Option<Span> {
    find_matching_tool_frontmatter_relative_span(
        text,
        ALLOWED_TOOLS_KEYS,
        is_unscoped_webfetch_token,
    )
}

pub(crate) fn find_wildcard_tool_frontmatter_relative_span(text: &str) -> Option<Span> {
    find_matching_tool_frontmatter_relative_span(text, WILDCARD_TOOL_KEYS, is_wildcard_tool_token)
}

pub(crate) fn find_exact_allowed_tool_frontmatter_relative_span(
    text: &str,
    permission: &str,
) -> Option<Span> {
    find_matching_tool_frontmatter_relative_span(text, ALLOWED_TOOLS_KEYS, |token| {
        token == permission
    })
}

pub(crate) fn find_unsafe_path_allowed_tool_frontmatter_relative_span(
    text: &str,
    tool_name: &str,
) -> Option<Span> {
    find_matching_tool_frontmatter_relative_span(text, ALLOWED_TOOLS_KEYS, |token| {
        tool_has_unsafe_path_scope(token, tool_name)
    })
}

pub(crate) fn find_frontmatter_key_relative_span(text: &str, key: &str) -> Option<Span> {
    let needle = format!("{key}:");
    let lowered_needle = needle.to_ascii_lowercase();
    let mut offset = 0usize;

    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed
            .to_ascii_lowercase()
            .starts_with(lowered_needle.as_str())
            && let Some(found) = line.find(key)
        {
            return Some(Span::new(offset + found, offset + found + key.len()));
        }
        offset += line.len();
    }

    None
}
