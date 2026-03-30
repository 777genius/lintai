use lintai_api::Span;
use serde_json::Value;

fn is_unscoped_bash_token(token: &str) -> bool {
    token.trim().eq_ignore_ascii_case("bash")
}

fn is_wildcard_tool_token(token: &str) -> bool {
    token.trim() == "*"
}

fn tokenize_allowed_tools_string(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|ch: char| ch == ',' || ch.is_whitespace())
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

pub(crate) fn frontmatter_has_unscoped_bash_allowed_tools(value: &Value) -> bool {
    match value {
        Value::String(raw) => tokenize_allowed_tools_string(raw).any(is_unscoped_bash_token),
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .any(is_unscoped_bash_token),
        _ => false,
    }
}

pub(crate) fn frontmatter_has_wildcard_tool_access(value: &Value) -> bool {
    match value {
        Value::String(raw) => tokenize_allowed_tools_string(raw).any(is_wildcard_tool_token),
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .any(is_wildcard_tool_token),
        _ => false,
    }
}

pub(crate) fn frontmatter_has_key(value: &Value, key: &str) -> bool {
    value
        .as_object()
        .is_some_and(|mapping| mapping.contains_key(key))
}

fn find_standalone_bash_relative_span(text: &str) -> Option<Span> {
    let lowered = text.to_ascii_lowercase();
    let needle = "bash";
    let mut start = 0usize;

    while let Some(found) = lowered[start..].find(needle) {
        let abs = start + found;
        let end = abs + needle.len();
        let prev_ok = abs == 0
            || !text[..abs]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        let next_ok = end >= text.len()
            || !text[end..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '(');
        if prev_ok && next_ok {
            return Some(Span::new(abs, end));
        }
        start = end;
    }

    None
}

fn is_wildcard_boundary(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '"' | '\'' | '[' | ']' | ',' | '-')
}

fn find_standalone_wildcard_relative_span(text: &str) -> Option<Span> {
    for (index, ch) in text.char_indices() {
        if ch != '*' {
            continue;
        }

        let prev_ok = text[..index]
            .chars()
            .next_back()
            .is_none_or(is_wildcard_boundary);
        let next_index = index + ch.len_utf8();
        let next_ok = text[next_index..]
            .chars()
            .next()
            .is_none_or(is_wildcard_boundary);

        if prev_ok && next_ok {
            return Some(Span::new(index, next_index));
        }
    }

    None
}

pub(crate) fn find_unscoped_bash_allowed_tools_frontmatter_relative_span(
    text: &str,
) -> Option<Span> {
    let mut offset = 0usize;
    let mut lines = text.split_inclusive('\n').peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        let lowered = trimmed.to_ascii_lowercase();
        let indent = line.len() - trimmed.len();
        if lowered.starts_with("allowed-tools:") || lowered.starts_with("allowed_tools:") {
            if let Some(found) = find_standalone_bash_relative_span(line) {
                return Some(Span::new(
                    offset + found.start_byte,
                    offset + found.end_byte,
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

                if let Some(found) = find_standalone_bash_relative_span(next_line) {
                    return Some(Span::new(
                        nested_offset + found.start_byte,
                        nested_offset + found.end_byte,
                    ));
                }

                nested_offset += next_line.len();
                lines.next();
            }
        }
        offset += line.len();
    }

    find_standalone_bash_relative_span(text)
}

pub(crate) fn find_wildcard_tool_frontmatter_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    let mut lines = text.split_inclusive('\n').peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        let lowered = trimmed.to_ascii_lowercase();
        let indent = line.len() - trimmed.len();
        if lowered.starts_with("allowed-tools:")
            || lowered.starts_with("allowed_tools:")
            || lowered.starts_with("tools:")
        {
            if let Some(found) = find_standalone_wildcard_relative_span(line) {
                return Some(Span::new(
                    offset + found.start_byte,
                    offset + found.end_byte,
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

                if let Some(found) = find_standalone_wildcard_relative_span(next_line) {
                    return Some(Span::new(
                        nested_offset + found.start_byte,
                        nested_offset + found.end_byte,
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
