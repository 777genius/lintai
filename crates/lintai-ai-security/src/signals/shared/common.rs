use lintai_api::Span;
use serde_json::Value;

use super::hook::shell_tokens;
use crate::helpers::contains_dynamic_reference;
use crate::json_locator::{JsonLocationMap, JsonPathSegment};
pub(crate) const HTML_COMMENT_DIRECTIVE_MARKERS: &[&str] = &[
    "ignore previous",
    "ignore all previous",
    "system prompt",
    "you are now",
    "send secrets",
    "exfiltrate",
];

pub(crate) fn has_download_exec(lowered: &str) -> bool {
    let has_download = lowered.contains("curl ") || lowered.contains("wget ");
    let has_pipe_exec = lowered.contains("| sh") || lowered.contains("| bash");
    let has_chmod_exec = lowered.contains("chmod +x") && lowered.contains("./");
    has_download && (has_pipe_exec || has_chmod_exec)
}

pub(crate) fn has_inline_download_pipe_exec(lowered: &str) -> bool {
    let has_download = lowered.contains("curl ") || lowered.contains("wget ");
    let has_pipe_exec =
        lowered.contains("| sh") || lowered.contains("| bash") || lowered.contains("| zsh");
    has_download && has_pipe_exec
}

pub(crate) fn is_mutable_mcp_launcher(command: &str, args: Option<&Vec<Value>>) -> bool {
    if command.eq_ignore_ascii_case("npx") || command.eq_ignore_ascii_case("uvx") {
        return true;
    }

    let first_arg = args
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .unwrap_or_default();

    ((command.eq_ignore_ascii_case("pnpm") || command.eq_ignore_ascii_case("yarn"))
        && first_arg.eq_ignore_ascii_case("dlx"))
        || (command.eq_ignore_ascii_case("pipx") && first_arg.eq_ignore_ascii_case("run"))
}

pub(crate) fn find_mutable_launcher_relative_span(command: &str) -> Option<Span> {
    let tokens = shell_tokens(command);
    for index in 0..tokens.len() {
        let text = tokens[index].text;
        if text.eq_ignore_ascii_case("npx") || text.eq_ignore_ascii_case("uvx") {
            return Some(Span::new(tokens[index].start, tokens[index].end));
        }
        if (text.eq_ignore_ascii_case("pnpm") || text.eq_ignore_ascii_case("yarn"))
            && tokens
                .get(index + 1)
                .is_some_and(|next| next.text.eq_ignore_ascii_case("dlx"))
        {
            return Some(Span::new(tokens[index].start, tokens[index].end));
        }
        if text.eq_ignore_ascii_case("pipx")
            && tokens
                .get(index + 1)
                .is_some_and(|next| next.text.eq_ignore_ascii_case("run"))
        {
            return Some(Span::new(tokens[index].start, tokens[index].end));
        }
    }
    None
}

pub(crate) fn looks_like_network_capable_command(lowered: &str) -> bool {
    lowered.contains("curl")
        || lowered.contains("wget")
        || lowered.contains("http://")
        || lowered.contains("https://")
}

pub(crate) fn find_command_tls_bypass_relative_span(text: &str) -> Option<Span> {
    if let Some(start) = text.find("NODE_TLS_REJECT_UNAUTHORIZED=0") {
        return Some(Span::new(
            start,
            start + "NODE_TLS_REJECT_UNAUTHORIZED=0".len(),
        ));
    }

    if let Some(start) = text.find("--insecure") {
        return Some(Span::new(start, start + "--insecure".len()));
    }

    find_standalone_short_flag(text, "-k").map(|start| Span::new(start, start + 2))
}

pub(crate) fn extract_url_host(text: &str) -> Option<&str> {
    let scheme_len = if starts_with_ascii_case_insensitive(text, "https://") {
        "https://".len()
    } else if starts_with_ascii_case_insensitive(text, "http://") {
        "http://".len()
    } else {
        return None;
    };

    let authority_end = text[scheme_len..]
        .char_indices()
        .find_map(|(index, ch)| match ch {
            '/' | '?' | '#' | '"' | '\'' | ' ' | '\t' | '\r' | '\n' => Some(scheme_len + index),
            _ => None,
        })
        .unwrap_or(text.len());
    let authority = &text[scheme_len..authority_end];
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(stripped) = host_port.strip_prefix('[') {
        let end = stripped.find(']')?;
        return Some(&stripped[..end]);
    }
    Some(host_port.split(':').next().unwrap_or(host_port))
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host.eq_ignore_ascii_case("[::1]")
}

pub(crate) fn find_standalone_short_flag(text: &str, flag: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let flag_bytes = flag.as_bytes();
    if flag_bytes.is_empty() || bytes.len() < flag_bytes.len() {
        return None;
    }

    for index in 0..=bytes.len() - flag_bytes.len() {
        if &bytes[index..index + flag_bytes.len()] != flag_bytes {
            continue;
        }
        let before_ok = index == 0 || bytes[index - 1].is_ascii_whitespace();
        let after_index = index + flag_bytes.len();
        let after_ok = after_index == bytes.len() || bytes[after_index].is_ascii_whitespace();
        if before_ok && after_ok {
            return Some(index);
        }
    }

    None
}

pub(crate) fn resolve_key_span(
    path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Span {
    locator
        .and_then(|locator| locator.key_span(path).cloned())
        .unwrap_or_else(|| Span::new(0, fallback_len))
}

pub(crate) fn resolve_child_key_span(
    path: &[JsonPathSegment],
    parent_key: &str,
    child_key: &str,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Span {
    let mut matched_path = path.to_vec();
    matched_path.push(JsonPathSegment::Key(parent_key.to_owned()));
    matched_path.push(JsonPathSegment::Key(child_key.to_owned()));
    resolve_key_span(&matched_path, locator, fallback_len)
}

pub(crate) fn resolve_value_span(
    path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Span {
    locator
        .and_then(|locator| locator.value_span(path).cloned())
        .unwrap_or_else(|| Span::new(0, fallback_len))
}

pub(crate) fn resolve_child_value_span(
    path: &[JsonPathSegment],
    key: &str,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Span {
    let mut matched_path = path.to_vec();
    matched_path.push(JsonPathSegment::Key(key.to_owned()));
    resolve_value_span(&matched_path, locator, fallback_len)
}

pub(crate) fn resolve_value_or_key_span(
    path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Span {
    locator
        .and_then(|locator| {
            locator
                .value_span(path)
                .cloned()
                .or_else(|| locator.key_span(path).cloned())
        })
        .unwrap_or_else(|| Span::new(0, fallback_len))
}

pub(crate) fn resolve_child_value_or_key_span(
    path: &[JsonPathSegment],
    key: &str,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Span {
    let mut matched_path = path.to_vec();
    matched_path.push(JsonPathSegment::Key(key.to_owned()));
    resolve_value_or_key_span(&matched_path, locator, fallback_len)
}

pub(crate) fn resolve_relative_value_span(
    path: &[JsonPathSegment],
    relative: Span,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Span {
    locator
        .and_then(|locator| {
            locator.value_span(path).map(|value_span| {
                Span::new(
                    value_span.start_byte + relative.start_byte,
                    value_span.start_byte + relative.end_byte,
                )
            })
        })
        .unwrap_or_else(|| Span::new(0, fallback_len))
}

pub(crate) fn resolve_child_relative_value_span(
    path: &[JsonPathSegment],
    parent_key: &str,
    child_key: &str,
    relative: Span,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Span {
    let mut matched_path = path.to_vec();
    matched_path.push(JsonPathSegment::Key(parent_key.to_owned()));
    if parent_key != child_key {
        matched_path.push(JsonPathSegment::Key(child_key.to_owned()));
    }
    resolve_relative_value_span(&matched_path, relative, locator, fallback_len)
}

pub(crate) fn with_child_key(path: &[JsonPathSegment], key: &str) -> Vec<JsonPathSegment> {
    let mut next = path.to_vec();
    next.push(JsonPathSegment::Key(key.to_owned()));
    next
}

pub(crate) fn with_child_index(path: &[JsonPathSegment], index: usize) -> Vec<JsonPathSegment> {
    let mut next = path.to_vec();
    next.push(JsonPathSegment::Index(index));
    next
}

pub(crate) fn path_contains_key(path: &[JsonPathSegment], wanted: &str) -> bool {
    path.iter().any(|segment| {
        matches!(
            segment,
            JsonPathSegment::Key(key) if key.eq_ignore_ascii_case(wanted)
        )
    })
}

pub(crate) fn find_literal_value_after_prefixes_case_insensitive(
    text: &str,
    prefixes: &[&str],
) -> Option<Span> {
    for prefix in prefixes {
        let mut search_start = 0usize;
        while let Some(relative) = find_ascii_case_insensitive(&text[search_start..], prefix) {
            let value_start = search_start + relative + prefix.len();
            let value_end = text[value_start..]
                .char_indices()
                .find_map(|(index, ch)| match ch {
                    '"' | '\'' | ' ' | '\t' | '\r' | '\n' => Some(value_start + index),
                    _ => None,
                })
                .unwrap_or(text.len());
            if value_end > value_start {
                let value = &text[value_start..value_end];
                if !contains_dynamic_reference(value) {
                    return Some(Span::new(value_start, value_end));
                }
            }
            search_start = value_start;
        }
    }

    None
}

pub(crate) fn starts_with_ascii_case_insensitive(text: &str, prefix: &str) -> bool {
    text.as_bytes()
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix.as_bytes()))
}

pub(crate) fn ends_with_ascii_case_insensitive(text: &str, suffix: &str) -> bool {
    text.as_bytes()
        .get(text.len().saturating_sub(suffix.len())..)
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(suffix.as_bytes()))
}

pub(crate) fn contains_ascii_case_insensitive(text: &str, needle: &str) -> bool {
    find_ascii_case_insensitive(text, needle).is_some()
}

pub(crate) fn find_ascii_case_insensitive(text: &str, needle: &str) -> Option<usize> {
    let needle_bytes = needle.as_bytes();
    if needle_bytes.is_empty() {
        return Some(0);
    }

    text.as_bytes()
        .windows(needle_bytes.len())
        .position(|window| window.eq_ignore_ascii_case(needle_bytes))
}
