use lintai_api::Span;
use serde_json::Value;

use super::super::common::{find_ascii_case_insensitive, starts_with_ascii_case_insensitive};
use super::auth_env::{
    contains_template_placeholder, find_literal_value_after_prefixes_case_insensitive,
    is_literal_secret_value,
};

pub(crate) const JSON_SUSPICIOUS_DOMAIN_MARKERS: &[&str] = &[
    "attacker", "evil", "malware", "steal", "exfil", "phish", "payload",
];

pub(crate) fn find_non_loopback_http_relative_span(text: &str) -> Option<Span> {
    if !starts_with_ascii_case_insensitive(text, "http://") {
        return None;
    }

    let host = extract_url_host(text)?;
    if is_loopback_host(host) {
        return None;
    }

    Some(Span::new(0, "http://".len()))
}

pub(crate) fn find_unresolved_remote_variable_relative_span(
    url: &str,
    remote_object: &serde_json::Map<String, Value>,
) -> Option<Span> {
    let variables = remote_object.get("variables").and_then(Value::as_object);
    let bytes = url.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'{' {
            index += 1;
            continue;
        }
        let name_start = index + 1;
        let Some(close_rel) = url[name_start..].find('}') else {
            index += 1;
            continue;
        };
        let name_end = name_start + close_rel;
        let name = &url[name_start..name_end];
        if is_remote_variable_name(name)
            && !variables.is_some_and(|variables| variables.contains_key(name))
        {
            return Some(Span::new(index, name_end + 1));
        }
        index = name_end + 1;
    }
    None
}

pub(crate) fn is_remote_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
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

pub(crate) fn find_literal_auth_header_relative_span(
    header_name: &str,
    header_object: &serde_json::Map<String, Value>,
) -> Option<Span> {
    let value = header_object.get("value").and_then(Value::as_str)?;
    if contains_template_placeholder(value) {
        return None;
    }

    if matches!(
        header_name.to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "authentication"
    ) {
        return find_literal_value_after_prefixes_case_insensitive(value, &["Bearer ", "Basic "]);
    }

    is_literal_secret_value(value).then_some(Span::new(0, value.len()))
}

pub(crate) fn find_unresolved_header_variable_relative_span(
    header_object: &serde_json::Map<String, Value>,
) -> Option<Span> {
    let value = header_object.get("value").and_then(Value::as_str)?;
    let variables = header_object.get("variables").and_then(Value::as_object);
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'{' {
            index += 1;
            continue;
        }
        let name_start = index + 1;
        let Some(close_rel) = value[name_start..].find('}') else {
            index += 1;
            continue;
        };
        let name_end = name_start + close_rel;
        let name = &value[name_start..name_end];
        if is_remote_variable_name(name)
            && !variables.is_some_and(|variables| variables.contains_key(name))
        {
            return Some(Span::new(index, name_end + 1));
        }
        index = name_end + 1;
    }
    None
}

pub(crate) fn auth_header_policy_mismatch(header_object: &serde_json::Map<String, Value>) -> bool {
    let carries_auth_material = header_object
        .get("value")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
        || header_object
            .get("variables")
            .and_then(Value::as_object)
            .is_some_and(|variables| !variables.is_empty());
    if !carries_auth_material {
        return false;
    }

    match header_object
        .get("isSecret")
        .or_else(|| header_object.get("is_secret"))
    {
        Some(Value::Bool(true)) => false,
        Some(Value::Bool(false)) | None => true,
        _ => true,
    }
}

pub(crate) fn is_endpointish_json_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("url")
        || key.eq_ignore_ascii_case("uri")
        || key.eq_ignore_ascii_case("endpoint")
        || key.eq_ignore_ascii_case("server")
        || key.eq_ignore_ascii_case("baseurl")
        || key.eq_ignore_ascii_case("base_url")
}

pub(crate) fn find_suspicious_remote_endpoint_relative_span(text: &str) -> Option<Span> {
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
    let host_start = authority
        .rfind('@')
        .map_or(scheme_len, |index| scheme_len + index + 1);
    let host = &text[host_start..authority_end];

    JSON_SUSPICIOUS_DOMAIN_MARKERS.iter().find_map(|marker| {
        find_ascii_case_insensitive(host, marker).map(|relative| {
            let start = host_start + relative;
            Span::new(start, start + marker.len())
        })
    })
}

pub(crate) fn find_dangerous_endpoint_host_relative_span(text: &str) -> Option<Span> {
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
    let host_start = authority
        .rfind('@')
        .map_or(scheme_len, |index| scheme_len + index + 1);
    let host = &text[host_start..authority_end];
    let host_without_port = host.split(':').next().unwrap_or(host);

    if host_without_port.eq_ignore_ascii_case("metadata.google.internal")
        || host_without_port == "169.254.169.254"
    {
        return Some(Span::new(host_start, host_start + host_without_port.len()));
    }

    let Ok(address) = host_without_port.parse::<std::net::Ipv4Addr>() else {
        return None;
    };
    if address.is_private() || address.is_link_local() {
        return Some(Span::new(host_start, host_start + host_without_port.len()));
    }

    None
}
