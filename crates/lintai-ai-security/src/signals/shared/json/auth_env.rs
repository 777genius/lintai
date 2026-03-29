use lintai_api::Span;
use serde_json::Value;

use super::super::common::{
    contains_ascii_case_insensitive, ends_with_ascii_case_insensitive, find_ascii_case_insensitive,
};
use super::server_headers::is_remote_variable_name;
use crate::helpers::contains_dynamic_reference;

pub(crate) const JSON_SECRET_ENV_KEYS: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "AUTHORIZATION",
];

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

pub(crate) fn is_env_container_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("env") || key.eq_ignore_ascii_case("environment")
}

pub(crate) fn is_header_container_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("headers") || key.eq_ignore_ascii_case("header")
}

pub(crate) fn is_trust_verification_disabled_key_value(key: &str, value: &Value) -> bool {
    (matches!(key, "strictSSL" | "verifyTLS" | "rejectUnauthorized")
        && value.as_bool() == Some(false))
        || (key == "insecureSkipVerify" && value.as_bool() == Some(true))
}

pub(crate) fn is_descriptive_json_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("description")
        || key.eq_ignore_ascii_case("instructions")
        || key.eq_ignore_ascii_case("instruction")
        || key.eq_ignore_ascii_case("prompt")
        || key.eq_ignore_ascii_case("message")
        || key.eq_ignore_ascii_case("summary")
}

pub(crate) fn is_secretish_json_key(key: &str) -> bool {
    is_sensitive_env_var_name(key)
        || key.eq_ignore_ascii_case("authorization")
        || key.eq_ignore_ascii_case("apiKey")
        || key.eq_ignore_ascii_case("api_key")
        || key.eq_ignore_ascii_case("accessToken")
        || key.eq_ignore_ascii_case("access_token")
        || key.eq_ignore_ascii_case("clientSecret")
        || key.eq_ignore_ascii_case("client_secret")
        || key.eq_ignore_ascii_case("token")
        || key.eq_ignore_ascii_case("secret")
        || key.eq_ignore_ascii_case("password")
        || key.eq_ignore_ascii_case("passwd")
}

pub(crate) fn is_sensitive_header_name(key: &str) -> bool {
    key.eq_ignore_ascii_case("authorization")
        || key.eq_ignore_ascii_case("x-api-key")
        || key.eq_ignore_ascii_case("api-key")
        || key.eq_ignore_ascii_case("x-auth-token")
        || key.eq_ignore_ascii_case("x-access-token")
        || key.eq_ignore_ascii_case("cookie")
}

pub(crate) fn is_server_auth_header_name(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "authentication"
            | "x-api-key"
            | "api-key"
            | "x-auth-token"
            | "x-access-token"
    )
}

pub(crate) fn is_static_authorization_literal(key: &str, value: &str) -> bool {
    key.eq_ignore_ascii_case("authorization")
        && find_literal_value_after_prefixes_case_insensitive(value, &["Bearer ", "Basic "])
            .is_some()
}

pub(crate) fn is_literal_secret_value(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || contains_dynamic_reference(trimmed) {
        return false;
    }

    let lowered = trimmed.to_ascii_lowercase();
    !lowered.contains("your_api_key")
        && !lowered.contains("example-token")
        && !lowered.contains("changeme")
        && !lowered.contains("replace-me")
        && !lowered.contains("placeholder")
        && !lowered.contains("<redacted>")
        && !lowered.contains("your_token_here")
        && !lowered.contains("your-secret")
}

pub(crate) fn is_broad_dotenv_env_file(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || contains_dynamic_reference(trimmed)
        || contains_template_placeholder(trimmed)
    {
        return false;
    }

    let normalized = trimmed.replace('\\', "/");
    let basename = normalized.rsplit('/').next().unwrap_or(normalized.as_str());
    let lowered = basename.to_ascii_lowercase();
    lowered == ".env" || lowered.starts_with(".env.")
}

pub(crate) fn contains_template_placeholder(value: &str) -> bool {
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
        if is_remote_variable_name(&value[name_start..name_end]) {
            return true;
        }
        index = name_end + 1;
    }
    false
}

pub(crate) fn find_sensitive_env_reference_relative_span(text: &str) -> Option<Span> {
    let bytes = text.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] != b'$' {
            index += 1;
            continue;
        }

        if index + 1 < bytes.len() && bytes[index + 1] == b'{' {
            let name_start = index + 2;
            let Some(close_rel) = text[name_start..].find('}') else {
                index += 1;
                continue;
            };
            let name_end = name_start + close_rel;
            let var_name = &text[name_start..name_end];
            if is_sensitive_env_var_name(var_name) {
                return Some(Span::new(index, name_end + 1));
            }
            index = name_end + 1;
            continue;
        }

        let name_start = index + 1;
        let name_len = text[name_start..]
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .map(char::len_utf8)
            .sum::<usize>();
        if name_len == 0 {
            index += 1;
            continue;
        }
        let name_end = name_start + name_len;
        let var_name = &text[name_start..name_end];
        if is_sensitive_env_var_name(var_name) {
            return Some(Span::new(index, name_end));
        }
        index = name_end;
    }

    None
}

pub(crate) fn is_sensitive_env_var_name(var_name: &str) -> bool {
    contains_ascii_case_insensitive(var_name, "secret")
        || contains_ascii_case_insensitive(var_name, "token")
        || contains_ascii_case_insensitive(var_name, "password")
        || contains_ascii_case_insensitive(var_name, "passwd")
        || contains_ascii_case_insensitive(var_name, "auth")
        || contains_ascii_case_insensitive(var_name, "credential")
        || contains_ascii_case_insensitive(var_name, "session")
        || contains_ascii_case_insensitive(var_name, "cookie")
        || contains_ascii_case_insensitive(var_name, "bearer")
        || contains_ascii_case_insensitive(var_name, "api_key")
        || ends_with_ascii_case_insensitive(var_name, "_key")
        || var_name.eq_ignore_ascii_case("key")
}
