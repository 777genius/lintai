use lintai_api::{ArtifactKind, Span};
use serde_json::{Map, Value};

use crate::json_locator::{JsonLocationMap, JsonPathSegment};
use crate::signals::JsonSignals;

use super::super::auth_env::*;
use super::super::spans::*;
use super::super::tool_descriptor::{
    is_broad_dotenv_env_file, is_plugin_manifest_path_key, is_unsafe_plugin_manifest_path,
};

pub(super) struct JsonObjectCommandShape<'a> {
    pub(super) shell_command_key: Option<&'a str>,
    pub(super) shell_has_dash_c: bool,
    pub(super) command: Option<&'a str>,
    pub(super) args: Option<&'a Vec<Value>>,
}

pub(super) fn analyze_json_object<'a>(
    map: &'a Map<String, Value>,
    path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    artifact_kind: ArtifactKind,
    signals: &mut JsonSignals,
) -> JsonObjectCommandShape<'a> {
    let mut shell_command_key = None;
    let mut shell_has_dash_c = false;
    let command = map.get("command").and_then(Value::as_str);
    let args = map.get("args").and_then(Value::as_array);

    for (key, nested) in map {
        if signals.shell_wrapper_span.is_none() {
            if key == "command" {
                if nested
                    .as_str()
                    .is_some_and(|command| command == "sh" || command == "bash")
                {
                    shell_command_key = Some(key.as_str());
                }
            } else if key == "args" {
                shell_has_dash_c = nested
                    .as_array()
                    .is_some_and(|items| items.iter().any(|item| item.as_str() == Some("-c")));
            }
        }

        if is_env_container_key(key)
            && let Some(env_map) = nested.as_object()
        {
            for (env_key, env_value) in env_map {
                if signals.literal_secret_span.is_none()
                    && is_sensitive_env_var_name(env_key)
                    && let Some(text) = env_value.as_str()
                    && is_literal_secret_value(text)
                {
                    signals.literal_secret_span = Some(resolve_child_relative_value_span(
                        path,
                        key,
                        env_key,
                        Span::new(0, text.len()),
                        locator,
                        fallback_len,
                    ));
                }

                if signals.credential_env_passthrough_span.is_none()
                    && JSON_SECRET_ENV_KEYS
                        .iter()
                        .any(|secret| env_key.eq_ignore_ascii_case(secret))
                {
                    signals.credential_env_passthrough_span = Some(resolve_child_key_span(
                        path,
                        key,
                        env_key,
                        locator,
                        fallback_len,
                    ));
                }

                if signals.sensitive_env_reference_span.is_none()
                    && !is_sensitive_env_var_name(env_key)
                    && let Some(text) = env_value.as_str()
                    && let Some(relative) = find_sensitive_env_reference_relative_span(text)
                {
                    signals.sensitive_env_reference_span = Some(resolve_child_relative_value_span(
                        path,
                        key,
                        env_key,
                        relative,
                        locator,
                        fallback_len,
                    ));
                }

                if signals.credential_env_passthrough_span.is_some()
                    && signals.sensitive_env_reference_span.is_some()
                {
                    break;
                }
            }
        }

        if signals.literal_secret_span.is_none()
            && is_header_container_key(key)
            && let Some(header_map) = nested.as_object()
        {
            for (header_key, header_value) in header_map {
                if is_sensitive_header_name(header_key)
                    && let Some(text) = header_value.as_str()
                    && is_literal_secret_value(text)
                    && !is_static_authorization_literal(header_key, text)
                {
                    signals.literal_secret_span = Some(resolve_child_relative_value_span(
                        path,
                        key,
                        header_key,
                        Span::new(0, text.len()),
                        locator,
                        fallback_len,
                    ));
                    break;
                }
            }
        }

        if signals.trust_verification_disabled_span.is_none()
            && is_trust_verification_disabled_key_value(key, nested)
        {
            signals.trust_verification_disabled_span = Some(resolve_child_value_or_key_span(
                path,
                key,
                locator,
                fallback_len,
            ));
        }

        if signals.static_auth_exposure_span.is_none()
            && key.eq_ignore_ascii_case("authorization")
            && let Some(text) = nested.as_str()
            && let Some(relative) =
                find_literal_value_after_prefixes_case_insensitive(text, &["Bearer ", "Basic "])
        {
            signals.static_auth_exposure_span = Some(resolve_child_relative_value_span(
                path,
                key,
                key,
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.literal_secret_span.is_none()
            && is_secretish_json_key(key)
            && let Some(text) = nested.as_str()
            && is_literal_secret_value(text)
            && !is_static_authorization_literal(key, text)
        {
            signals.literal_secret_span =
                Some(resolve_child_value_span(path, key, locator, fallback_len));
        }

        if signals.unsafe_plugin_path_span.is_none()
            && artifact_kind == ArtifactKind::CursorPluginManifest
            && is_plugin_manifest_path_key(key)
            && let Some(text) = nested.as_str()
            && is_unsafe_plugin_manifest_path(text)
        {
            signals.unsafe_plugin_path_span =
                Some(resolve_child_value_span(path, key, locator, fallback_len));
        }

        if signals.broad_env_file_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && signals.expanded_mcp_client_variant
            && key == "envFile"
            && let Some(text) = nested.as_str()
            && is_broad_dotenv_env_file(text)
        {
            signals.broad_env_file_span =
                Some(resolve_child_value_span(path, key, locator, fallback_len));
        }

        if signals.autoapprove_wildcard_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "*")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_wildcard_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_tools_true_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApproveTools"
            && nested.as_bool() == Some(true)
        {
            signals.autoapprove_tools_true_span =
                Some(resolve_child_value_span(path, key, locator, fallback_len));
        }

        if signals.trust_tools_true_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "trustTools"
            && nested.as_bool() == Some(true)
        {
            signals.trust_tools_true_span =
                Some(resolve_child_value_span(path, key, locator, fallback_len));
        }

        if signals.sandbox_disabled_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && ((key == "sandbox" && nested.as_bool() == Some(false))
                || (key == "disableSandbox" && nested.as_bool() == Some(true)))
        {
            signals.sandbox_disabled_span =
                Some(resolve_child_value_span(path, key, locator, fallback_len));
        }

        if signals.capabilities_wildcard_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "capabilities"
        {
            if let Some(index) = find_string_array_item_index(nested, "*") {
                let key_path = with_child_key(path, key);
                let item_path = with_child_index(&key_path, index);
                signals.capabilities_wildcard_span =
                    Some(resolve_value_span(&item_path, locator, fallback_len));
            } else if nested.as_str() == Some("*") {
                signals.capabilities_wildcard_span =
                    Some(resolve_child_value_span(path, key, locator, fallback_len));
            }
        }
    }

    JsonObjectCommandShape {
        shell_command_key,
        shell_has_dash_c,
        command,
        args,
    }
}

fn find_string_array_item_index(value: &Value, wanted: &str) -> Option<usize> {
    value
        .as_array()
        .and_then(|items| items.iter().position(|item| item.as_str() == Some(wanted)))
}
