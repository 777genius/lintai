use lintai_api::{ArtifactKind, Span};
use serde_json::Value;

use crate::helpers::{contains_dynamic_reference, find_url_userinfo_span};
use crate::json_locator::{JsonLocationMap, JsonPathSegment};

use super::super::{ClaudeSettingsSignals, JsonSignals, SignalWorkBudget, ToolJsonSignals};
use super::common::*;
use super::hook::{HookToken, McpCommandSignalSpan};
use super::markdown::analyze_docker_run_args;
pub(crate) const JSON_SECRET_ENV_KEYS: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "AUTHORIZATION",
];

pub(crate) const JSON_SUSPICIOUS_DOMAIN_MARKERS: &[&str] = &[
    "attacker", "evil", "malware", "steal", "exfil", "phish", "payload",
];

pub(crate) fn visit_json_value(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    artifact_kind: ArtifactKind,
    signals: &mut JsonSignals,
    metrics: &mut SignalWorkBudget,
) {
    metrics.json_values_visited += 1;
    if let Value::Object(map) = value {
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

            if is_env_container_key(key) {
                if let Some(env_map) = nested.as_object() {
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
                        {
                            if let Some(text) = env_value.as_str() {
                                if let Some(relative) =
                                    find_sensitive_env_reference_relative_span(text)
                                {
                                    signals.sensitive_env_reference_span =
                                        Some(resolve_child_relative_value_span(
                                            path,
                                            key,
                                            env_key,
                                            relative,
                                            locator,
                                            fallback_len,
                                        ));
                                }
                            }
                        }

                        if signals.credential_env_passthrough_span.is_some()
                            && signals.sensitive_env_reference_span.is_some()
                        {
                            break;
                        }
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
            {
                if let Some(text) = nested.as_str() {
                    if let Some(relative) = find_literal_value_after_prefixes_case_insensitive(
                        text,
                        &["Bearer ", "Basic "],
                    ) {
                        signals.static_auth_exposure_span =
                            Some(resolve_child_relative_value_span(
                                path,
                                key,
                                key,
                                relative,
                                locator,
                                fallback_len,
                            ));
                    }
                }
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
        }

        if artifact_kind == ArtifactKind::McpConfig {
            if signals.mutable_mcp_launcher_span.is_none()
                && let Some(command) = command
                && is_mutable_mcp_launcher(command, args)
            {
                signals.mutable_mcp_launcher_span = Some(resolve_child_value_span(
                    path,
                    "command",
                    locator,
                    fallback_len,
                ));
            }

            if (signals.inline_download_exec_command_span.is_none()
                || signals.network_tls_bypass_command_span.is_none()
                || signals.mutable_docker_image_span.is_none()
                || signals.mutable_docker_pull_span.is_none()
                || signals.sensitive_docker_mount_span.is_none()
                || signals.dangerous_docker_flag_span.is_none())
                && let Some(command_signals) =
                    find_mcp_command_signal_span(path, command, args, locator, fallback_len)
            {
                if signals.inline_download_exec_command_span.is_none() {
                    signals.inline_download_exec_command_span =
                        command_signals.inline_download_exec;
                }
                if signals.network_tls_bypass_command_span.is_none() {
                    signals.network_tls_bypass_command_span = command_signals.network_tls_bypass;
                }
                if signals.mutable_docker_image_span.is_none() {
                    signals.mutable_docker_image_span = command_signals.mutable_docker_image;
                }
                if signals.mutable_docker_pull_span.is_none() {
                    signals.mutable_docker_pull_span = command_signals.mutable_docker_pull;
                }
                if signals.sensitive_docker_mount_span.is_none() {
                    signals.sensitive_docker_mount_span = command_signals.sensitive_docker_mount;
                }
                if signals.dangerous_docker_flag_span.is_none() {
                    signals.dangerous_docker_flag_span = command_signals.dangerous_docker_flag;
                }
            }
        }

        if artifact_kind == ArtifactKind::CursorPluginHooks && is_plugin_hook_command_path(path) {
            if signals.mutable_plugin_hook_launcher_span.is_none()
                && let Some(command) = command
                && let Some(relative) = find_mutable_launcher_relative_span(command)
            {
                signals.mutable_plugin_hook_launcher_span =
                    Some(resolve_child_relative_value_span(
                        path,
                        "command",
                        "command",
                        relative,
                        locator,
                        fallback_len,
                    ));
            }

            if signals.inline_download_exec_plugin_hook_span.is_none()
                && let Some(command) = command
                && has_inline_download_pipe_exec(&command.to_ascii_lowercase())
            {
                signals.inline_download_exec_plugin_hook_span = Some(resolve_child_value_span(
                    path,
                    "command",
                    locator,
                    fallback_len,
                ));
            }

            if signals.network_tls_bypass_plugin_hook_span.is_none()
                && let Some(command) = command
                && looks_like_network_capable_command(&command.to_ascii_lowercase())
                && let Some(relative) = find_command_tls_bypass_relative_span(command)
            {
                signals.network_tls_bypass_plugin_hook_span =
                    Some(resolve_child_relative_value_span(
                        path,
                        "command",
                        "command",
                        relative,
                        locator,
                        fallback_len,
                    ));
            }
        }

        if signals.shell_wrapper_span.is_none()
            && shell_has_dash_c
            && let Some(command_key) = shell_command_key
        {
            signals.shell_wrapper_span = Some(resolve_child_value_span(
                path,
                command_key,
                locator,
                fallback_len,
            ));
        }
    }

    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                path.push(JsonPathSegment::Key(key.clone()));
                visit_json_value(
                    nested,
                    path,
                    locator,
                    fallback_len,
                    artifact_kind,
                    signals,
                    metrics,
                );
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                path.push(JsonPathSegment::Index(index));
                visit_json_value(
                    nested,
                    path,
                    locator,
                    fallback_len,
                    artifact_kind,
                    signals,
                    metrics,
                );
                path.pop();
            }
        }
        Value::String(text) => {
            if signals.plain_http_endpoint_span.is_none() && text.starts_with("http://") {
                signals.plain_http_endpoint_span =
                    Some(resolve_value_span(path, locator, fallback_len));
            }

            if signals.static_auth_exposure_span.is_none() {
                if let Some(relative) = find_url_userinfo_span(text) {
                    signals.static_auth_exposure_span = Some(resolve_relative_value_span(
                        path,
                        relative,
                        locator,
                        fallback_len,
                    ));
                }
            }

            let Some(JsonPathSegment::Key(key)) = path.last() else {
                return;
            };

            if signals.hidden_instruction_span.is_none() && is_descriptive_json_key(key) {
                if let Some(relative) = find_hidden_instruction_relative_span(text) {
                    signals.hidden_instruction_span = Some(resolve_relative_value_span(
                        path,
                        relative,
                        locator,
                        fallback_len,
                    ));
                }
            }

            if signals.suspicious_remote_endpoint_span.is_none() && is_endpointish_json_key(key) {
                if let Some(relative) = find_suspicious_remote_endpoint_relative_span(text) {
                    signals.suspicious_remote_endpoint_span = Some(resolve_relative_value_span(
                        path,
                        relative,
                        locator,
                        fallback_len,
                    ));
                }
            }

            if signals.dangerous_endpoint_host_span.is_none() && is_endpointish_json_key(key) {
                if let Some(relative) = find_dangerous_endpoint_host_relative_span(text) {
                    signals.dangerous_endpoint_host_span = Some(resolve_relative_value_span(
                        path,
                        relative,
                        locator,
                        fallback_len,
                    ));
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

pub(crate) fn visit_claude_settings_value(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    signals: &mut ClaudeSettingsSignals,
    metrics: &mut SignalWorkBudget,
) {
    metrics.json_values_visited += 1;

    if let Value::Object(map) = value
        && path_contains_key(path, "hooks")
        && map.get("type").and_then(Value::as_str) == Some("command")
        && let Some(command) = map.get("command").and_then(Value::as_str)
    {
        if signals.mutable_launcher_span.is_none()
            && let Some(relative) = find_mutable_launcher_relative_span(command)
        {
            signals.mutable_launcher_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        let lowered = command.to_ascii_lowercase();
        if signals.inline_download_exec_span.is_none() && has_inline_download_pipe_exec(&lowered) {
            signals.inline_download_exec_span = Some(resolve_child_value_span(
                path,
                "command",
                locator,
                fallback_len,
            ));
        }

        let has_network_context = looks_like_network_capable_command(&lowered);
        if signals.network_tls_bypass_span.is_none()
            && has_network_context
            && let Some(relative) = find_command_tls_bypass_relative_span(command)
        {
            signals.network_tls_bypass_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
    }

    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                path.push(JsonPathSegment::Key(key.clone()));
                visit_claude_settings_value(nested, path, locator, fallback_len, signals, metrics);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                path.push(JsonPathSegment::Index(index));
                visit_claude_settings_value(nested, path, locator, fallback_len, signals, metrics);
                path.pop();
            }
        }
        _ => {}
    }
}

pub(crate) fn visit_tool_json_value(
    value: &Value,
    normalized_path: &str,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    signals: &mut ToolJsonSignals,
    metrics: &mut SignalWorkBudget,
) {
    let collections = collect_tool_descriptor_collections(value, metrics);
    if collections.is_empty() || signals.fixture_like_path {
        return;
    }

    for collection in collections {
        let mut seen_mcp_names = std::collections::BTreeSet::new();
        for path in collection {
            let Some(object) = json_object_at_path(value, &path) else {
                continue;
            };

            if is_mcp_style_tool_descriptor_object(object) {
                if signals.mcp_missing_machine_field_span.is_none()
                    && let Some(span) =
                        find_mcp_missing_machine_field_span(&path, object, locator, fallback_len)
                {
                    signals.mcp_missing_machine_field_span = Some(span);
                }

                if signals.duplicate_mcp_tool_name_span.is_none()
                    && let Some(name) = object.get("name").and_then(Value::as_str)
                    && !seen_mcp_names.insert(name.to_owned())
                {
                    signals.duplicate_mcp_tool_name_span = Some(resolve_child_value_span(
                        &path,
                        "name",
                        locator,
                        fallback_len,
                    ));
                }
            }

            if let Some(function_object) = openai_function_object(object) {
                let strict_enabled = object.get("strict").and_then(Value::as_bool) == Some(true)
                    || function_object.get("strict").and_then(Value::as_bool) == Some(true);
                if strict_enabled {
                    let parameters_key = "parameters";
                    if let Some(parameters) = function_object.get(parameters_key) {
                        if signals.openai_strict_additional_properties_span.is_none()
                            && let Some(relative_path) =
                                find_open_object_schema_lock_span_path(parameters, metrics)
                        {
                            signals.openai_strict_additional_properties_span =
                                Some(resolve_openai_relative_schema_span(
                                    &path,
                                    parameters_key,
                                    &relative_path,
                                    locator,
                                    fallback_len,
                                ));
                        }

                        if signals.openai_strict_required_span.is_none()
                            && let Some(relative_path) =
                                find_required_coverage_mismatch_span_path(parameters, metrics)
                        {
                            signals.openai_strict_required_span =
                                Some(resolve_openai_relative_schema_span(
                                    &path,
                                    parameters_key,
                                    &relative_path,
                                    locator,
                                    fallback_len,
                                ));
                        }
                    }
                }
            }

            if signals.anthropic_strict_locked_input_schema_span.is_none()
                && object.get("name").and_then(Value::as_str).is_some()
                && object.get("strict").and_then(Value::as_bool) == Some(true)
                && let Some(input_schema) = object.get("input_schema")
                && let Some(relative_path) =
                    find_open_object_schema_lock_span_path(input_schema, metrics)
            {
                signals.anthropic_strict_locked_input_schema_span =
                    Some(resolve_relative_schema_span(
                        &path,
                        "input_schema",
                        &relative_path,
                        locator,
                        fallback_len,
                    ));
            }
        }
    }

    let _ = normalized_path;
}

pub(crate) fn collect_tool_descriptor_collections(
    value: &Value,
    metrics: &mut SignalWorkBudget,
) -> Vec<Vec<Vec<JsonPathSegment>>> {
    metrics.json_values_visited += 1;
    let mut collections = Vec::new();

    match value {
        Value::Array(items) => {
            let paths = items
                .iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    item.as_object()
                        .filter(|object| looks_like_tool_descriptor_object(object))
                        .map(|_| vec![JsonPathSegment::Index(index)])
                })
                .collect::<Vec<_>>();
            if !paths.is_empty() {
                collections.push(paths);
            }
        }
        Value::Object(map) => {
            if looks_like_tool_descriptor_object(map) {
                collections.push(vec![Vec::new()]);
            }

            for key in ["tools", "functions"] {
                let Some(items) = map.get(key).and_then(Value::as_array) else {
                    continue;
                };
                let paths = items
                    .iter()
                    .enumerate()
                    .filter_map(|(index, item)| {
                        item.as_object()
                            .filter(|object| looks_like_tool_descriptor_object(object))
                            .map(|_| {
                                vec![
                                    JsonPathSegment::Key(key.to_owned()),
                                    JsonPathSegment::Index(index),
                                ]
                            })
                    })
                    .collect::<Vec<_>>();
                if !paths.is_empty() {
                    collections.push(paths);
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }

    collections
}

pub(crate) fn json_object_at_path<'a>(
    value: &'a Value,
    path: &[JsonPathSegment],
) -> Option<&'a serde_json::Map<String, Value>> {
    let mut current = value;
    for segment in path {
        match segment {
            JsonPathSegment::Key(key) => {
                current = current.as_object()?.get(key)?;
            }
            JsonPathSegment::Index(index) => {
                current = current.as_array()?.get(*index)?;
            }
        }
    }
    current.as_object()
}

pub(crate) fn looks_like_tool_descriptor_object(object: &serde_json::Map<String, Value>) -> bool {
    if object.contains_key("tools") || object.contains_key("functions") {
        return false;
    }

    object.contains_key("inputSchema")
        || object.contains_key("input_schema")
        || object.contains_key("parameters")
        || object.contains_key("function")
        || object.contains_key("name")
}

pub(crate) fn is_mcp_style_tool_descriptor_object(object: &serde_json::Map<String, Value>) -> bool {
    if object.contains_key("inputSchema") {
        return true;
    }

    object.get("name").and_then(Value::as_str).is_some()
        && !object.contains_key("function")
        && !object.contains_key("input_schema")
        && !object.contains_key("parameters")
        && !object.contains_key("tools")
        && !object.contains_key("functions")
}

pub(crate) fn find_mcp_missing_machine_field_span(
    path: &[JsonPathSegment],
    object: &serde_json::Map<String, Value>,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Option<Span> {
    let has_name = object.get("name").and_then(Value::as_str).is_some();
    let has_input_schema = object.contains_key("inputSchema");

    if has_input_schema && !has_name {
        return Some(resolve_child_value_or_key_span(
            path,
            "inputSchema",
            locator,
            fallback_len,
        ));
    }

    if !has_input_schema
        && has_name
        && (object.get("description").and_then(Value::as_str).is_some()
            || object.get("title").and_then(Value::as_str).is_some()
            || object
                .get("annotations")
                .and_then(Value::as_object)
                .is_some())
    {
        return Some(resolve_child_value_span(
            path,
            "name",
            locator,
            fallback_len,
        ));
    }

    None
}

pub(crate) fn openai_function_object<'a>(
    object: &'a serde_json::Map<String, Value>,
) -> Option<&'a serde_json::Map<String, Value>> {
    (object.get("type").and_then(Value::as_str) == Some("function"))
        .then(|| object.get("function").and_then(Value::as_object))
        .flatten()
}

pub(crate) fn find_open_object_schema_lock_span_path(
    value: &Value,
    metrics: &mut SignalWorkBudget,
) -> Option<Vec<JsonPathSegment>> {
    let mut path = Vec::new();
    find_open_object_schema_lock_span_path_inner(value, &mut path, metrics)
}

pub(crate) fn find_open_object_schema_lock_span_path_inner(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
    metrics: &mut SignalWorkBudget,
) -> Option<Vec<JsonPathSegment>> {
    metrics.json_values_visited += 1;
    let object = value.as_object()?;
    let has_properties = object
        .get("properties")
        .and_then(Value::as_object)
        .is_some();
    if has_properties {
        match object.get("additionalProperties") {
            Some(Value::Bool(false)) => {}
            Some(_) => {
                let mut offending = path.clone();
                offending.push(JsonPathSegment::Key("additionalProperties".to_owned()));
                return Some(offending);
            }
            None => {
                let mut offending = path.clone();
                offending.push(JsonPathSegment::Key("properties".to_owned()));
                return Some(offending);
            }
        }
    }

    if let Some(properties) = object.get("properties").and_then(Value::as_object) {
        for (key, nested) in properties {
            path.push(JsonPathSegment::Key("properties".to_owned()));
            path.push(JsonPathSegment::Key(key.clone()));
            if let Some(offending) =
                find_open_object_schema_lock_span_path_inner(nested, path, metrics)
            {
                return Some(offending);
            }
            path.pop();
            path.pop();
        }
    }

    if let Some(items) = object.get("items") {
        path.push(JsonPathSegment::Key("items".to_owned()));
        if let Some(offending) = find_open_object_schema_lock_span_path_inner(items, path, metrics)
        {
            return Some(offending);
        }
        path.pop();
    }

    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(variants) = object.get(key).and_then(Value::as_array) {
            for (index, nested) in variants.iter().enumerate() {
                path.push(JsonPathSegment::Key(key.to_owned()));
                path.push(JsonPathSegment::Index(index));
                if let Some(offending) =
                    find_open_object_schema_lock_span_path_inner(nested, path, metrics)
                {
                    return Some(offending);
                }
                path.pop();
                path.pop();
            }
        }
    }

    None
}

pub(crate) fn find_required_coverage_mismatch_span_path(
    value: &Value,
    metrics: &mut SignalWorkBudget,
) -> Option<Vec<JsonPathSegment>> {
    let mut path = Vec::new();
    find_required_coverage_mismatch_span_path_inner(value, &mut path, metrics)
}

pub(crate) fn find_required_coverage_mismatch_span_path_inner(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
    metrics: &mut SignalWorkBudget,
) -> Option<Vec<JsonPathSegment>> {
    metrics.json_values_visited += 1;
    let object = value.as_object()?;
    if let Some(properties) = object.get("properties").and_then(Value::as_object) {
        let property_keys = properties
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let required_keys = object
            .get("required")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .unwrap_or_default();
        if property_keys != required_keys {
            let mut offending = path.clone();
            offending.push(JsonPathSegment::Key(
                if object.get("required").is_some() {
                    "required"
                } else {
                    "properties"
                }
                .to_owned(),
            ));
            return Some(offending);
        }

        for (key, nested) in properties {
            path.push(JsonPathSegment::Key("properties".to_owned()));
            path.push(JsonPathSegment::Key(key.clone()));
            if let Some(offending) =
                find_required_coverage_mismatch_span_path_inner(nested, path, metrics)
            {
                return Some(offending);
            }
            path.pop();
            path.pop();
        }
    }

    if let Some(items) = object.get("items") {
        path.push(JsonPathSegment::Key("items".to_owned()));
        if let Some(offending) =
            find_required_coverage_mismatch_span_path_inner(items, path, metrics)
        {
            return Some(offending);
        }
        path.pop();
    }

    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(variants) = object.get(key).and_then(Value::as_array) {
            for (index, nested) in variants.iter().enumerate() {
                path.push(JsonPathSegment::Key(key.to_owned()));
                path.push(JsonPathSegment::Index(index));
                if let Some(offending) =
                    find_required_coverage_mismatch_span_path_inner(nested, path, metrics)
                {
                    return Some(offending);
                }
                path.pop();
                path.pop();
            }
        }
    }

    None
}

pub(crate) fn resolve_relative_schema_span(
    path: &[JsonPathSegment],
    schema_key: &str,
    relative_path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Span {
    let mut full_path = path.to_vec();
    full_path.push(JsonPathSegment::Key(schema_key.to_owned()));
    full_path.extend_from_slice(relative_path);
    resolve_value_or_key_span(&full_path, locator, fallback_len)
}

pub(crate) fn resolve_openai_relative_schema_span(
    path: &[JsonPathSegment],
    schema_key: &str,
    relative_path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Span {
    let mut full_path = path.to_vec();
    full_path.push(JsonPathSegment::Key("function".to_owned()));
    full_path.push(JsonPathSegment::Key(schema_key.to_owned()));
    full_path.extend_from_slice(relative_path);
    resolve_value_or_key_span(&full_path, locator, fallback_len)
}

pub(crate) fn is_plugin_hook_command_path(path: &[JsonPathSegment]) -> bool {
    path.iter().any(|segment| {
        matches!(
            segment,
            JsonPathSegment::Key(key) if key.eq_ignore_ascii_case("hooks")
        )
    })
}

pub(crate) fn find_mcp_command_signal_span(
    path: &[JsonPathSegment],
    command: Option<&str>,
    args: Option<&Vec<Value>>,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Option<McpCommandSignalSpan> {
    let mut spans = McpCommandSignalSpan::default();
    let has_network_context = command
        .map(|value| looks_like_network_capable_command(&value.to_ascii_lowercase()))
        .unwrap_or(false)
        || args
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|value| looks_like_network_capable_command(&value.to_ascii_lowercase()));

    if let Some(command) = command {
        let lowered = command.to_ascii_lowercase();
        if has_inline_download_pipe_exec(&lowered) {
            spans.inline_download_exec = Some(resolve_child_value_span(
                path,
                "command",
                locator,
                fallback_len,
            ));
        }
        if has_network_context
            && let Some(relative) = find_command_tls_bypass_relative_span(command)
        {
            spans.network_tls_bypass = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
    }

    if let Some(args) = args {
        if command.is_some_and(|value| value.eq_ignore_ascii_case("docker"))
            && let Some(docker) = analyze_docker_run_args(args)
        {
            if let Some(index) = docker.mutable_image_arg_index {
                let arg_path = with_child_index(&with_child_key(path, "args"), index);
                spans.mutable_docker_image =
                    Some(resolve_value_span(&arg_path, locator, fallback_len));
            }
            if let Some(index) = docker.mutable_pull_arg_index {
                let arg_path = with_child_index(&with_child_key(path, "args"), index);
                spans.mutable_docker_pull =
                    Some(resolve_value_span(&arg_path, locator, fallback_len));
            }
            if let Some(index) = docker.sensitive_mount_arg_index {
                let arg_path = with_child_index(&with_child_key(path, "args"), index);
                spans.sensitive_docker_mount =
                    Some(resolve_value_span(&arg_path, locator, fallback_len));
            }
            if let Some(index) = docker.dangerous_flag_arg_index {
                let arg_path = with_child_index(&with_child_key(path, "args"), index);
                spans.dangerous_docker_flag =
                    Some(resolve_value_span(&arg_path, locator, fallback_len));
            }
        }

        for (index, item) in args.iter().enumerate() {
            let Some(text) = item.as_str() else {
                continue;
            };
            let lowered = text.to_ascii_lowercase();
            let arg_path = with_child_index(&with_child_key(path, "args"), index);

            if spans.inline_download_exec.is_none() && has_inline_download_pipe_exec(&lowered) {
                spans.inline_download_exec =
                    Some(resolve_value_span(&arg_path, locator, fallback_len));
            }

            if spans.network_tls_bypass.is_none()
                && has_network_context
                && let Some(relative) = find_command_tls_bypass_relative_span(text)
            {
                spans.network_tls_bypass = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }
        }
    }

    (spans.inline_download_exec.is_some()
        || spans.network_tls_bypass.is_some()
        || spans.mutable_docker_image.is_some()
        || spans.mutable_docker_pull.is_some()
        || spans.sensitive_docker_mount.is_some()
        || spans.dangerous_docker_flag.is_some())
    .then_some(spans)
}

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

pub(crate) fn shell_tokens(line: &str) -> Vec<HookToken<'_>> {
    let mut tokens = Vec::new();
    let mut token_start = None;

    for (index, ch) in line.char_indices() {
        if ch.is_whitespace() {
            if let Some(start) = token_start.take() {
                tokens.push(HookToken {
                    text: &line[start..index],
                    start,
                    end: index,
                });
            }
        } else if token_start.is_none() {
            token_start = Some(index);
        }
    }

    if let Some(start) = token_start {
        tokens.push(HookToken {
            text: &line[start..],
            start,
            end: line.len(),
        });
    }

    tokens
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

pub(crate) fn is_plugin_manifest_path_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("logo")
        || key.eq_ignore_ascii_case("skills")
        || key.eq_ignore_ascii_case("mcpServers")
        || key.eq_ignore_ascii_case("mcpservers")
        || key.eq_ignore_ascii_case("commands")
        || key.eq_ignore_ascii_case("agents")
        || key.eq_ignore_ascii_case("hooks")
}

pub(crate) fn is_unsafe_plugin_manifest_path(value: &str) -> bool {
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

pub(crate) fn find_hidden_instruction_relative_span(text: &str) -> Option<Span> {
    HTML_COMMENT_DIRECTIVE_MARKERS.iter().find_map(|needle| {
        find_ascii_case_insensitive(text, needle)
            .map(|start| Span::new(start, start + needle.len()))
    })
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
