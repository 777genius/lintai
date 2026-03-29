use lintai_api::{ArtifactKind, Span};
use serde_json::Value;

use crate::helpers::find_url_userinfo_span;
use crate::json_locator::{JsonLocationMap, JsonPathSegment};

use super::super::super::{ClaudeSettingsSignals, JsonSignals, SignalWorkBudget};
use super::super::common::{
    find_command_tls_bypass_relative_span, find_mutable_launcher_relative_span,
    has_inline_download_pipe_exec, is_mutable_mcp_launcher, looks_like_network_capable_command,
};
use super::super::hook::McpCommandSignalSpan;
use super::super::markdown::analyze_docker_run_args;
use super::auth_env::*;
use super::server_headers::*;
use super::spans::*;
use super::tool_descriptor::{
    find_hidden_instruction_relative_span, is_broad_dotenv_env_file, is_descriptive_json_key,
    is_plugin_manifest_path_key, is_unsafe_plugin_manifest_path,
};

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
