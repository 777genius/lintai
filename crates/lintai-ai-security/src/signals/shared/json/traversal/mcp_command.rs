use serde_json::Value;

use crate::json_locator::{JsonLocationMap, JsonPathSegment};
use crate::signals::JsonSignals;

use super::super::super::common::{
    find_command_tls_bypass_relative_span, find_mutable_launcher_relative_span,
    has_inline_download_pipe_exec, is_mutable_mcp_launcher, looks_like_network_capable_command,
};
use super::super::super::hook::McpCommandSignalSpan;
use super::super::super::markdown::analyze_docker_run_args;
use super::super::spans::{
    resolve_child_relative_value_span, resolve_child_value_span, resolve_relative_value_span,
    resolve_value_span, with_child_index, with_child_key,
};

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

pub(super) fn apply_mcp_config_command_rules(
    path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    command: Option<&str>,
    args: Option<&Vec<Value>>,
    signals: &mut JsonSignals,
) {
    if signals.sudo_command_span.is_none()
        && let Some(command) = command
        && command.eq_ignore_ascii_case("sudo")
    {
        signals.sudo_command_span = Some(resolve_child_value_span(
            path,
            "command",
            locator,
            fallback_len,
        ));
    }

    if signals.sudo_args0_span.is_none()
        && let Some(args) = args
        && let Some(arg0) = args.first().and_then(Value::as_str)
        && arg0.eq_ignore_ascii_case("sudo")
    {
        let arg_path = with_child_index(&with_child_key(path, "args"), 0);
        signals.sudo_args0_span = Some(resolve_value_span(&arg_path, locator, fallback_len));
    }

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
            signals.inline_download_exec_command_span = command_signals.inline_download_exec;
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

pub(super) fn apply_plugin_hook_command_rules(
    path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    command: Option<&str>,
    signals: &mut JsonSignals,
) {
    if !is_plugin_hook_command_path(path) {
        return;
    }

    if signals.mutable_plugin_hook_launcher_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_mutable_launcher_relative_span(command)
    {
        signals.mutable_plugin_hook_launcher_span = Some(resolve_child_relative_value_span(
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
        signals.network_tls_bypass_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }
}
