use serde_json::Value;

use crate::json_locator::{JsonLocationMap, JsonPathSegment};
use crate::signals::JsonSignals;

use super::super::super::common::{
    ends_with_ascii_case_insensitive, find_authorized_keys_write_relative_span,
    find_browser_secret_store_access_relative_span, find_camera_capture_relative_span,
    find_clipboard_read_relative_span, find_command_tls_bypass_relative_span,
    find_crontab_persistence_relative_span, find_destructive_root_delete_relative_span,
    find_environment_dump_relative_span, find_insecure_permission_change_relative_span,
    find_keylogging_relative_span, find_launchd_registration_relative_span,
    find_linux_capability_manipulation_relative_span, find_microphone_capture_relative_span,
    find_mutable_launcher_relative_span, find_plain_http_relative_span,
    find_screen_capture_relative_span, find_secret_reference_relative_span,
    find_sensitive_password_file_relative_span, find_sensitive_secret_file_relative_span,
    find_setuid_setgid_relative_span, find_shell_profile_write_relative_span,
    find_systemd_service_registration_relative_span, find_webhook_endpoint_relative_span,
    has_inline_download_pipe_exec, is_mutable_mcp_launcher, looks_like_exfil_network_command,
    looks_like_network_capable_command, looks_like_sensitive_file_transfer_command,
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
    let mut sensitive_file_exfil_candidate = None;
    let mut secret_exfil_candidate = None;
    let mut plain_http_secret_exfil_candidate = None;
    let mut webhook_secret_exfil_candidate = None;
    let combined_command_text = build_combined_command_text(command, args);
    let has_network_context = command
        .map(|value| looks_like_network_capable_command(&value.to_ascii_lowercase()))
        .unwrap_or(false)
        || args
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|value| looks_like_network_capable_command(&value.to_ascii_lowercase()));
    let has_exfil_network_context = command
        .map(looks_like_exfil_network_command)
        .unwrap_or(false)
        || args
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(looks_like_exfil_network_command);
    let has_sensitive_file_transfer_context =
        looks_like_sensitive_file_transfer_command(&combined_command_text);

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
        if let Some(relative) = find_destructive_root_delete_relative_span(command) {
            spans.root_delete = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_sensitive_password_file_relative_span(command) {
            spans.password_file_access = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_shell_profile_write_relative_span(command) {
            spans.shell_profile_write = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_authorized_keys_write_relative_span(command) {
            spans.authorized_keys_write = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_sensitive_secret_file_relative_span(command) {
            sensitive_file_exfil_candidate = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_clipboard_read_relative_span(command) {
            spans.clipboard_read = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_browser_secret_store_access_relative_span(command) {
            spans.browser_secret_store_access = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_screen_capture_relative_span(command) {
            spans.screen_capture = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_camera_capture_relative_span(command) {
            spans.camera_capture = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_microphone_capture_relative_span(command) {
            spans.microphone_capture = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_keylogging_relative_span(command) {
            spans.keylogging = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_environment_dump_relative_span(command) {
            spans.environment_dump = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_secret_reference_relative_span(command) {
            secret_exfil_candidate = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_plain_http_relative_span(command) {
            plain_http_secret_exfil_candidate = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_webhook_endpoint_relative_span(command) {
            webhook_secret_exfil_candidate = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_crontab_persistence_relative_span(command) {
            spans.cron_persistence = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_systemd_service_registration_relative_span(command) {
            spans.systemd_service_registration = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_launchd_registration_relative_span(command) {
            spans.launchd_registration = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_insecure_permission_change_relative_span(command) {
            spans.insecure_permission_change = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_setuid_setgid_relative_span(command) {
            spans.setuid_setgid = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
        if let Some(relative) = find_linux_capability_manipulation_relative_span(command) {
            spans.linux_capability_manipulation = Some(resolve_child_relative_value_span(
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
        let command_is_rm = command_matches(command, "rm");
        let command_is_tee = command_matches(command, "tee");
        let command_is_crontab = command_matches(command, "crontab");
        let command_is_systemctl = command_matches(command, "systemctl");
        let command_is_launchctl = command_matches(command, "launchctl");
        let command_is_chmod = command_matches(command, "chmod");
        let command_is_setcap = command_matches(command, "setcap");
        let mut rm_has_recursive = false;
        let mut rm_has_force = false;
        let mut rm_root_arg_index = None;
        let mut crontab_list_only = false;

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

            if spans.root_delete.is_none()
                && let Some(relative) = find_destructive_root_delete_relative_span(text)
            {
                spans.root_delete = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }

            if spans.password_file_access.is_none()
                && let Some(relative) = find_sensitive_password_file_relative_span(text)
            {
                spans.password_file_access = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }

            if spans.shell_profile_write.is_none() {
                if let Some(relative) = find_shell_profile_write_relative_span(text) {
                    spans.shell_profile_write = Some(resolve_relative_value_span(
                        &arg_path,
                        relative,
                        locator,
                        fallback_len,
                    ));
                } else if command_is_tee && is_shell_profile_path(text) {
                    spans.shell_profile_write =
                        Some(resolve_value_span(&arg_path, locator, fallback_len));
                }
            }

            if spans.authorized_keys_write.is_none() {
                if let Some(relative) = find_authorized_keys_write_relative_span(text) {
                    spans.authorized_keys_write = Some(resolve_relative_value_span(
                        &arg_path,
                        relative,
                        locator,
                        fallback_len,
                    ));
                } else if command_is_tee && is_authorized_keys_path(text) {
                    spans.authorized_keys_write =
                        Some(resolve_value_span(&arg_path, locator, fallback_len));
                }
            }

            if sensitive_file_exfil_candidate.is_none()
                && let Some(relative) = find_sensitive_secret_file_relative_span(text)
            {
                sensitive_file_exfil_candidate = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }

            if spans.clipboard_read.is_none()
                && let Some(relative) = find_clipboard_read_relative_span(text)
            {
                spans.clipboard_read = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }

            if spans.browser_secret_store_access.is_none()
                && let Some(relative) = find_browser_secret_store_access_relative_span(text)
            {
                spans.browser_secret_store_access = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }

            if spans.screen_capture.is_none()
                && let Some(relative) = find_screen_capture_relative_span(text)
            {
                spans.screen_capture = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }

            if spans.camera_capture.is_none()
                && let Some(relative) = find_camera_capture_relative_span(text)
            {
                spans.camera_capture = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }

            if spans.microphone_capture.is_none()
                && let Some(relative) = find_microphone_capture_relative_span(text)
            {
                spans.microphone_capture = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }
            if spans.keylogging.is_none()
                && let Some(relative) = find_keylogging_relative_span(text)
            {
                spans.keylogging = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }
            if spans.environment_dump.is_none()
                && let Some(relative) = find_environment_dump_relative_span(text)
            {
                spans.environment_dump = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }

            if secret_exfil_candidate.is_none()
                && let Some(relative) = find_secret_reference_relative_span(text)
            {
                secret_exfil_candidate = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }

            if plain_http_secret_exfil_candidate.is_none()
                && let Some(relative) = find_plain_http_relative_span(text)
            {
                plain_http_secret_exfil_candidate = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }

            if webhook_secret_exfil_candidate.is_none()
                && let Some(relative) = find_webhook_endpoint_relative_span(text)
            {
                webhook_secret_exfil_candidate = Some(resolve_relative_value_span(
                    &arg_path,
                    relative,
                    locator,
                    fallback_len,
                ));
            }

            if spans.cron_persistence.is_none() {
                if let Some(relative) = find_crontab_persistence_relative_span(text) {
                    spans.cron_persistence = Some(resolve_relative_value_span(
                        &arg_path,
                        relative,
                        locator,
                        fallback_len,
                    ));
                } else if command_is_tee && is_cron_path(text) {
                    spans.cron_persistence =
                        Some(resolve_value_span(&arg_path, locator, fallback_len));
                }
            }

            if spans.systemd_service_registration.is_none() {
                if let Some(relative) = find_systemd_service_registration_relative_span(text) {
                    spans.systemd_service_registration = Some(resolve_relative_value_span(
                        &arg_path,
                        relative,
                        locator,
                        fallback_len,
                    ));
                } else if command_is_tee && is_systemd_unit_path(text) {
                    spans.systemd_service_registration =
                        Some(resolve_value_span(&arg_path, locator, fallback_len));
                }
            }

            if spans.launchd_registration.is_none() {
                if let Some(relative) = find_launchd_registration_relative_span(text) {
                    spans.launchd_registration = Some(resolve_relative_value_span(
                        &arg_path,
                        relative,
                        locator,
                        fallback_len,
                    ));
                } else if command_is_tee && is_launchd_plist_path(text) {
                    spans.launchd_registration =
                        Some(resolve_value_span(&arg_path, locator, fallback_len));
                }
            }

            if spans.insecure_permission_change.is_none() {
                if let Some(relative) = find_insecure_permission_change_relative_span(text) {
                    spans.insecure_permission_change = Some(resolve_relative_value_span(
                        &arg_path,
                        relative,
                        locator,
                        fallback_len,
                    ));
                } else if command_is_chmod && is_insecure_chmod_mode(text) {
                    spans.insecure_permission_change =
                        Some(resolve_value_span(&arg_path, locator, fallback_len));
                }
            }

            if spans.setuid_setgid.is_none() {
                if let Some(relative) = find_setuid_setgid_relative_span(text) {
                    spans.setuid_setgid = Some(resolve_relative_value_span(
                        &arg_path,
                        relative,
                        locator,
                        fallback_len,
                    ));
                } else if command_is_chmod && is_setuid_setgid_mode(text) {
                    spans.setuid_setgid =
                        Some(resolve_value_span(&arg_path, locator, fallback_len));
                }
            }

            if spans.linux_capability_manipulation.is_none() {
                if let Some(relative) = find_linux_capability_manipulation_relative_span(text) {
                    spans.linux_capability_manipulation = Some(resolve_relative_value_span(
                        &arg_path,
                        relative,
                        locator,
                        fallback_len,
                    ));
                } else if command_is_setcap && is_linux_capability_token(text) {
                    spans.linux_capability_manipulation =
                        Some(resolve_value_span(&arg_path, locator, fallback_len));
                }
            }

            if command_is_rm {
                if lowered == "--recursive" {
                    rm_has_recursive = true;
                } else if lowered == "--force" {
                    rm_has_force = true;
                } else if lowered.starts_with('-') && !lowered.starts_with("--") {
                    for flag in lowered[1..].chars() {
                        if flag == 'r' {
                            rm_has_recursive = true;
                        }
                        if flag == 'f' {
                            rm_has_force = true;
                        }
                    }
                }
                if lowered == "--no-preserve-root" && spans.root_delete.is_none() {
                    spans.root_delete = Some(resolve_value_span(&arg_path, locator, fallback_len));
                }
                if text == "/" || text == "/*" {
                    rm_root_arg_index = Some(index);
                }
            }

            if command_is_crontab && spans.cron_persistence.is_none() {
                if lowered == "-l" || lowered == "--list" {
                    crontab_list_only = true;
                } else {
                    spans.cron_persistence =
                        Some(resolve_value_span(&arg_path, locator, fallback_len));
                }
            }

            if command_is_systemctl
                && spans.systemd_service_registration.is_none()
                && (lowered == "enable" || lowered == "link")
            {
                spans.systemd_service_registration =
                    Some(resolve_value_span(&arg_path, locator, fallback_len));
            }

            if command_is_launchctl
                && spans.launchd_registration.is_none()
                && (lowered == "load" || lowered == "bootstrap")
            {
                spans.launchd_registration =
                    Some(resolve_value_span(&arg_path, locator, fallback_len));
            }
        }

        if spans.root_delete.is_none()
            && command_is_rm
            && rm_has_recursive
            && rm_has_force
            && let Some(index) = rm_root_arg_index
        {
            let arg_path = with_child_index(&with_child_key(path, "args"), index);
            spans.root_delete = Some(resolve_value_span(&arg_path, locator, fallback_len));
        }

        if spans.cron_persistence.is_none() && command_is_crontab && !crontab_list_only {
            spans.cron_persistence = Some(resolve_child_value_span(
                path,
                "command",
                locator,
                fallback_len,
            ));
        }

        if spans.linux_capability_manipulation.is_none() && command_is_setcap {
            spans.linux_capability_manipulation = Some(resolve_child_value_span(
                path,
                "command",
                locator,
                fallback_len,
            ));
        }

        if spans.sensitive_file_exfil.is_none() && has_sensitive_file_transfer_context {
            spans.sensitive_file_exfil = sensitive_file_exfil_candidate.clone();
        }

        if spans.clipboard_exfil.is_none() && has_exfil_network_context {
            spans.clipboard_exfil = spans.clipboard_read.clone();
        }

        if spans.browser_secret_store_exfil.is_none() && has_exfil_network_context {
            spans.browser_secret_store_exfil = spans.browser_secret_store_access.clone();
        }

        if spans.screen_capture_exfil.is_none() && has_exfil_network_context {
            spans.screen_capture_exfil = spans.screen_capture.clone();
        }

        if spans.camera_capture_exfil.is_none() && has_exfil_network_context {
            spans.camera_capture_exfil = spans.camera_capture.clone();
        }

        if spans.microphone_capture_exfil.is_none() && has_exfil_network_context {
            spans.microphone_capture_exfil = spans.microphone_capture.clone();
        }
        if spans.keylogging_exfil.is_none() && has_exfil_network_context {
            spans.keylogging_exfil = spans.keylogging.clone();
        }
        if spans.environment_dump_exfil.is_none() && has_exfil_network_context {
            spans.environment_dump_exfil = spans.environment_dump.clone();
        }

        if spans.secret_exfil.is_none() && has_exfil_network_context {
            spans.secret_exfil = secret_exfil_candidate.clone();
        }

        if spans.plain_http_secret_exfil.is_none()
            && has_exfil_network_context
            && secret_exfil_candidate.is_some()
        {
            spans.plain_http_secret_exfil = plain_http_secret_exfil_candidate.clone();
        }

        if spans.webhook_secret_exfil.is_none()
            && has_exfil_network_context
            && secret_exfil_candidate.is_some()
        {
            spans.webhook_secret_exfil = webhook_secret_exfil_candidate.clone();
        }
    }

    (spans.inline_download_exec.is_some()
        || spans.network_tls_bypass.is_some()
        || spans.root_delete.is_some()
        || spans.password_file_access.is_some()
        || spans.shell_profile_write.is_some()
        || spans.authorized_keys_write.is_some()
        || spans.sensitive_file_exfil.is_some()
        || spans.clipboard_read.is_some()
        || spans.browser_secret_store_access.is_some()
        || spans.clipboard_exfil.is_some()
        || spans.browser_secret_store_exfil.is_some()
        || spans.screen_capture.is_some()
        || spans.screen_capture_exfil.is_some()
        || spans.camera_capture.is_some()
        || spans.microphone_capture.is_some()
        || spans.camera_capture_exfil.is_some()
        || spans.microphone_capture_exfil.is_some()
        || spans.keylogging.is_some()
        || spans.keylogging_exfil.is_some()
        || spans.environment_dump.is_some()
        || spans.environment_dump_exfil.is_some()
        || spans.secret_exfil.is_some()
        || spans.plain_http_secret_exfil.is_some()
        || spans.webhook_secret_exfil.is_some()
        || spans.cron_persistence.is_some()
        || spans.systemd_service_registration.is_some()
        || spans.launchd_registration.is_some()
        || spans.insecure_permission_change.is_some()
        || spans.setuid_setgid.is_some()
        || spans.linux_capability_manipulation.is_some()
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
        || signals.root_delete_command_span.is_none()
        || signals.password_file_access_command_span.is_none()
        || signals.shell_profile_write_command_span.is_none()
        || signals.authorized_keys_write_command_span.is_none()
        || signals.sensitive_file_exfil_command_span.is_none()
        || signals.clipboard_read_command_span.is_none()
        || signals.browser_secret_store_access_command_span.is_none()
        || signals.clipboard_exfil_command_span.is_none()
        || signals.browser_secret_store_exfil_command_span.is_none()
        || signals.screen_capture_command_span.is_none()
        || signals.screen_capture_exfil_command_span.is_none()
        || signals.camera_capture_command_span.is_none()
        || signals.microphone_capture_command_span.is_none()
        || signals.camera_capture_exfil_command_span.is_none()
        || signals.microphone_capture_exfil_command_span.is_none()
        || signals.keylogging_command_span.is_none()
        || signals.keylogging_exfil_command_span.is_none()
        || signals.environment_dump_command_span.is_none()
        || signals.environment_dump_exfil_command_span.is_none()
        || signals.secret_exfil_command_span.is_none()
        || signals.plain_http_secret_exfil_command_span.is_none()
        || signals.webhook_secret_exfil_command_span.is_none()
        || signals.cron_persistence_command_span.is_none()
        || signals.systemd_service_registration_command_span.is_none()
        || signals.launchd_registration_command_span.is_none()
        || signals.insecure_permission_change_command_span.is_none()
        || signals.setuid_setgid_command_span.is_none()
        || signals.linux_capability_manipulation_command_span.is_none()
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
        if signals.root_delete_command_span.is_none() {
            signals.root_delete_command_span = command_signals.root_delete;
        }
        if signals.password_file_access_command_span.is_none() {
            signals.password_file_access_command_span = command_signals.password_file_access;
        }
        if signals.shell_profile_write_command_span.is_none() {
            signals.shell_profile_write_command_span = command_signals.shell_profile_write;
        }
        if signals.authorized_keys_write_command_span.is_none() {
            signals.authorized_keys_write_command_span = command_signals.authorized_keys_write;
        }
        if signals.sensitive_file_exfil_command_span.is_none() {
            signals.sensitive_file_exfil_command_span = command_signals.sensitive_file_exfil;
        }
        if signals.clipboard_read_command_span.is_none() {
            signals.clipboard_read_command_span = command_signals.clipboard_read;
        }
        if signals.browser_secret_store_access_command_span.is_none() {
            signals.browser_secret_store_access_command_span =
                command_signals.browser_secret_store_access;
        }
        if signals.clipboard_exfil_command_span.is_none() {
            signals.clipboard_exfil_command_span = command_signals.clipboard_exfil;
        }
        if signals.browser_secret_store_exfil_command_span.is_none() {
            signals.browser_secret_store_exfil_command_span =
                command_signals.browser_secret_store_exfil;
        }
        if signals.screen_capture_command_span.is_none() {
            signals.screen_capture_command_span = command_signals.screen_capture;
        }
        if signals.screen_capture_exfil_command_span.is_none() {
            signals.screen_capture_exfil_command_span = command_signals.screen_capture_exfil;
        }
        if signals.camera_capture_command_span.is_none() {
            signals.camera_capture_command_span = command_signals.camera_capture;
        }
        if signals.microphone_capture_command_span.is_none() {
            signals.microphone_capture_command_span = command_signals.microphone_capture;
        }
        if signals.camera_capture_exfil_command_span.is_none() {
            signals.camera_capture_exfil_command_span = command_signals.camera_capture_exfil;
        }
        if signals.microphone_capture_exfil_command_span.is_none() {
            signals.microphone_capture_exfil_command_span =
                command_signals.microphone_capture_exfil;
        }
        if signals.keylogging_command_span.is_none() {
            signals.keylogging_command_span = command_signals.keylogging;
        }
        if signals.keylogging_exfil_command_span.is_none() {
            signals.keylogging_exfil_command_span = command_signals.keylogging_exfil;
        }
        if signals.environment_dump_command_span.is_none() {
            signals.environment_dump_command_span = command_signals.environment_dump;
        }
        if signals.environment_dump_exfil_command_span.is_none() {
            signals.environment_dump_exfil_command_span = command_signals.environment_dump_exfil;
        }
        if signals.secret_exfil_command_span.is_none() {
            signals.secret_exfil_command_span = command_signals.secret_exfil;
        }
        if signals.plain_http_secret_exfil_command_span.is_none() {
            signals.plain_http_secret_exfil_command_span = command_signals.plain_http_secret_exfil;
        }
        if signals.webhook_secret_exfil_command_span.is_none() {
            signals.webhook_secret_exfil_command_span = command_signals.webhook_secret_exfil;
        }
        if signals.cron_persistence_command_span.is_none() {
            signals.cron_persistence_command_span = command_signals.cron_persistence;
        }
        if signals.systemd_service_registration_command_span.is_none() {
            signals.systemd_service_registration_command_span =
                command_signals.systemd_service_registration;
        }
        if signals.launchd_registration_command_span.is_none() {
            signals.launchd_registration_command_span = command_signals.launchd_registration;
        }
        if signals.insecure_permission_change_command_span.is_none() {
            signals.insecure_permission_change_command_span =
                command_signals.insecure_permission_change;
        }
        if signals.setuid_setgid_command_span.is_none() {
            signals.setuid_setgid_command_span = command_signals.setuid_setgid;
        }
        if signals.linux_capability_manipulation_command_span.is_none() {
            signals.linux_capability_manipulation_command_span =
                command_signals.linux_capability_manipulation;
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

    if signals.root_delete_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_destructive_root_delete_relative_span(command)
    {
        signals.root_delete_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.password_file_access_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_sensitive_password_file_relative_span(command)
    {
        signals.password_file_access_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.shell_profile_write_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_shell_profile_write_relative_span(command)
    {
        signals.shell_profile_write_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.authorized_keys_write_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_authorized_keys_write_relative_span(command)
    {
        signals.authorized_keys_write_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.sensitive_file_exfil_plugin_hook_span.is_none()
        && let Some(command) = command
        && looks_like_sensitive_file_transfer_command(command)
        && let Some(relative) = find_sensitive_secret_file_relative_span(command)
    {
        signals.sensitive_file_exfil_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.clipboard_read_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_clipboard_read_relative_span(command)
    {
        signals.clipboard_read_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals
        .browser_secret_store_access_plugin_hook_span
        .is_none()
        && let Some(command) = command
        && let Some(relative) = find_browser_secret_store_access_relative_span(command)
    {
        signals.browser_secret_store_access_plugin_hook_span =
            Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
    }

    if signals.screen_capture_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_screen_capture_relative_span(command)
    {
        signals.screen_capture_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.camera_capture_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_camera_capture_relative_span(command)
    {
        signals.camera_capture_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.microphone_capture_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_microphone_capture_relative_span(command)
    {
        signals.microphone_capture_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.keylogging_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_keylogging_relative_span(command)
    {
        signals.keylogging_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.environment_dump_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_environment_dump_relative_span(command)
    {
        signals.environment_dump_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.secret_exfil_plugin_hook_span.is_none()
        && let Some(command) = command
        && looks_like_exfil_network_command(command)
        && let Some(relative) = find_secret_reference_relative_span(command)
    {
        signals.secret_exfil_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.clipboard_exfil_plugin_hook_span.is_none()
        && let Some(command) = command
        && looks_like_exfil_network_command(command)
        && let Some(relative) = find_clipboard_read_relative_span(command)
    {
        signals.clipboard_exfil_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals
        .browser_secret_store_exfil_plugin_hook_span
        .is_none()
        && let Some(command) = command
        && looks_like_exfil_network_command(command)
        && let Some(relative) = find_browser_secret_store_access_relative_span(command)
    {
        signals.browser_secret_store_exfil_plugin_hook_span =
            Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
    }

    if signals.screen_capture_exfil_plugin_hook_span.is_none()
        && let Some(command) = command
        && looks_like_exfil_network_command(command)
        && let Some(relative) = find_screen_capture_relative_span(command)
    {
        signals.screen_capture_exfil_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.camera_capture_exfil_plugin_hook_span.is_none()
        && let Some(command) = command
        && looks_like_exfil_network_command(command)
        && let Some(relative) = find_camera_capture_relative_span(command)
    {
        signals.camera_capture_exfil_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.microphone_capture_exfil_plugin_hook_span.is_none()
        && let Some(command) = command
        && looks_like_exfil_network_command(command)
        && let Some(relative) = find_microphone_capture_relative_span(command)
    {
        signals.microphone_capture_exfil_plugin_hook_span =
            Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
    }

    if signals.keylogging_exfil_plugin_hook_span.is_none()
        && let Some(command) = command
        && looks_like_exfil_network_command(command)
        && let Some(relative) = find_keylogging_relative_span(command)
    {
        signals.keylogging_exfil_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.environment_dump_exfil_plugin_hook_span.is_none()
        && let Some(command) = command
        && looks_like_exfil_network_command(command)
        && let Some(relative) = find_environment_dump_relative_span(command)
    {
        signals.environment_dump_exfil_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.plain_http_secret_exfil_plugin_hook_span.is_none()
        && let Some(command) = command
        && looks_like_exfil_network_command(command)
        && find_secret_reference_relative_span(command).is_some()
        && let Some(relative) = find_plain_http_relative_span(command)
    {
        signals.plain_http_secret_exfil_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.webhook_secret_exfil_plugin_hook_span.is_none()
        && let Some(command) = command
        && looks_like_exfil_network_command(command)
        && find_secret_reference_relative_span(command).is_some()
        && let Some(relative) = find_webhook_endpoint_relative_span(command)
    {
        signals.webhook_secret_exfil_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.cron_persistence_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_crontab_persistence_relative_span(command)
    {
        signals.cron_persistence_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals
        .systemd_service_registration_plugin_hook_span
        .is_none()
        && let Some(command) = command
        && let Some(relative) = find_systemd_service_registration_relative_span(command)
    {
        signals.systemd_service_registration_plugin_hook_span =
            Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
    }

    if signals.launchd_registration_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_launchd_registration_relative_span(command)
    {
        signals.launchd_registration_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals
        .insecure_permission_change_plugin_hook_span
        .is_none()
        && let Some(command) = command
        && let Some(relative) = find_insecure_permission_change_relative_span(command)
    {
        signals.insecure_permission_change_plugin_hook_span =
            Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
    }

    if signals.setuid_setgid_plugin_hook_span.is_none()
        && let Some(command) = command
        && let Some(relative) = find_setuid_setgid_relative_span(command)
    {
        signals.setuid_setgid_plugin_hook_span = Some(resolve_child_relative_value_span(
            path,
            "command",
            "command",
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals
        .linux_capability_manipulation_plugin_hook_span
        .is_none()
        && let Some(command) = command
        && let Some(relative) = find_linux_capability_manipulation_relative_span(command)
    {
        signals.linux_capability_manipulation_plugin_hook_span =
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

fn command_matches(command: Option<&str>, expected: &str) -> bool {
    command.is_some_and(|value| {
        value.eq_ignore_ascii_case(expected)
            || value
                .rsplit('/')
                .next()
                .is_some_and(|component| component.eq_ignore_ascii_case(expected))
    })
}

fn build_combined_command_text(command: Option<&str>, args: Option<&Vec<Value>>) -> String {
    let mut parts = Vec::new();
    if let Some(command) = command {
        parts.push(command.to_owned());
    }
    if let Some(args) = args {
        for item in args {
            if let Some(text) = item.as_str() {
                parts.push(text.to_owned());
            }
        }
    }
    parts.join(" ")
}

fn is_shell_profile_path(text: &str) -> bool {
    [".bashrc", ".bash_profile", ".zshrc", ".profile"]
        .iter()
        .any(|suffix| ends_with_ascii_case_insensitive(text, suffix))
}

fn is_authorized_keys_path(text: &str) -> bool {
    ends_with_ascii_case_insensitive(text, "authorized_keys")
}

fn is_cron_path(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered == "/etc/crontab"
        || lowered.contains("/etc/cron")
        || lowered.contains("/var/spool/cron")
}

fn is_systemd_unit_path(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    let is_systemd_path = lowered.contains("/etc/systemd/system/")
        || lowered.contains("/lib/systemd/system/")
        || lowered.contains("/usr/lib/systemd/system/")
        || lowered.contains("/run/systemd/system/")
        || lowered.contains("/.config/systemd/user/")
        || lowered.contains("/systemd/user/");
    let is_unit_file = lowered.ends_with(".service")
        || lowered.ends_with(".timer")
        || lowered.ends_with(".socket")
        || lowered.ends_with(".path");

    is_systemd_path && is_unit_file
}

fn is_launchd_plist_path(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    (lowered.contains("/library/launchagents/") || lowered.contains("/library/launchdaemons/"))
        && lowered.ends_with(".plist")
}

fn is_insecure_chmod_mode(text: &str) -> bool {
    let trimmed = text.trim_matches(|ch| matches!(ch, '"' | '\'' | ';'));
    matches!(trimmed, "777" | "0777")
        || trimmed.eq_ignore_ascii_case("a+rwx")
        || trimmed.eq_ignore_ascii_case("ugo+rwx")
}

fn is_setuid_setgid_mode(text: &str) -> bool {
    let trimmed = text.trim_matches(|ch| matches!(ch, '"' | '\'' | ';'));
    if trimmed.eq_ignore_ascii_case("u+s")
        || trimmed.eq_ignore_ascii_case("g+s")
        || trimmed.eq_ignore_ascii_case("ug+s")
        || trimmed.eq_ignore_ascii_case("u=xs")
        || trimmed.eq_ignore_ascii_case("g=xs")
    {
        return true;
    }

    let octal = trimmed.strip_prefix('0').unwrap_or(trimmed);
    octal.len() == 4
        && octal.as_bytes().iter().all(u8::is_ascii_digit)
        && matches!(octal.as_bytes()[0], b'2' | b'4' | b'6')
        && octal
            .as_bytes()
            .iter()
            .all(|digit| matches!(digit, b'0'..=b'7'))
}

fn is_linux_capability_token(text: &str) -> bool {
    let lowered = text
        .trim_matches(|ch| matches!(ch, '"' | '\'' | ';'))
        .to_ascii_lowercase();
    [
        "cap_setuid",
        "cap_setgid",
        "cap_sys_admin",
        "cap_sys_ptrace",
        "cap_net_admin",
        "cap_net_raw",
        "cap_dac_override",
        "cap_chown",
    ]
    .iter()
    .any(|cap| lowered.contains(cap))
}
