use crate::json_locator::{JsonLocationMap, JsonPathSegment};
use crate::signals::JsonSignals;

use super::super::super::common::{
    find_authorized_keys_write_relative_span, find_browser_secret_store_access_relative_span,
    find_camera_capture_relative_span, find_clipboard_read_relative_span,
    find_command_tls_bypass_relative_span, find_crontab_persistence_relative_span,
    find_destructive_root_delete_relative_span, find_environment_dump_relative_span,
    find_insecure_permission_change_relative_span, find_keylogging_relative_span,
    find_launchd_registration_relative_span, find_linux_capability_manipulation_relative_span,
    find_microphone_capture_relative_span, find_mutable_launcher_relative_span,
    find_plain_http_relative_span, find_screen_capture_relative_span,
    find_secret_reference_relative_span, find_sensitive_password_file_relative_span,
    find_sensitive_secret_file_relative_span, find_setuid_setgid_relative_span,
    find_shell_profile_write_relative_span, find_systemd_service_registration_relative_span,
    find_webhook_endpoint_relative_span, has_inline_download_pipe_exec,
    looks_like_exfil_network_command, looks_like_network_capable_command,
    looks_like_sensitive_file_transfer_command,
};
use super::super::spans::{resolve_child_relative_value_span, resolve_child_value_span};

pub(super) fn apply_plugin_hook_command_rules(
    path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    command: Option<&str>,
    signals: &mut JsonSignals,
) {
    if !path.iter().any(|segment| {
        matches!(
            segment,
            JsonPathSegment::Key(key) if key.eq_ignore_ascii_case("hooks")
        )
    }) {
        return;
    }

    macro_rules! assign_relative_span {
        ($field:ident, $finder:path) => {
            if signals.$field.is_none()
                && let Some(command) = command
                && let Some(relative) = $finder(command)
            {
                signals.$field = Some(resolve_child_relative_value_span(
                    path,
                    "command",
                    "command",
                    relative,
                    locator,
                    fallback_len,
                ));
            }
        };
    }

    macro_rules! assign_relative_span_if {
        ($field:ident, $condition:expr, $finder:path) => {
            if signals.$field.is_none()
                && let Some(command) = command
                && $condition(command)
                && let Some(relative) = $finder(command)
            {
                signals.$field = Some(resolve_child_relative_value_span(
                    path,
                    "command",
                    "command",
                    relative,
                    locator,
                    fallback_len,
                ));
            }
        };
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

    assign_relative_span_if!(
        network_tls_bypass_plugin_hook_span,
        |command: &str| looks_like_network_capable_command(&command.to_ascii_lowercase()),
        find_command_tls_bypass_relative_span
    );
    assign_relative_span!(
        root_delete_plugin_hook_span,
        find_destructive_root_delete_relative_span
    );
    assign_relative_span!(
        password_file_access_plugin_hook_span,
        find_sensitive_password_file_relative_span
    );
    assign_relative_span!(
        shell_profile_write_plugin_hook_span,
        find_shell_profile_write_relative_span
    );
    assign_relative_span!(
        authorized_keys_write_plugin_hook_span,
        find_authorized_keys_write_relative_span
    );
    assign_relative_span_if!(
        sensitive_file_exfil_plugin_hook_span,
        looks_like_sensitive_file_transfer_command,
        find_sensitive_secret_file_relative_span
    );
    assign_relative_span!(
        clipboard_read_plugin_hook_span,
        find_clipboard_read_relative_span
    );
    assign_relative_span!(
        browser_secret_store_access_plugin_hook_span,
        find_browser_secret_store_access_relative_span
    );
    assign_relative_span!(
        screen_capture_plugin_hook_span,
        find_screen_capture_relative_span
    );
    assign_relative_span!(
        camera_capture_plugin_hook_span,
        find_camera_capture_relative_span
    );
    assign_relative_span!(
        microphone_capture_plugin_hook_span,
        find_microphone_capture_relative_span
    );
    assign_relative_span!(keylogging_plugin_hook_span, find_keylogging_relative_span);
    assign_relative_span!(
        environment_dump_plugin_hook_span,
        find_environment_dump_relative_span
    );
    assign_relative_span_if!(
        secret_exfil_plugin_hook_span,
        looks_like_exfil_network_command,
        find_secret_reference_relative_span
    );
    assign_relative_span_if!(
        clipboard_exfil_plugin_hook_span,
        looks_like_exfil_network_command,
        find_clipboard_read_relative_span
    );
    assign_relative_span_if!(
        browser_secret_store_exfil_plugin_hook_span,
        looks_like_exfil_network_command,
        find_browser_secret_store_access_relative_span
    );
    assign_relative_span_if!(
        screen_capture_exfil_plugin_hook_span,
        looks_like_exfil_network_command,
        find_screen_capture_relative_span
    );
    assign_relative_span_if!(
        camera_capture_exfil_plugin_hook_span,
        looks_like_exfil_network_command,
        find_camera_capture_relative_span
    );
    assign_relative_span_if!(
        microphone_capture_exfil_plugin_hook_span,
        looks_like_exfil_network_command,
        find_microphone_capture_relative_span
    );
    assign_relative_span_if!(
        keylogging_exfil_plugin_hook_span,
        looks_like_exfil_network_command,
        find_keylogging_relative_span
    );
    assign_relative_span_if!(
        environment_dump_exfil_plugin_hook_span,
        looks_like_exfil_network_command,
        find_environment_dump_relative_span
    );

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

    assign_relative_span!(
        cron_persistence_plugin_hook_span,
        find_crontab_persistence_relative_span
    );
    assign_relative_span!(
        systemd_service_registration_plugin_hook_span,
        find_systemd_service_registration_relative_span
    );
    assign_relative_span!(
        launchd_registration_plugin_hook_span,
        find_launchd_registration_relative_span
    );
    assign_relative_span!(
        insecure_permission_change_plugin_hook_span,
        find_insecure_permission_change_relative_span
    );
    assign_relative_span!(
        setuid_setgid_plugin_hook_span,
        find_setuid_setgid_relative_span
    );
    assign_relative_span!(
        linux_capability_manipulation_plugin_hook_span,
        find_linux_capability_manipulation_relative_span
    );
}
