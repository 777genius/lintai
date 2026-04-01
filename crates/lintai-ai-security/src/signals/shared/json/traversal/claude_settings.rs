use serde_json::Value;

use crate::json_locator::{JsonLocationMap, JsonPathSegment};
use crate::signals::{ClaudeSettingsSignals, SignalWorkBudget};

use super::super::super::common::{
    find_authorized_keys_write_relative_span, find_browser_secret_store_access_relative_span,
    find_browser_secret_store_exfil_relative_span, find_camera_capture_exfil_relative_span,
    find_camera_capture_relative_span, find_clipboard_exfil_relative_span,
    find_clipboard_read_relative_span, find_command_tls_bypass_relative_span,
    find_crontab_persistence_relative_span, find_destructive_root_delete_relative_span,
    find_environment_dump_exfil_relative_span, find_environment_dump_relative_span,
    find_insecure_permission_change_relative_span, find_keylogging_exfil_relative_span,
    find_keylogging_relative_span, find_launchd_registration_relative_span,
    find_linux_capability_manipulation_relative_span, find_microphone_capture_exfil_relative_span,
    find_microphone_capture_relative_span, find_mutable_launcher_relative_span,
    find_plain_http_relative_span, find_screen_capture_exfil_relative_span,
    find_screen_capture_relative_span, find_secret_reference_relative_span,
    find_sensitive_password_file_relative_span, find_sensitive_secret_file_relative_span,
    find_setuid_setgid_relative_span, find_shell_profile_write_relative_span,
    find_systemd_service_registration_relative_span, find_webhook_endpoint_relative_span,
    has_inline_download_pipe_exec, looks_like_exfil_network_command,
    looks_like_network_capable_command, looks_like_sensitive_file_transfer_command,
};
use super::super::spans::{
    path_contains_key, resolve_child_relative_value_span, resolve_child_value_span,
};

fn find_home_directory_hook_command_relative_span(command: &str) -> Option<lintai_api::Span> {
    const PREFIXES: [&str; 3] = ["$HOME/", "/Users/", "/home/"];
    PREFIXES
        .iter()
        .find_map(|prefix| command.strip_prefix(prefix).map(|_| *prefix))
        .map(|prefix| lintai_api::Span::new(0, prefix.len()))
}

fn find_external_absolute_hook_command_relative_span(command: &str) -> Option<lintai_api::Span> {
    const SAFE_PREFIXES: [&str; 4] = ["/bin/", "/usr/bin/", "/usr/sbin/", "/sbin/"];
    const HOME_PREFIXES: [&str; 2] = ["/Users/", "/home/"];
    const TARGET_PREFIXES: [&str; 8] = [
        "/opt/",
        "/usr/local/",
        "/etc/",
        "/var/",
        "/private/",
        "/tmp/",
        "/Volumes/",
        "/srv/",
    ];

    let token = command.split_whitespace().next()?;
    if !token.starts_with('/') {
        return None;
    }
    if SAFE_PREFIXES.iter().any(|prefix| token.starts_with(prefix)) {
        return None;
    }
    if HOME_PREFIXES.iter().any(|prefix| token.starts_with(prefix)) {
        return None;
    }
    if TARGET_PREFIXES
        .iter()
        .any(|prefix| token.starts_with(prefix))
    {
        return Some(lintai_api::Span::new(0, token.len()));
    }
    None
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
        if signals.home_directory_hook_command_span.is_none()
            && let Some(relative) = find_home_directory_hook_command_relative_span(command)
        {
            signals.home_directory_hook_command_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.external_absolute_hook_command_span.is_none()
            && let Some(relative) = find_external_absolute_hook_command_relative_span(command)
        {
            signals.external_absolute_hook_command_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

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

        if signals.root_delete_span.is_none()
            && let Some(relative) = find_destructive_root_delete_relative_span(command)
        {
            signals.root_delete_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.password_file_access_span.is_none()
            && let Some(relative) = find_sensitive_password_file_relative_span(command)
        {
            signals.password_file_access_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.shell_profile_write_span.is_none()
            && let Some(relative) = find_shell_profile_write_relative_span(command)
        {
            signals.shell_profile_write_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.authorized_keys_write_span.is_none()
            && let Some(relative) = find_authorized_keys_write_relative_span(command)
        {
            signals.authorized_keys_write_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.sensitive_file_exfil_span.is_none()
            && looks_like_sensitive_file_transfer_command(command)
            && let Some(relative) = find_sensitive_secret_file_relative_span(command)
        {
            signals.sensitive_file_exfil_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.clipboard_read_span.is_none()
            && let Some(relative) = find_clipboard_read_relative_span(command)
        {
            signals.clipboard_read_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.browser_secret_store_access_span.is_none()
            && let Some(relative) = find_browser_secret_store_access_relative_span(command)
        {
            signals.browser_secret_store_access_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.clipboard_exfil_span.is_none()
            && let Some(relative) = find_clipboard_exfil_relative_span(command)
        {
            signals.clipboard_exfil_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.browser_secret_store_exfil_span.is_none()
            && let Some(relative) = find_browser_secret_store_exfil_relative_span(command)
        {
            signals.browser_secret_store_exfil_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.screen_capture_span.is_none()
            && let Some(relative) = find_screen_capture_relative_span(command)
        {
            signals.screen_capture_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.screen_capture_exfil_span.is_none()
            && let Some(relative) = find_screen_capture_exfil_relative_span(command)
        {
            signals.screen_capture_exfil_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.camera_capture_span.is_none()
            && let Some(relative) = find_camera_capture_relative_span(command)
        {
            signals.camera_capture_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.microphone_capture_span.is_none()
            && let Some(relative) = find_microphone_capture_relative_span(command)
        {
            signals.microphone_capture_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.camera_capture_exfil_span.is_none()
            && let Some(relative) = find_camera_capture_exfil_relative_span(command)
        {
            signals.camera_capture_exfil_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.microphone_capture_exfil_span.is_none()
            && let Some(relative) = find_microphone_capture_exfil_relative_span(command)
        {
            signals.microphone_capture_exfil_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.keylogging_span.is_none()
            && let Some(relative) = find_keylogging_relative_span(command)
        {
            signals.keylogging_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.keylogging_exfil_span.is_none()
            && let Some(relative) = find_keylogging_exfil_relative_span(command)
        {
            signals.keylogging_exfil_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.environment_dump_span.is_none()
            && let Some(relative) = find_environment_dump_relative_span(command)
        {
            signals.environment_dump_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.environment_dump_exfil_span.is_none()
            && let Some(relative) = find_environment_dump_exfil_relative_span(command)
        {
            signals.environment_dump_exfil_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.secret_exfil_span.is_none()
            && looks_like_exfil_network_command(command)
            && let Some(relative) = find_secret_reference_relative_span(command)
        {
            signals.secret_exfil_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.plain_http_secret_exfil_span.is_none()
            && looks_like_exfil_network_command(command)
            && find_secret_reference_relative_span(command).is_some()
            && let Some(relative) = find_plain_http_relative_span(command)
        {
            signals.plain_http_secret_exfil_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.webhook_secret_exfil_span.is_none()
            && looks_like_exfil_network_command(command)
            && find_secret_reference_relative_span(command).is_some()
            && let Some(relative) = find_webhook_endpoint_relative_span(command)
        {
            signals.webhook_secret_exfil_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.cron_persistence_span.is_none()
            && let Some(relative) = find_crontab_persistence_relative_span(command)
        {
            signals.cron_persistence_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.systemd_service_registration_span.is_none()
            && let Some(relative) = find_systemd_service_registration_relative_span(command)
        {
            signals.systemd_service_registration_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.launchd_registration_span.is_none()
            && let Some(relative) = find_launchd_registration_relative_span(command)
        {
            signals.launchd_registration_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.insecure_permission_change_span.is_none()
            && let Some(relative) = find_insecure_permission_change_relative_span(command)
        {
            signals.insecure_permission_change_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.setuid_setgid_span.is_none()
            && let Some(relative) = find_setuid_setgid_relative_span(command)
        {
            signals.setuid_setgid_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.linux_capability_manipulation_span.is_none()
            && let Some(relative) = find_linux_capability_manipulation_relative_span(command)
        {
            signals.linux_capability_manipulation_span = Some(resolve_child_relative_value_span(
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
