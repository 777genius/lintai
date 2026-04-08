use lintai_api::Span;

use crate::helpers::find_url_userinfo_span;

use super::super::{HookSignals, SignalWorkBudget};
use super::common::{
    find_authorized_keys_write_relative_span, find_browser_secret_store_access_relative_span,
    find_browser_secret_store_exfil_relative_span, find_camera_capture_exfil_relative_span,
    find_camera_capture_relative_span, find_clipboard_exfil_relative_span,
    find_clipboard_read_relative_span, find_crontab_persistence_relative_span,
    find_destructive_root_delete_relative_span, find_environment_dump_exfil_relative_span,
    find_environment_dump_relative_span, find_insecure_permission_change_relative_span,
    find_keylogging_exfil_relative_span, find_keylogging_relative_span,
    find_launchd_registration_relative_span, find_linux_capability_manipulation_relative_span,
    find_literal_value_after_prefixes_case_insensitive,
    find_microphone_capture_exfil_relative_span, find_microphone_capture_relative_span,
    find_plain_http_relative_span, find_screen_capture_exfil_relative_span,
    find_screen_capture_relative_span, find_secret_reference_relative_span,
    find_sensitive_password_file_relative_span, find_sensitive_secret_file_relative_span,
    find_setuid_setgid_relative_span, find_shell_profile_write_relative_span,
    find_systemd_service_registration_relative_span, find_webhook_endpoint_relative_span,
    has_download_exec, looks_like_exfil_network_command,
    looks_like_sensitive_file_transfer_command,
};

#[derive(Clone, Copy)]
pub(crate) struct HookToken<'a> {
    pub(crate) text: &'a str,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct McpCommandSignalSpan {
    pub(crate) inline_download_exec: Option<Span>,
    pub(crate) network_tls_bypass: Option<Span>,
    pub(crate) root_delete: Option<Span>,
    pub(crate) password_file_access: Option<Span>,
    pub(crate) shell_profile_write: Option<Span>,
    pub(crate) authorized_keys_write: Option<Span>,
    pub(crate) sensitive_file_exfil: Option<Span>,
    pub(crate) clipboard_read: Option<Span>,
    pub(crate) browser_secret_store_access: Option<Span>,
    pub(crate) clipboard_exfil: Option<Span>,
    pub(crate) browser_secret_store_exfil: Option<Span>,
    pub(crate) screen_capture: Option<Span>,
    pub(crate) screen_capture_exfil: Option<Span>,
    pub(crate) camera_capture: Option<Span>,
    pub(crate) microphone_capture: Option<Span>,
    pub(crate) camera_capture_exfil: Option<Span>,
    pub(crate) microphone_capture_exfil: Option<Span>,
    pub(crate) keylogging: Option<Span>,
    pub(crate) keylogging_exfil: Option<Span>,
    pub(crate) environment_dump: Option<Span>,
    pub(crate) environment_dump_exfil: Option<Span>,
    pub(crate) secret_exfil: Option<Span>,
    pub(crate) plain_http_secret_exfil: Option<Span>,
    pub(crate) webhook_secret_exfil: Option<Span>,
    pub(crate) cron_persistence: Option<Span>,
    pub(crate) systemd_service_registration: Option<Span>,
    pub(crate) launchd_registration: Option<Span>,
    pub(crate) insecure_permission_change: Option<Span>,
    pub(crate) setuid_setgid: Option<Span>,
    pub(crate) linux_capability_manipulation: Option<Span>,
    pub(crate) mutable_docker_image: Option<Span>,
    pub(crate) mutable_docker_pull: Option<Span>,
    pub(crate) sensitive_docker_mount: Option<Span>,
    pub(crate) dangerous_docker_flag: Option<Span>,
}

pub(crate) fn collect_hook_line(
    signals: &mut HookSignals,
    line: &str,
    offset: usize,
    metrics: &mut SignalWorkBudget,
) {
    metrics.hook_lines_visited += 1;
    if line.trim_start().starts_with('#') {
        return;
    }

    let line_span = Span::new(offset, offset + line.len());
    signals.non_comment_line_spans.push(line_span.clone());

    let lowered = line.to_ascii_lowercase();
    let tokens = shell_tokens(line);
    metrics.hook_tokens_visited += tokens.len();

    if signals.download_exec_span.is_none() && has_download_exec(&lowered) {
        signals.download_exec_span = Some(line_span.clone());
    }

    if signals.base64_exec_span.is_none() && has_base64_exec(&lowered) {
        signals.base64_exec_span = Some(line_span.clone());
    }

    if signals.root_delete_span.is_none()
        && let Some(relative) = find_destructive_root_delete_relative_span(line)
    {
        signals.root_delete_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.password_file_access_span.is_none()
        && let Some(relative) = find_sensitive_password_file_relative_span(line)
    {
        signals.password_file_access_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.shell_profile_write_span.is_none()
        && let Some(relative) = find_shell_profile_write_relative_span(line)
    {
        signals.shell_profile_write_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.authorized_keys_write_span.is_none()
        && let Some(relative) = find_authorized_keys_write_relative_span(line)
    {
        signals.authorized_keys_write_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.cron_persistence_span.is_none()
        && let Some(relative) = find_crontab_persistence_relative_span(line)
    {
        signals.cron_persistence_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.systemd_service_registration_span.is_none()
        && let Some(relative) = find_systemd_service_registration_relative_span(line)
    {
        signals.systemd_service_registration_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.launchd_registration_span.is_none()
        && let Some(relative) = find_launchd_registration_relative_span(line)
    {
        signals.launchd_registration_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.insecure_permission_change_span.is_none()
        && let Some(relative) = find_insecure_permission_change_relative_span(line)
    {
        signals.insecure_permission_change_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.setuid_setgid_span.is_none()
        && let Some(relative) = find_setuid_setgid_relative_span(line)
    {
        signals.setuid_setgid_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.linux_capability_manipulation_span.is_none()
        && let Some(relative) = find_linux_capability_manipulation_relative_span(line)
    {
        signals.linux_capability_manipulation_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.sensitive_file_exfil_span.is_none()
        && looks_like_sensitive_file_transfer_command(line)
        && let Some(relative) = find_sensitive_secret_file_relative_span(line)
    {
        signals.sensitive_file_exfil_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.clipboard_read_span.is_none()
        && let Some(relative) = find_clipboard_read_relative_span(line)
    {
        signals.clipboard_read_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.browser_secret_store_access_span.is_none()
        && let Some(relative) = find_browser_secret_store_access_relative_span(line)
    {
        signals.browser_secret_store_access_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.clipboard_exfil_span.is_none()
        && let Some(relative) = find_clipboard_exfil_relative_span(line)
    {
        signals.clipboard_exfil_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.browser_secret_store_exfil_span.is_none()
        && let Some(relative) = find_browser_secret_store_exfil_relative_span(line)
    {
        signals.browser_secret_store_exfil_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.screen_capture_span.is_none()
        && let Some(relative) = find_screen_capture_relative_span(line)
    {
        signals.screen_capture_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.screen_capture_exfil_span.is_none()
        && let Some(relative) = find_screen_capture_exfil_relative_span(line)
    {
        signals.screen_capture_exfil_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.camera_capture_span.is_none()
        && let Some(relative) = find_camera_capture_relative_span(line)
    {
        signals.camera_capture_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.microphone_capture_span.is_none()
        && let Some(relative) = find_microphone_capture_relative_span(line)
    {
        signals.microphone_capture_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.camera_capture_exfil_span.is_none()
        && let Some(relative) = find_camera_capture_exfil_relative_span(line)
    {
        signals.camera_capture_exfil_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.microphone_capture_exfil_span.is_none()
        && let Some(relative) = find_microphone_capture_exfil_relative_span(line)
    {
        signals.microphone_capture_exfil_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.keylogging_span.is_none()
        && let Some(relative) = find_keylogging_relative_span(line)
    {
        signals.keylogging_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.keylogging_exfil_span.is_none()
        && let Some(relative) = find_keylogging_exfil_relative_span(line)
    {
        signals.keylogging_exfil_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.environment_dump_span.is_none()
        && let Some(relative) = find_environment_dump_relative_span(line)
    {
        signals.environment_dump_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.environment_dump_exfil_span.is_none()
        && let Some(relative) = find_environment_dump_exfil_relative_span(line)
    {
        signals.environment_dump_exfil_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.secret_exfil_span.is_none()
        && looks_like_exfil_network_command(line)
        && find_secret_reference_relative_span(line).is_some()
    {
        signals.secret_exfil_span = Some(line_span.clone());
    }

    if signals.plain_http_secret_exfil_span.is_none()
        && looks_like_exfil_network_command(line)
        && find_secret_reference_relative_span(line).is_some()
        && let Some(relative) = find_plain_http_relative_span(line)
    {
        signals.plain_http_secret_exfil_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.webhook_secret_exfil_span.is_none()
        && looks_like_exfil_network_command(line)
        && find_secret_reference_relative_span(line).is_some()
        && let Some(relative) = find_webhook_endpoint_relative_span(line)
    {
        signals.webhook_secret_exfil_span = Some(Span::new(
            offset + relative.start_byte,
            offset + relative.end_byte,
        ));
    }

    if signals.static_auth_exposure_span.is_none() {
        if let Some(relative) = find_url_userinfo_span(line) {
            signals.static_auth_exposure_span = Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        } else if lowered.contains("curl ")
            && let Some(relative) = find_literal_value_after_prefixes_case_insensitive(
                line,
                &["authorization: bearer ", "authorization: basic "],
            )
        {
            signals.static_auth_exposure_span = Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
    }

    if signals.tls_bypass_span.is_none() {
        let has_curl = tokens.iter().any(|token| token.text == "curl");
        let has_wget = tokens.iter().any(|token| token.text == "wget");
        let has_network_context = has_curl
            || has_wget
            || tokens
                .iter()
                .any(|token| token.text.contains("http://") || token.text.contains("https://"));

        if has_curl
            && let Some(token) = tokens
                .iter()
                .find(|token| matches!(token.text, "-k" | "--insecure"))
        {
            signals.tls_bypass_span = Some(Span::new(offset + token.start, offset + token.end));
            return;
        }

        if has_wget
            && let Some(token) = tokens
                .iter()
                .find(|token| token.text == "--no-check-certificate")
        {
            signals.tls_bypass_span = Some(Span::new(offset + token.start, offset + token.end));
            return;
        }

        if has_network_context
            && let Some(token) = tokens
                .iter()
                .find(|token| token.text == "NODE_TLS_REJECT_UNAUTHORIZED=0")
        {
            signals.tls_bypass_span = Some(Span::new(offset + token.start, offset + token.end));
        }
    }
}

pub(crate) fn has_base64_exec(lowered: &str) -> bool {
    let has_base64_decode = lowered.contains("base64 -d") || lowered.contains("base64 --decode");
    let has_exec = lowered.contains("| sh")
        || lowered.contains("| bash")
        || lowered.contains("sh -c")
        || lowered.contains("bash -c");
    has_base64_decode && has_exec
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
