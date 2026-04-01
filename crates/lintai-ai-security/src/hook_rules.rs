use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_hook_download_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.download_exec_span.clone()),
        "hook script downloads remote code and executes it",
    )
}

pub(crate) fn check_hook_secret_exfil(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.secret_exfil_span.clone()),
        "hook script appears to send secrets over the network",
    )
}

pub(crate) fn check_hook_base64_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.base64_exec_span.clone()),
        "hook script decodes a base64 payload and executes it",
    )
}

pub(crate) fn check_hook_root_delete(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.root_delete_span.clone()),
        "hook script attempts destructive root deletion",
    )
}

pub(crate) fn check_hook_password_file_access(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.password_file_access_span.clone()),
        "hook script accesses a sensitive system password file",
    )
}

pub(crate) fn check_hook_shell_profile_write(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.shell_profile_write_span.clone()),
        "hook script writes to a shell profile startup file",
    )
}

pub(crate) fn check_hook_authorized_keys_write(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.authorized_keys_write_span.clone()),
        "hook script writes to SSH authorized_keys",
    )
}

pub(crate) fn check_hook_sensitive_file_exfil(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.sensitive_file_exfil_span.clone()),
        "hook script transfers a sensitive credential file to a remote destination",
    )
}

pub(crate) fn check_hook_clipboard_read(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.clipboard_read_span.clone()),
        "hook script reads clipboard contents",
    )
}

pub(crate) fn check_hook_browser_secret_store_access(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.browser_secret_store_access_span.clone()),
        "hook script accesses browser credential or cookie store data",
    )
}

pub(crate) fn check_hook_clipboard_exfil(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.clipboard_exfil_span.clone()),
        "hook script exfiltrates clipboard contents over the network",
    )
}

pub(crate) fn check_hook_browser_secret_store_exfil(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.browser_secret_store_exfil_span.clone()),
        "hook script exfiltrates browser credential or cookie store data",
    )
}

pub(crate) fn check_hook_screen_capture(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.screen_capture_span.clone()),
        "hook script captures a screenshot or desktop image",
    )
}

pub(crate) fn check_hook_screen_capture_exfil(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.screen_capture_exfil_span.clone()),
        "hook script captures and exfiltrates a screenshot or desktop image",
    )
}

pub(crate) fn check_hook_camera_capture(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.camera_capture_span.clone()),
        "hook script captures a camera image or webcam stream",
    )
}

pub(crate) fn check_hook_microphone_capture(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.microphone_capture_span.clone()),
        "hook script records microphone or audio input",
    )
}

pub(crate) fn check_hook_camera_capture_exfil(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.camera_capture_exfil_span.clone()),
        "hook script captures and exfiltrates camera or webcam data",
    )
}

pub(crate) fn check_hook_microphone_capture_exfil(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.microphone_capture_exfil_span.clone()),
        "hook script records and exfiltrates microphone or audio input",
    )
}

pub(crate) fn check_hook_keylogging(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.keylogging_span.clone()),
        "hook script captures keystrokes or keyboard input",
    )
}

pub(crate) fn check_hook_keylogging_exfil(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.keylogging_exfil_span.clone()),
        "hook script captures and exfiltrates keystrokes or keyboard input",
    )
}

pub(crate) fn check_hook_environment_dump(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.environment_dump_span.clone()),
        "hook script dumps environment variables or shell state",
    )
}

pub(crate) fn check_hook_environment_dump_exfil(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.environment_dump_exfil_span.clone()),
        "hook script dumps and exfiltrates environment variables or shell state",
    )
}

pub(crate) fn check_hook_cron_persistence(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.cron_persistence_span.clone()),
        "hook script manipulates cron persistence",
    )
}

pub(crate) fn check_hook_systemd_service_registration(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.systemd_service_registration_span.clone()),
        "hook script registers a systemd service or unit for persistence",
    )
}

pub(crate) fn check_hook_launchd_registration(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.launchd_registration_span.clone()),
        "hook script registers a launchd plist for persistence",
    )
}

pub(crate) fn check_hook_insecure_permission_change(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.insecure_permission_change_span.clone()),
        "hook script performs an insecure permission change",
    )
}

pub(crate) fn check_hook_setuid_setgid(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.setuid_setgid_span.clone()),
        "hook script manipulates setuid or setgid permissions",
    )
}

pub(crate) fn check_hook_linux_capability_manipulation(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.linux_capability_manipulation_span.clone()),
        "hook script manipulates Linux capabilities",
    )
}

pub(crate) fn check_hook_plain_http_exfil(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.plain_http_secret_exfil_span.clone()),
        "hook script sends secret material to an insecure http:// endpoint",
    )
}

pub(crate) fn check_hook_webhook_secret_exfil(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.webhook_secret_exfil_span.clone()),
        "hook script posts secret material to a webhook endpoint",
    )
}

pub(crate) fn check_hook_tls_bypass(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.tls_bypass_span.clone()),
        "hook script disables TLS or certificate verification for a network call",
    )
}

pub(crate) fn check_hook_static_auth_exposure(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .hook()
            .and_then(|signals| signals.static_auth_exposure_span.clone()),
        "hook script embeds static authentication material in a network call",
    )
}

fn finding_from_span(
    ctx: &ScanContext,
    meta: RuleMetadata,
    span: Option<Span>,
    message: &'static str,
) -> Vec<Finding> {
    span.into_iter()
        .map(|span| finding_for_region(&meta, ctx, &span, message))
        .collect()
}
