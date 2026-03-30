use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_claude_settings_mutable_launcher(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.mutable_launcher_span.clone()),
        "Claude settings command hook uses a mutable package launcher",
    )
}

pub(crate) fn check_claude_settings_missing_schema(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.missing_schema_span.clone()),
        "Claude settings file is missing a top-level `$schema` reference",
    )
}

pub(crate) fn check_claude_settings_bypass_permissions(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.bypass_permissions_span.clone()),
        "Claude settings set `permissions.defaultMode` to `bypassPermissions` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_insecure_http_hook_url(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.insecure_http_hook_url_span.clone()),
        "Claude settings allow non-HTTPS HTTP hook URLs in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_dangerous_http_hook_host(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.dangerous_http_hook_host_span.clone()),
        "Claude settings allow dangerous host literals in `allowedHttpHookUrls`",
    )
}

pub(crate) fn check_claude_settings_bash_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.bash_wildcard_span.clone()),
        "Claude settings permissions allow `Bash(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_webfetch_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.webfetch_wildcard_span.clone()),
        "Claude settings permissions allow `WebFetch(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_write_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.write_wildcard_span.clone()),
        "Claude settings permissions allow `Write(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_read_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.read_wildcard_span.clone()),
        "Claude settings permissions allow `Read(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_edit_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.edit_wildcard_span.clone()),
        "Claude settings permissions allow `Edit(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_websearch_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.websearch_wildcard_span.clone()),
        "Claude settings permissions allow `WebSearch(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_glob_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.glob_wildcard_span.clone()),
        "Claude settings permissions allow `Glob(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_home_directory_hook_command(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.home_directory_hook_command_span.clone()),
        "Claude settings hook command uses a home-directory path in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_external_absolute_hook_command(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.external_absolute_hook_command_span.clone()),
        "Claude settings hook command uses a repo-external absolute path in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_inline_download_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.inline_download_exec_span.clone()),
        "Claude settings command hook downloads remote content and pipes it directly into a shell",
    )
}

pub(crate) fn check_claude_settings_network_tls_bypass(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.network_tls_bypass_span.clone()),
        "Claude settings command hook disables TLS verification in a network-capable execution path",
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
