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
