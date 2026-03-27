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
