use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_html_comment_directive(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.directive_comment_spans.as_slice())
            .unwrap_or(&[]),
        "dangerous hidden instructions in HTML comment",
    )
}

pub(crate) fn check_markdown_download_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.prose_download_exec_spans.as_slice())
            .unwrap_or(&[]),
        "remote download-and-execute instruction outside a code block",
    )
}

pub(crate) fn check_markdown_base64_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.prose_base64_exec_spans.as_slice())
            .unwrap_or(&[]),
        "base64-decoded payload is executed outside a code block",
    )
}

pub(crate) fn check_markdown_path_traversal(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.prose_path_traversal_spans.as_slice())
            .unwrap_or(&[]),
        "instruction references parent-directory traversal for file access",
    )
}

pub(crate) fn check_html_comment_download_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.comment_download_exec_spans.as_slice())
            .unwrap_or(&[]),
        "hidden HTML comment contains a download-and-execute instruction",
    )
}

fn findings_for_spans(
    ctx: &ScanContext,
    meta: RuleMetadata,
    spans: &[Span],
    message: &'static str,
) -> Vec<Finding> {
    spans
        .iter()
        .map(|span| finding_for_region(&meta, ctx, span, message))
        .collect()
}
