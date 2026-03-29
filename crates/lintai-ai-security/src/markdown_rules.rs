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

pub(crate) fn check_markdown_private_key_pem(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.private_key_spans.as_slice())
            .unwrap_or(&[]),
        "markdown contains committed private key material",
    )
}

pub(crate) fn check_markdown_fenced_pipe_shell(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.fenced_pipe_shell_spans.as_slice())
            .unwrap_or(&[]),
        "fenced shell example pipes remote content directly into a shell",
    )
}

pub(crate) fn check_markdown_metadata_service_access(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.metadata_service_access_spans.as_slice())
            .unwrap_or(&[]),
        "markdown example targets a cloud metadata service literal",
    )
}

pub(crate) fn check_markdown_mutable_mcp_launcher(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.mutable_mcp_launcher_spans.as_slice())
            .unwrap_or(&[]),
        "markdown example launches MCP through a mutable package runner",
    )
}

pub(crate) fn check_markdown_mutable_docker_image(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.mutable_docker_image_spans.as_slice())
            .unwrap_or(&[]),
        "markdown docker example uses a mutable registry image",
    )
}

pub(crate) fn check_markdown_docker_host_escape(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.docker_host_escape_spans.as_slice())
            .unwrap_or(&[]),
        "markdown docker example uses a host-escape or privileged runtime pattern",
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
