use lintai_api::{ArtifactKind, Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;

pub(crate) fn check_hook_download_exec(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::CursorHookScript {
        return Vec::new();
    }

    let lowered = ctx.content.to_lowercase();
    let has_download = lowered.contains("curl ") || lowered.contains("wget ");
    let has_pipe_exec = lowered.contains("| sh") || lowered.contains("| bash");
    let has_chmod_exec = lowered.contains("chmod +x") && lowered.contains("./");
    if !(has_download && (has_pipe_exec || has_chmod_exec)) {
        return Vec::new();
    }

    vec![finding_for_region(
        meta,
        ctx,
        &Span::new(0, ctx.content.len()),
        "hook script downloads remote code and executes it",
    )]
}

pub(crate) fn check_hook_secret_exfil(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::CursorHookScript {
        return Vec::new();
    }

    let lowered = ctx.content.to_lowercase();
    let has_network = lowered.contains("curl ") || lowered.contains("wget ");
    let secret_markers = [
        "openai_api_key",
        "anthropic_api_key",
        "aws_secret_access_key",
        "authorization:",
        "bearer ",
    ];

    if !(has_network && secret_markers.iter().any(|marker| lowered.contains(marker))) {
        return Vec::new();
    }

    vec![finding_for_region(
        meta,
        ctx,
        &Span::new(0, ctx.content.len()),
        "hook script appears to send secrets over the network",
    )]
}

pub(crate) fn check_hook_plain_http_exfil(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::CursorHookScript {
        return Vec::new();
    }

    let lowered = ctx.content.to_lowercase();
    let has_plain_http = lowered.contains("http://");
    let secret_markers = [
        "openai_api_key",
        "anthropic_api_key",
        "aws_secret_access_key",
        "authorization:",
        "bearer ",
    ];

    if !(has_plain_http && secret_markers.iter().any(|marker| lowered.contains(marker))) {
        return Vec::new();
    }

    vec![finding_for_region(
        meta,
        ctx,
        &Span::new(0, ctx.content.len()),
        "hook script sends secret material to an insecure http:// endpoint",
    )]
}
