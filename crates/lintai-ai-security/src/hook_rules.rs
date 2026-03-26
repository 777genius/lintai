use lintai_api::{ArtifactKind, Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;

pub(crate) fn check_hook_download_exec(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::CursorHookScript {
        return Vec::new();
    }

    let Some(span) = first_matching_line_span(&ctx.content, |line| {
        let lowered = line.to_lowercase();
        let has_download = lowered.contains("curl ") || lowered.contains("wget ");
        let has_pipe_exec = lowered.contains("| sh") || lowered.contains("| bash");
        let has_chmod_exec = lowered.contains("chmod +x") && lowered.contains("./");
        has_download && (has_pipe_exec || has_chmod_exec)
    }) else {
        return Vec::new();
    };

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "hook script downloads remote code and executes it",
    )]
}

pub(crate) fn check_hook_secret_exfil(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::CursorHookScript {
        return Vec::new();
    }

    let secret_markers = [
        "openai_api_key",
        "anthropic_api_key",
        "aws_secret_access_key",
        "authorization:",
        "bearer ",
    ];

    let Some(span) = first_matching_line_span(&ctx.content, |line| {
        let lowered = line.to_lowercase();
        let has_network = lowered.contains("curl ") || lowered.contains("wget ");
        has_network && secret_markers.iter().any(|marker| lowered.contains(marker))
    }) else {
        return Vec::new();
    };

    vec![finding_for_region(
        meta,
        ctx,
        &span,
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
    let span = find_first_substring_span(&lowered, "http://")
        .unwrap_or_else(|| Span::new(0, ctx.content.len()));

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "hook script sends secret material to an insecure http:// endpoint",
    )]
}

fn first_matching_line_span(content: &str, predicate: impl Fn(&str) -> bool) -> Option<Span> {
    let mut start = 0usize;
    for segment in content.split_inclusive('\n') {
        let line = segment.strip_suffix('\n').unwrap_or(segment);
        if predicate(line) {
            return Some(Span::new(start, start + line.len()));
        }
        start += segment.len();
    }

    if start < content.len() {
        let line = &content[start..];
        if predicate(line) {
            return Some(Span::new(start, content.len()));
        }
    }

    None
}

fn find_first_substring_span(content: &str, needle: &str) -> Option<Span> {
    content
        .find(needle)
        .map(|start| Span::new(start, start + needle.len()))
}
