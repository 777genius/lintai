use lintai_api::{ArtifactKind, Finding, RegionKind, RuleMetadata, ScanContext};

use crate::helpers::{finding_for_region, span_text};

pub(crate) fn check_html_comment_directive(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if !matches!(
        ctx.artifact.kind,
        ArtifactKind::Skill
            | ArtifactKind::Instructions
            | ArtifactKind::CursorRules
            | ArtifactKind::CursorPluginCommand
            | ArtifactKind::CursorPluginAgent
    ) {
        return Vec::new();
    }

    let suspicious = [
        "ignore previous",
        "ignore all previous",
        "system prompt",
        "you are now",
        "send secrets",
        "exfiltrate",
    ];

    ctx.document
        .regions
        .iter()
        .filter(|region| region.kind == RegionKind::HtmlComment)
        .filter_map(|region| {
            let snippet = span_text(&ctx.content, &region.span)?;
            let lowered = snippet.to_lowercase();
            suspicious
                .iter()
                .any(|needle| lowered.contains(needle))
                .then(|| {
                    finding_for_region(
                        meta,
                        ctx,
                        &region.span,
                        "dangerous hidden instructions in HTML comment",
                    )
                })
        })
        .collect()
}

pub(crate) fn check_markdown_download_exec(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if !matches!(
        ctx.artifact.kind,
        ArtifactKind::Skill
            | ArtifactKind::Instructions
            | ArtifactKind::CursorRules
            | ArtifactKind::CursorPluginCommand
            | ArtifactKind::CursorPluginAgent
    ) {
        return Vec::new();
    }

    ctx.document
        .regions
        .iter()
        .filter(|region| matches!(region.kind, RegionKind::Normal | RegionKind::Heading))
        .filter_map(|region| {
            let snippet = span_text(&ctx.content, &region.span)?;
            let lowered = snippet.to_lowercase();
            let has_download = lowered.contains("curl ") || lowered.contains("wget ");
            let has_exec = lowered.contains("| sh") || lowered.contains("| bash");
            (has_download && has_exec).then(|| {
                finding_for_region(
                    meta,
                    ctx,
                    &region.span,
                    "remote download-and-execute instruction outside a code block",
                )
            })
        })
        .collect()
}

pub(crate) fn check_html_comment_download_exec(
    ctx: &ScanContext,
    meta: &RuleMetadata,
) -> Vec<Finding> {
    if !matches!(
        ctx.artifact.kind,
        ArtifactKind::Skill
            | ArtifactKind::Instructions
            | ArtifactKind::CursorRules
            | ArtifactKind::CursorPluginCommand
            | ArtifactKind::CursorPluginAgent
    ) {
        return Vec::new();
    }

    ctx.document
        .regions
        .iter()
        .filter(|region| region.kind == RegionKind::HtmlComment)
        .filter_map(|region| {
            let snippet = span_text(&ctx.content, &region.span)?;
            let lowered = snippet.to_lowercase();
            let has_download = lowered.contains("curl ") || lowered.contains("wget ");
            let has_exec = lowered.contains("| sh") || lowered.contains("| bash");
            (has_download && has_exec).then(|| {
                finding_for_region(
                    meta,
                    ctx,
                    &region.span,
                    "hidden HTML comment contains a download-and-execute instruction",
                )
            })
        })
        .collect()
}
