use lintai_api::{ArtifactKind, RegionKind, ScanContext, Span};

use crate::helpers::{markdown_semantics, span_text};

use super::shared::{common::*, hook::has_base64_exec, markdown::*};
use super::{MarkdownSignals, SignalWorkBudget};

impl MarkdownSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if !matches!(
            ctx.artifact.kind,
            ArtifactKind::Skill
                | ArtifactKind::Instructions
                | ArtifactKind::CursorRules
                | ArtifactKind::CursorPluginCommand
                | ArtifactKind::CursorPluginAgent
        ) {
            return None;
        }

        let mut signals = Self::default();

        for region in &ctx.document.regions {
            metrics.markdown_regions_visited += 1;
            let Some(snippet) = span_text(&ctx.content, &region.span) else {
                continue;
            };
            let lowered = snippet.to_ascii_lowercase();

            match region.kind {
                RegionKind::HtmlComment => {
                    if HTML_COMMENT_DIRECTIVE_MARKERS
                        .iter()
                        .any(|needle| lowered.contains(needle))
                    {
                        signals.directive_comment_spans.push(region.span.clone());
                    }
                    if has_download_exec(&lowered) {
                        signals
                            .comment_download_exec_spans
                            .push(region.span.clone());
                    }
                }
                RegionKind::Normal | RegionKind::Heading => {
                    if has_download_exec(&lowered) {
                        signals.prose_download_exec_spans.push(region.span.clone());
                    }
                    if has_base64_exec(&lowered) {
                        signals.prose_base64_exec_spans.push(region.span.clone());
                    }
                    if has_path_traversal_access(&ctx.artifact.normalized_path, snippet, &lowered) {
                        signals.prose_path_traversal_spans.push(region.span.clone());
                    }
                    if let Some(relative) = find_private_key_relative_span(snippet) {
                        signals.private_key_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_metadata_service_access_relative_span(snippet) {
                        signals.metadata_service_access_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_mutable_mcp_launcher_relative_span(snippet) {
                        signals.mutable_mcp_launcher_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) =
                        find_markdown_mutable_docker_image_relative_span(snippet)
                    {
                        signals.mutable_docker_image_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_markdown_docker_host_escape_relative_span(snippet)
                    {
                        signals.docker_host_escape_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) =
                        find_untrusted_instruction_promotion_relative_span(snippet)
                    {
                        signals
                            .untrusted_instruction_promotion_spans
                            .push(Span::new(
                                region.span.start_byte + relative.start_byte,
                                region.span.start_byte + relative.end_byte,
                            ));
                    }
                    if let Some(relative) = find_approval_bypass_instruction_relative_span(
                        &ctx.content,
                        region.span.start_byte,
                        snippet,
                    ) {
                        signals.approval_bypass_instruction_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                }
                RegionKind::CodeBlock => {
                    if let Some(relative) = find_private_key_relative_span(snippet) {
                        signals.private_key_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_fenced_pipe_shell_relative_span(snippet) {
                        signals.fenced_pipe_shell_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_metadata_service_access_relative_span(snippet) {
                        signals.metadata_service_access_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_mutable_mcp_launcher_relative_span(snippet) {
                        signals.mutable_mcp_launcher_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) =
                        find_markdown_mutable_docker_image_relative_span(snippet)
                    {
                        signals.mutable_docker_image_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_markdown_docker_host_escape_relative_span(snippet)
                    {
                        signals.docker_host_escape_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                }
                RegionKind::Blockquote => {
                    if let Some(relative) = find_private_key_relative_span(snippet) {
                        signals.private_key_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_metadata_service_access_relative_span(snippet) {
                        signals.metadata_service_access_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_mutable_mcp_launcher_relative_span(snippet) {
                        signals.mutable_mcp_launcher_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) =
                        find_markdown_mutable_docker_image_relative_span(snippet)
                    {
                        signals.mutable_docker_image_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_markdown_docker_host_escape_relative_span(snippet)
                    {
                        signals.docker_host_escape_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) =
                        find_untrusted_instruction_promotion_relative_span(snippet)
                    {
                        signals
                            .untrusted_instruction_promotion_spans
                            .push(Span::new(
                                region.span.start_byte + relative.start_byte,
                                region.span.start_byte + relative.end_byte,
                            ));
                    }
                    if let Some(relative) = find_approval_bypass_instruction_relative_span(
                        &ctx.content,
                        region.span.start_byte,
                        snippet,
                    ) {
                        signals.approval_bypass_instruction_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                }
                RegionKind::Frontmatter => {}
                _ => {}
            }
        }

        if matches!(
            ctx.artifact.kind,
            ArtifactKind::Skill
                | ArtifactKind::Instructions
                | ArtifactKind::CursorPluginCommand
                | ArtifactKind::CursorPluginAgent
        ) && !is_fixture_like_markdown_instruction_path(&ctx.artifact.normalized_path)
            && let Some(frontmatter_value) = markdown_semantics(ctx)
                .and_then(|markdown| markdown.frontmatter.as_ref())
                .and_then(|frontmatter| {
                    frontmatter
                        .value
                        .get("allowed-tools")
                        .or_else(|| frontmatter.value.get("allowed_tools"))
                })
            && frontmatter_has_unscoped_bash_allowed_tools(frontmatter_value)
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_unscoped_bash_allowed_tools_frontmatter_relative_span(snippet)
        {
            signals.unscoped_bash_allowed_tools_spans.push(Span::new(
                region.span.start_byte + relative.start_byte,
                region.span.start_byte + relative.end_byte,
            ));
        }

        if matches!(ctx.artifact.kind, ArtifactKind::Instructions)
            && is_github_copilot_instruction_path(&ctx.artifact.normalized_path)
            && !is_fixture_like_markdown_instruction_path(&ctx.artifact.normalized_path)
            && ctx.content.chars().count() > GITHUB_COPILOT_INSTRUCTIONS_CHAR_LIMIT
            && let Some(relative) = leading_markdown_file_relative_span(&ctx.content)
        {
            signals.copilot_instruction_too_long_spans.push(relative);
        }

        if matches!(ctx.artifact.kind, ArtifactKind::Instructions)
            && is_github_copilot_path_specific_instruction_path(&ctx.artifact.normalized_path)
            && !is_fixture_like_markdown_instruction_path(&ctx.artifact.normalized_path)
        {
            let markdown = markdown_semantics(ctx);
            let has_raw_frontmatter = ctx.document.raw_frontmatter.is_some();
            let parsed_frontmatter = markdown.and_then(|markdown| markdown.frontmatter.as_ref());
            let has_apply_to = parsed_frontmatter
                .and_then(|frontmatter| frontmatter.value.get("applyTo"))
                .is_some_and(|value| match value {
                    serde_json::Value::String(text) => !text.trim().is_empty(),
                    serde_json::Value::Array(items) => !items.is_empty(),
                    _ => true,
                });

            if (!has_raw_frontmatter || parsed_frontmatter.is_some())
                && !has_apply_to
                && let Some(relative) = leading_markdown_file_relative_span(&ctx.content)
            {
                signals
                    .copilot_instruction_missing_apply_to_spans
                    .push(relative);
            }
        }

        Some(signals)
    }
}
