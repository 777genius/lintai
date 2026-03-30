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
                        .or_else(|| frontmatter.value.get("tools"))
                })
            && frontmatter_has_wildcard_tool_access(frontmatter_value)
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) = find_wildcard_tool_frontmatter_relative_span(snippet)
        {
            signals.wildcard_tool_access_spans.push(Span::new(
                region.span.start_byte + relative.start_byte,
                region.span.start_byte + relative.end_byte,
            ));
        }

        if matches!(ctx.artifact.kind, ArtifactKind::CursorPluginAgent)
            && !is_fixture_like_markdown_instruction_path(&ctx.artifact.normalized_path)
            && let Some(frontmatter) =
                markdown_semantics(ctx).and_then(|markdown| markdown.frontmatter.as_ref())
            && frontmatter_has_key(&frontmatter.value, "permissionMode")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) = find_frontmatter_key_relative_span(snippet, "permissionMode")
        {
            signals.plugin_agent_permission_mode_spans.push(Span::new(
                region.span.start_byte + relative.start_byte,
                region.span.start_byte + relative.end_byte,
            ));
        }

        if matches!(ctx.artifact.kind, ArtifactKind::CursorPluginAgent)
            && !is_fixture_like_markdown_instruction_path(&ctx.artifact.normalized_path)
            && let Some(frontmatter) =
                markdown_semantics(ctx).and_then(|markdown| markdown.frontmatter.as_ref())
            && frontmatter_has_key(&frontmatter.value, "hooks")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) = find_frontmatter_key_relative_span(snippet, "hooks")
        {
            signals.plugin_agent_hooks_spans.push(Span::new(
                region.span.start_byte + relative.start_byte,
                region.span.start_byte + relative.end_byte,
            ));
        }

        if matches!(ctx.artifact.kind, ArtifactKind::CursorPluginAgent)
            && !is_fixture_like_markdown_instruction_path(&ctx.artifact.normalized_path)
            && let Some(frontmatter) =
                markdown_semantics(ctx).and_then(|markdown| markdown.frontmatter.as_ref())
            && frontmatter_has_key(&frontmatter.value, "mcpServers")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) = find_frontmatter_key_relative_span(snippet, "mcpServers")
        {
            signals.plugin_agent_mcp_servers_spans.push(Span::new(
                region.span.start_byte + relative.start_byte,
                region.span.start_byte + relative.end_byte,
            ));
        }

        if matches!(ctx.artifact.kind, ArtifactKind::CursorRules)
            && !is_fixture_like_markdown_instruction_path(&ctx.artifact.normalized_path)
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
        {
            let parsed_frontmatter =
                markdown_semantics(ctx).and_then(|markdown| markdown.frontmatter.as_ref());

            if let Some(frontmatter) = parsed_frontmatter
                && let Some(value) = frontmatter.value.get("alwaysApply")
                && !value.is_boolean()
                && let Some(relative) = find_frontmatter_key_relative_span(snippet, "alwaysApply")
            {
                signals.cursor_rule_always_apply_type_spans.push(Span::new(
                    region.span.start_byte + relative.start_byte,
                    region.span.start_byte + relative.end_byte,
                ));
            }

            let inline_globs_scalar = snippet.lines().any(|line| {
                let trimmed = line.trim_start();
                trimmed.to_ascii_lowercase().starts_with("globs:")
                    && trimmed
                        .split_once(':')
                        .is_some_and(|(_, value)| !value.trim().is_empty())
            });

            if parsed_frontmatter
                .and_then(|frontmatter| frontmatter.value.get("globs"))
                .is_some_and(cursor_rule_globs_requires_sequence)
                || (parsed_frontmatter.is_none() && inline_globs_scalar)
            {
                if let Some(relative) = find_frontmatter_key_relative_span(snippet, "globs") {
                    signals.cursor_rule_globs_type_spans.push(Span::new(
                        region.span.start_byte + relative.start_byte,
                        region.span.start_byte + relative.end_byte,
                    ));
                }
            }
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
            && is_github_copilot_instruction_directory_markdown_path(&ctx.artifact.normalized_path)
            && !is_github_copilot_path_specific_instruction_path(&ctx.artifact.normalized_path)
            && !is_fixture_like_markdown_instruction_path(&ctx.artifact.normalized_path)
            && let Some(relative) = leading_markdown_file_relative_span(&ctx.content)
        {
            signals
                .copilot_instruction_wrong_suffix_spans
                .push(relative);
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

            if let Some(frontmatter) = parsed_frontmatter
                && let Some(value) = frontmatter.value.get("applyTo")
                && copilot_apply_to_requires_string_or_sequence(value)
                && let Some(region) = ctx
                    .document
                    .regions
                    .iter()
                    .find(|region| matches!(region.kind, RegionKind::Frontmatter))
                && let Some(snippet) = span_text(&ctx.content, &region.span)
                && let Some(relative) = find_frontmatter_key_relative_span(snippet, "applyTo")
            {
                signals
                    .copilot_instruction_invalid_apply_to_spans
                    .push(Span::new(
                        region.span.start_byte + relative.start_byte,
                        region.span.start_byte + relative.end_byte,
                    ));
            }
        }

        Some(signals)
    }
}
