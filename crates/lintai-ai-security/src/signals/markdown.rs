use globset::Glob;
use lintai_api::{ArtifactKind, RegionKind, ScanContext, Span};

use crate::helpers::{markdown_semantics, span_text};

use super::shared::{common::*, hook::has_base64_exec, markdown::*};
use super::{MarkdownSignals, SignalWorkBudget};

const CURSOR_RULE_FRONTMATTER_KEYS: &[&str] = &["description", "globs", "alwaysApply"];

fn copilot_apply_to_contains_invalid_glob(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(pattern) => Glob::new(pattern).is_err(),
        serde_json::Value::Array(items) => items.iter().any(|item| match item.as_str() {
            Some(pattern) => Glob::new(pattern).is_err(),
            None => false,
        }),
        _ => false,
    }
}

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
        let has_uv_preference = has_uv_instead_of_pip_preference(&ctx.content);

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
                    if has_uv_preference
                        && let Some(relative) = find_claude_bare_pip_install_relative_span(snippet)
                    {
                        signals.claude_bare_pip_install_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_unpinned_pip_git_install_relative_span(snippet) {
                        signals.unpinned_pip_git_install_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_http_git_install_relative_span(snippet) {
                        signals.pip_http_git_install_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_trusted_host_relative_span(snippet) {
                        signals.pip_trusted_host_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_http_index_relative_span(snippet) {
                        signals.pip_http_index_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_http_find_links_relative_span(snippet) {
                        signals.pip_http_find_links_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_config_http_index_relative_span(snippet) {
                        signals.pip_config_http_index_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_config_http_find_links_relative_span(snippet) {
                        signals.pip_config_http_find_links_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_config_trusted_host_relative_span(snippet) {
                        signals.pip_config_trusted_host_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_network_tls_bypass_relative_span(snippet) {
                        signals.network_tls_bypass_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_http_source_relative_span(snippet) {
                        signals.pip_http_source_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_npm_http_registry_relative_span(snippet) {
                        signals.npm_http_registry_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) =
                        find_js_package_config_http_registry_relative_span(snippet)
                    {
                        signals
                            .js_package_config_http_registry_spans
                            .push(Span::new(
                                region.span.start_byte + relative.start_byte,
                                region.span.start_byte + relative.end_byte,
                            ));
                    }
                    if let Some(relative) = find_js_package_strict_ssl_false_relative_span(snippet)
                    {
                        signals.js_package_strict_ssl_false_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_npm_http_source_relative_span(snippet) {
                        signals.npm_http_source_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_cargo_http_git_install_relative_span(snippet) {
                        signals.cargo_http_git_install_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_cargo_http_index_relative_span(snippet) {
                        signals.cargo_http_index_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_http_clone_relative_span(snippet) {
                        signals.git_http_clone_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_http_remote_relative_span(snippet) {
                        signals.git_http_remote_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_sslverify_false_relative_span(snippet) {
                        signals.git_sslverify_false_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_ssl_no_verify_relative_span(snippet) {
                        signals.git_ssl_no_verify_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_inline_sslverify_false_relative_span(snippet) {
                        signals.git_inline_sslverify_false_spans.push(Span::new(
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
                    if has_uv_preference
                        && let Some(relative) = find_claude_bare_pip_install_relative_span(snippet)
                    {
                        signals.claude_bare_pip_install_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_unpinned_pip_git_install_relative_span(snippet) {
                        signals.unpinned_pip_git_install_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_http_git_install_relative_span(snippet) {
                        signals.pip_http_git_install_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_trusted_host_relative_span(snippet) {
                        signals.pip_trusted_host_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_http_index_relative_span(snippet) {
                        signals.pip_http_index_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_http_find_links_relative_span(snippet) {
                        signals.pip_http_find_links_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_config_http_index_relative_span(snippet) {
                        signals.pip_config_http_index_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_config_http_find_links_relative_span(snippet) {
                        signals.pip_config_http_find_links_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_config_trusted_host_relative_span(snippet) {
                        signals.pip_config_trusted_host_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_network_tls_bypass_relative_span(snippet) {
                        signals.network_tls_bypass_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_http_source_relative_span(snippet) {
                        signals.pip_http_source_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_npm_http_registry_relative_span(snippet) {
                        signals.npm_http_registry_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) =
                        find_js_package_config_http_registry_relative_span(snippet)
                    {
                        signals
                            .js_package_config_http_registry_spans
                            .push(Span::new(
                                region.span.start_byte + relative.start_byte,
                                region.span.start_byte + relative.end_byte,
                            ));
                    }
                    if let Some(relative) = find_js_package_strict_ssl_false_relative_span(snippet)
                    {
                        signals.js_package_strict_ssl_false_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_npm_http_source_relative_span(snippet) {
                        signals.npm_http_source_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_cargo_http_git_install_relative_span(snippet) {
                        signals.cargo_http_git_install_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_cargo_http_index_relative_span(snippet) {
                        signals.cargo_http_index_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_http_clone_relative_span(snippet) {
                        signals.git_http_clone_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_http_remote_relative_span(snippet) {
                        signals.git_http_remote_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_sslverify_false_relative_span(snippet) {
                        signals.git_sslverify_false_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_ssl_no_verify_relative_span(snippet) {
                        signals.git_ssl_no_verify_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_inline_sslverify_false_relative_span(snippet) {
                        signals.git_inline_sslverify_false_spans.push(Span::new(
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
                    if has_uv_preference
                        && let Some(relative) = find_claude_bare_pip_install_relative_span(snippet)
                    {
                        signals.claude_bare_pip_install_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_unpinned_pip_git_install_relative_span(snippet) {
                        signals.unpinned_pip_git_install_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_http_git_install_relative_span(snippet) {
                        signals.pip_http_git_install_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_trusted_host_relative_span(snippet) {
                        signals.pip_trusted_host_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_http_index_relative_span(snippet) {
                        signals.pip_http_index_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_http_find_links_relative_span(snippet) {
                        signals.pip_http_find_links_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_config_http_index_relative_span(snippet) {
                        signals.pip_config_http_index_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_config_http_find_links_relative_span(snippet) {
                        signals.pip_config_http_find_links_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_config_trusted_host_relative_span(snippet) {
                        signals.pip_config_trusted_host_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_network_tls_bypass_relative_span(snippet) {
                        signals.network_tls_bypass_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_pip_http_source_relative_span(snippet) {
                        signals.pip_http_source_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_npm_http_registry_relative_span(snippet) {
                        signals.npm_http_registry_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) =
                        find_js_package_config_http_registry_relative_span(snippet)
                    {
                        signals
                            .js_package_config_http_registry_spans
                            .push(Span::new(
                                region.span.start_byte + relative.start_byte,
                                region.span.start_byte + relative.end_byte,
                            ));
                    }
                    if let Some(relative) = find_js_package_strict_ssl_false_relative_span(snippet)
                    {
                        signals.js_package_strict_ssl_false_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_npm_http_source_relative_span(snippet) {
                        signals.npm_http_source_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_cargo_http_git_install_relative_span(snippet) {
                        signals.cargo_http_git_install_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_cargo_http_index_relative_span(snippet) {
                        signals.cargo_http_index_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_http_clone_relative_span(snippet) {
                        signals.git_http_clone_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_http_remote_relative_span(snippet) {
                        signals.git_http_remote_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_sslverify_false_relative_span(snippet) {
                        signals.git_sslverify_false_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_ssl_no_verify_relative_span(snippet) {
                        signals.git_ssl_no_verify_spans.push(Span::new(
                            region.span.start_byte + relative.start_byte,
                            region.span.start_byte + relative.end_byte,
                        ));
                    }
                    if let Some(relative) = find_git_inline_sslverify_false_relative_span(snippet) {
                        signals.git_inline_sslverify_false_spans.push(Span::new(
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
                })
            && frontmatter_has_unscoped_websearch_allowed_tools(frontmatter_value)
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_unscoped_websearch_allowed_tools_frontmatter_relative_span(snippet)
        {
            signals
                .unscoped_websearch_allowed_tools_spans
                .push(Span::new(
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
                })
            && frontmatter_has_unscoped_webfetch_allowed_tools(frontmatter_value)
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_unscoped_webfetch_allowed_tools_frontmatter_relative_span(snippet)
        {
            signals
                .unscoped_webfetch_allowed_tools_spans
                .push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git push)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git push)")
        {
            signals.git_push_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git checkout:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git checkout:*)")
        {
            signals.git_checkout_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git commit:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git commit:*)")
        {
            signals.git_commit_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git stash:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git stash:*)")
        {
            signals.git_stash_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(gh pr:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(gh pr:*)")
        {
            signals.gh_pr_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(gh api --method POST:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) = find_exact_allowed_tool_frontmatter_relative_span(
                snippet,
                "Bash(gh api --method POST:*)",
            )
        {
            signals.gh_api_post_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(gh issue create:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) = find_exact_allowed_tool_frontmatter_relative_span(
                snippet,
                "Bash(gh issue create:*)",
            )
        {
            signals.gh_issue_create_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(gh repo create:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(gh repo create:*)")
        {
            signals.gh_repo_create_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(npm exec:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(npm exec:*)")
        {
            signals.npm_exec_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(bunx:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(bunx:*)")
        {
            signals.bunx_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(uvx:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(uvx:*)")
        {
            signals.uvx_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(pnpm dlx:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(pnpm dlx:*)")
        {
            signals.pnpm_dlx_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(yarn dlx:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(yarn dlx:*)")
        {
            signals.yarn_dlx_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(pipx run:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(pipx run:*)")
        {
            signals.pipx_run_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(npx:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(npx:*)")
        {
            signals.npx_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git ls-remote:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git ls-remote:*)")
        {
            signals.git_ls_remote_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(curl:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(curl:*)")
        {
            signals.curl_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(wget:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(wget:*)")
        {
            signals.wget_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(sudo:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(sudo:*)")
        {
            signals.sudo_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(rm:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(rm:*)")
        {
            signals.rm_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(chmod:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(chmod:*)")
        {
            signals.chmod_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(chown:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(chown:*)")
        {
            signals.chown_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(chgrp:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(chgrp:*)")
        {
            signals.chgrp_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(su:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(su:*)")
        {
            signals.su_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git clone:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git clone:*)")
        {
            signals.git_clone_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git add:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git add:*)")
        {
            signals.git_add_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git fetch:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git fetch:*)")
        {
            signals.git_fetch_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(
                frontmatter_value,
                "WebFetch(domain:raw.githubusercontent.com)",
            )
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) = find_exact_allowed_tool_frontmatter_relative_span(
                snippet,
                "WebFetch(domain:raw.githubusercontent.com)",
            )
        {
            signals
                .webfetch_raw_github_allowed_tools_spans
                .push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git config:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git config:*)")
        {
            signals.git_config_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git tag:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git tag:*)")
        {
            signals.git_tag_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git branch:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git branch:*)")
        {
            signals.git_branch_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git reset:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git reset:*)")
        {
            signals.git_reset_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git clean:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git clean:*)")
        {
            signals.git_clean_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git restore:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git restore:*)")
        {
            signals.git_restore_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git rebase:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git rebase:*)")
        {
            signals.git_rebase_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git merge:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git merge:*)")
        {
            signals.git_merge_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git cherry-pick:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) = find_exact_allowed_tool_frontmatter_relative_span(
                snippet,
                "Bash(git cherry-pick:*)",
            )
        {
            signals.git_cherry_pick_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git apply:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git apply:*)")
        {
            signals.git_apply_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Bash(git am:*)")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Bash(git am:*)")
        {
            signals.git_am_allowed_tools_spans.push(Span::new(
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
                })
            && let Some(permission) = [
                "Bash(pip install)",
                "Bash(pip3 install)",
                "Bash(python -m pip install)",
                "Bash(yarn install)",
                "Bash(npm install)",
                "Bash(pnpm install)",
                "Bash(bun install)",
            ]
            .iter()
            .find(|permission| frontmatter_has_exact_allowed_tool(frontmatter_value, permission))
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, permission)
        {
            signals.package_install_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Read")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Read")
        {
            signals.unscoped_read_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Write")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Write")
        {
            signals.unscoped_write_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Edit")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Edit")
        {
            signals.unscoped_edit_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Glob")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Glob")
        {
            signals.unscoped_glob_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_exact_allowed_tool(frontmatter_value, "Grep")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_exact_allowed_tool_frontmatter_relative_span(snippet, "Grep")
        {
            signals.unscoped_grep_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_unsafe_path_allowed_tool(frontmatter_value, "Read")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_unsafe_path_allowed_tool_frontmatter_relative_span(snippet, "Read")
        {
            signals.read_unsafe_path_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_unsafe_path_allowed_tool(frontmatter_value, "Write")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_unsafe_path_allowed_tool_frontmatter_relative_span(snippet, "Write")
        {
            signals
                .write_unsafe_path_allowed_tools_spans
                .push(Span::new(
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
                })
            && frontmatter_has_unsafe_path_allowed_tool(frontmatter_value, "Edit")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_unsafe_path_allowed_tool_frontmatter_relative_span(snippet, "Edit")
        {
            signals.edit_unsafe_path_allowed_tools_spans.push(Span::new(
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
                })
            && frontmatter_has_unsafe_path_allowed_tool(frontmatter_value, "Glob")
            && let Some(region) = ctx
                .document
                .regions
                .iter()
                .find(|region| matches!(region.kind, RegionKind::Frontmatter))
            && let Some(snippet) = span_text(&ctx.content, &region.span)
            && let Some(relative) =
                find_unsafe_path_allowed_tool_frontmatter_relative_span(snippet, "Glob")
        {
            signals.glob_unsafe_path_allowed_tools_spans.push(Span::new(
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

            if let Some(frontmatter) = parsed_frontmatter
                && frontmatter
                    .value
                    .get("alwaysApply")
                    .is_some_and(|value| value.as_bool() == Some(true))
                && frontmatter.value.get("globs").is_some()
                && let Some(relative) = find_frontmatter_key_relative_span(snippet, "globs")
            {
                signals.cursor_rule_redundant_globs_spans.push(Span::new(
                    region.span.start_byte + relative.start_byte,
                    region.span.start_byte + relative.end_byte,
                ));
            }

            if let Some(frontmatter) = parsed_frontmatter
                && let Some(mapping) = frontmatter.value.as_object()
            {
                if !mapping
                    .get("description")
                    .is_some_and(|value| value.as_str().is_some_and(|text| !text.trim().is_empty()))
                {
                    signals
                        .cursor_rule_missing_description_spans
                        .push(Span::new(
                            region.span.start_byte,
                            region.span.start_byte + 3,
                        ));
                }

                for key in mapping.keys() {
                    if CURSOR_RULE_FRONTMATTER_KEYS.contains(&key.as_str()) {
                        continue;
                    }

                    if let Some(relative) = find_frontmatter_key_relative_span(snippet, key) {
                        signals
                            .cursor_rule_unknown_frontmatter_key_spans
                            .push(Span::new(
                                region.span.start_byte + relative.start_byte,
                                region.span.start_byte + relative.end_byte,
                            ));
                    }
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

            if let Some(frontmatter) = parsed_frontmatter
                && let Some(value) = frontmatter.value.get("applyTo")
                && !copilot_apply_to_requires_string_or_sequence(value)
                && copilot_apply_to_contains_invalid_glob(value)
                && let Some(region) = ctx
                    .document
                    .regions
                    .iter()
                    .find(|region| matches!(region.kind, RegionKind::Frontmatter))
                && let Some(snippet) = span_text(&ctx.content, &region.span)
                && let Some(relative) = find_frontmatter_key_relative_span(snippet, "applyTo")
            {
                signals
                    .copilot_instruction_invalid_apply_to_glob_spans
                    .push(Span::new(
                        region.span.start_byte + relative.start_byte,
                        region.span.start_byte + relative.end_byte,
                    ));
            }
        }

        Some(signals)
    }
}
