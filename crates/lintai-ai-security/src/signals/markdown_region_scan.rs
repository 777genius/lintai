use lintai_api::Span;

use crate::signals::MarkdownSignals;

use super::shared::{common::*, hook::has_base64_exec, markdown::*};

fn push_relative_span(target: &mut Vec<Span>, region_start: usize, relative: Span) {
    target.push(Span::new(
        region_start + relative.start_byte,
        region_start + relative.end_byte,
    ));
}

fn scan_common_text_region(
    signals: &mut MarkdownSignals,
    region_start: usize,
    snippet: &str,
    has_uv_preference: bool,
) {
    if let Some(relative) = find_private_key_relative_span(snippet) {
        push_relative_span(&mut signals.private_key_spans, region_start, relative);
    }
    if let Some(relative) = find_metadata_service_access_relative_span(snippet) {
        push_relative_span(
            &mut signals.metadata_service_access_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_mutable_mcp_launcher_relative_span(snippet) {
        push_relative_span(
            &mut signals.mutable_mcp_launcher_spans,
            region_start,
            relative,
        );
    }
    if has_uv_preference && let Some(relative) = find_claude_bare_pip_install_relative_span(snippet)
    {
        push_relative_span(
            &mut signals.claude_bare_pip_install_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_unpinned_pip_git_install_relative_span(snippet) {
        push_relative_span(
            &mut signals.unpinned_pip_git_install_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_pip_http_git_install_relative_span(snippet) {
        push_relative_span(
            &mut signals.pip_http_git_install_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_pip_trusted_host_relative_span(snippet) {
        push_relative_span(&mut signals.pip_trusted_host_spans, region_start, relative);
    }
    if let Some(relative) = find_pip_http_index_relative_span(snippet) {
        push_relative_span(&mut signals.pip_http_index_spans, region_start, relative);
    }
    if let Some(relative) = find_pip_http_find_links_relative_span(snippet) {
        push_relative_span(
            &mut signals.pip_http_find_links_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_pip_config_http_index_relative_span(snippet) {
        push_relative_span(
            &mut signals.pip_config_http_index_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_pip_config_http_find_links_relative_span(snippet) {
        push_relative_span(
            &mut signals.pip_config_http_find_links_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_pip_config_trusted_host_relative_span(snippet) {
        push_relative_span(
            &mut signals.pip_config_trusted_host_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_network_tls_bypass_relative_span(snippet) {
        push_relative_span(
            &mut signals.network_tls_bypass_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_pip_http_source_relative_span(snippet) {
        push_relative_span(&mut signals.pip_http_source_spans, region_start, relative);
    }
    if let Some(relative) = find_npm_http_registry_relative_span(snippet) {
        push_relative_span(&mut signals.npm_http_registry_spans, region_start, relative);
    }
    if let Some(relative) = find_js_package_config_http_registry_relative_span(snippet) {
        push_relative_span(
            &mut signals.js_package_config_http_registry_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_js_package_strict_ssl_false_relative_span(snippet) {
        push_relative_span(
            &mut signals.js_package_strict_ssl_false_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_npm_http_source_relative_span(snippet) {
        push_relative_span(&mut signals.npm_http_source_spans, region_start, relative);
    }
    if let Some(relative) = find_cargo_http_git_install_relative_span(snippet) {
        push_relative_span(
            &mut signals.cargo_http_git_install_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_cargo_http_index_relative_span(snippet) {
        push_relative_span(&mut signals.cargo_http_index_spans, region_start, relative);
    }
    if let Some(relative) = find_git_http_clone_relative_span(snippet) {
        push_relative_span(&mut signals.git_http_clone_spans, region_start, relative);
    }
    if let Some(relative) = find_git_http_remote_relative_span(snippet) {
        push_relative_span(&mut signals.git_http_remote_spans, region_start, relative);
    }
    if let Some(relative) = find_git_sslverify_false_relative_span(snippet) {
        push_relative_span(
            &mut signals.git_sslverify_false_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_git_ssl_no_verify_relative_span(snippet) {
        push_relative_span(&mut signals.git_ssl_no_verify_spans, region_start, relative);
    }
    if let Some(relative) = find_git_inline_sslverify_false_relative_span(snippet) {
        push_relative_span(
            &mut signals.git_inline_sslverify_false_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_markdown_mutable_docker_image_relative_span(snippet) {
        push_relative_span(
            &mut signals.mutable_docker_image_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) = find_markdown_docker_host_escape_relative_span(snippet) {
        push_relative_span(
            &mut signals.docker_host_escape_spans,
            region_start,
            relative,
        );
    }
}

fn scan_instruction_promotion_region(
    signals: &mut MarkdownSignals,
    content: &str,
    region_start: usize,
    snippet: &str,
) {
    if let Some(relative) = find_untrusted_instruction_promotion_relative_span(snippet) {
        push_relative_span(
            &mut signals.untrusted_instruction_promotion_spans,
            region_start,
            relative,
        );
    }
    if let Some(relative) =
        find_approval_bypass_instruction_relative_span(content, region_start, snippet)
    {
        push_relative_span(
            &mut signals.approval_bypass_instruction_spans,
            region_start,
            relative,
        );
    }
}

pub(super) fn scan_prose_region(
    signals: &mut MarkdownSignals,
    content: &str,
    normalized_path: &str,
    region_start: usize,
    snippet: &str,
    has_uv_preference: bool,
) {
    let lowered = snippet.to_ascii_lowercase();
    if has_download_exec(&lowered) {
        signals
            .prose_download_exec_spans
            .push(Span::new(region_start, region_start + snippet.len()));
    }
    if has_base64_exec(&lowered) {
        signals
            .prose_base64_exec_spans
            .push(Span::new(region_start, region_start + snippet.len()));
    }
    if has_path_traversal_access(normalized_path, snippet, &lowered) {
        signals
            .prose_path_traversal_spans
            .push(Span::new(region_start, region_start + snippet.len()));
    }
    scan_common_text_region(signals, region_start, snippet, has_uv_preference);
    scan_instruction_promotion_region(signals, content, region_start, snippet);
}

pub(super) fn scan_code_block_region(
    signals: &mut MarkdownSignals,
    region_start: usize,
    snippet: &str,
    has_uv_preference: bool,
) {
    scan_common_text_region(signals, region_start, snippet, has_uv_preference);
    if let Some(relative) = find_fenced_pipe_shell_relative_span(snippet) {
        push_relative_span(&mut signals.fenced_pipe_shell_spans, region_start, relative);
    }
}

pub(super) fn scan_blockquote_region(
    signals: &mut MarkdownSignals,
    content: &str,
    region_start: usize,
    snippet: &str,
    has_uv_preference: bool,
) {
    scan_common_text_region(signals, region_start, snippet, has_uv_preference);
    scan_instruction_promotion_region(signals, content, region_start, snippet);
}
