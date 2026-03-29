use lintai_api::Span;

use super::tokens::{normalized_markdown_shell_token, tokenize_markdown_shell_command};

pub(crate) const MARKDOWN_MUTABLE_MCP_LAUNCHER_MARKERS: &[&str] =
    &["npx", "uvx", "pnpm dlx", "yarn dlx", "pipx run"];
pub(crate) const MARKDOWN_MUTABLE_MCP_CONTEXT_MARKERS: &[&str] = &[
    "mcpservers",
    "\"mcpservers\"",
    "claude mcp",
    "cursor mcp",
    "model context protocol",
    "mcp server",
];
pub(crate) const MARKDOWN_MUTABLE_MCP_SAFETY_MARKERS: &[&str] = &[
    "do not use",
    "don't use",
    "avoid",
    "replace with",
    "instead of",
];

pub(crate) fn find_mutable_mcp_launcher_relative_span(text: &str) -> Option<Span> {
    let lowered_region = text.to_ascii_lowercase();
    let region_has_mcp_context = MARKDOWN_MUTABLE_MCP_CONTEXT_MARKERS
        .iter()
        .any(|marker| lowered_region.contains(marker));

    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let lowered = line.to_ascii_lowercase();
        if lowered.contains("claude mcp add")
            && let Some(relative) = find_mutable_launcher_token_relative_span(line)
            && !has_markdown_mutable_mcp_safety_context(line, &relative)
        {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if region_has_mcp_context
        && let Some(relative) = find_markdown_command_launcher_relative_span(text)
    {
        return Some(relative);
    }

    if !text.ends_with('\n') {
        let lowered = text.to_ascii_lowercase();
        if lowered.contains("claude mcp add")
            && let Some(relative) = find_mutable_launcher_token_relative_span(text)
            && !has_markdown_mutable_mcp_safety_context(text, &relative)
        {
            return Some(relative);
        }
    }

    None
}

pub(crate) fn find_mutable_launcher_token_relative_span(text: &str) -> Option<Span> {
    let lowered = text.to_ascii_lowercase();
    for marker in MARKDOWN_MUTABLE_MCP_LAUNCHER_MARKERS {
        if let Some(start) = lowered.find(marker) {
            let token_len = marker.split_whitespace().next().unwrap_or(marker).len();
            return Some(Span::new(start, start + token_len));
        }
    }
    None
}

pub(crate) fn find_markdown_command_launcher_relative_span(text: &str) -> Option<Span> {
    let lowered = text.to_ascii_lowercase();
    for launcher in ["npx", "uvx", "pnpm", "yarn", "pipx"] {
        for prefix in [
            format!("\"command\": \"{launcher}\""),
            format!("command: {launcher}"),
        ] {
            if let Some(start) = lowered.find(&prefix) {
                let launcher_start = start + prefix.rfind(launcher).unwrap_or(0);
                let launcher_span = Span::new(launcher_start, launcher_start + launcher.len());
                if has_markdown_mutable_mcp_safety_context(text, &launcher_span) {
                    continue;
                }
                if markdown_command_launcher_has_mutable_args(text, launcher, &launcher_span) {
                    return Some(launcher_span);
                }
            }
        }
    }
    None
}

pub(crate) fn markdown_command_launcher_has_mutable_args(
    text: &str,
    launcher: &str,
    launcher_span: &Span,
) -> bool {
    let lowered = text.to_ascii_lowercase();
    let window_start = launcher_span.start_byte.saturating_sub(48);
    let window_end = (launcher_span.end_byte + 220).min(lowered.len());
    let window = &lowered[window_start..window_end];

    let Some(args_index) = window.find("\"args\"").or_else(|| window.find("args:")) else {
        return false;
    };
    let args_window = &window[args_index..];

    match launcher {
        "npx" | "uvx" => contains_package_like_arg(args_window, &["-y", "--yes"]),
        "pnpm" | "yarn" => {
            args_window.contains("dlx")
                && contains_package_like_arg(args_window, &["dlx", "-y", "--yes"])
        }
        "pipx" => {
            args_window.contains("run")
                && contains_package_like_arg(args_window, &["run", "-y", "--yes"])
        }
        _ => false,
    }
}

pub(crate) fn contains_package_like_arg(args_window: &str, excluded_tokens: &[&str]) -> bool {
    tokenize_markdown_shell_command(args_window)
        .into_iter()
        .map(|(token, _, _)| {
            normalized_markdown_shell_token(token).trim_matches(|ch| {
                ch == '"' || ch == '\'' || ch == '[' || ch == ']' || ch == ',' || ch == ':'
            })
        })
        .any(|token| {
            !token.is_empty()
                && token.chars().any(|ch| ch.is_ascii_alphabetic())
                && token != "args"
                && !excluded_tokens.iter().any(|excluded| token == *excluded)
        })
}

pub(crate) fn has_markdown_mutable_mcp_safety_context(text: &str, marker_span: &Span) -> bool {
    let lowered = text.to_ascii_lowercase();
    let start = marker_span.start_byte.saturating_sub(96);
    let end = (marker_span.end_byte + 96).min(lowered.len());
    let window = &lowered[start..end];
    MARKDOWN_MUTABLE_MCP_SAFETY_MARKERS
        .iter()
        .any(|marker| window.contains(marker))
}
