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
pub(crate) const MARKDOWN_MUTABLE_MCP_EXCLUDED_PACKAGE_PREFIXES: &[&str] =
    &["mcp-remote", "@modelcontextprotocol/inspector", "inspector"];

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
            && !contains_excluded_mutable_mcp_package(line)
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
            && !contains_excluded_mutable_mcp_package(text)
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
                && !token.starts_with("http://")
                && !token.starts_with("https://")
                && !is_excluded_mutable_mcp_package_token(token)
                && !excluded_tokens.contains(&token)
        })
}

pub(crate) fn contains_excluded_mutable_mcp_package(text: &str) -> bool {
    tokenize_markdown_shell_command(text)
        .into_iter()
        .map(|(token, _, _)| normalized_markdown_shell_token(token))
        .any(is_excluded_mutable_mcp_package_token)
}

pub(crate) fn is_excluded_mutable_mcp_package_token(token: &str) -> bool {
    let normalized =
        token.trim_matches(|ch| matches!(ch, '"' | '\'' | '[' | ']' | ',' | ':' | '`'));
    MARKDOWN_MUTABLE_MCP_EXCLUDED_PACKAGE_PREFIXES
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
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

#[cfg(test)]
mod tests {
    use super::{
        contains_excluded_mutable_mcp_package, find_markdown_command_launcher_relative_span,
        find_mutable_mcp_launcher_relative_span,
    };

    #[test]
    fn ignores_remote_bridge_mcp_config_example() {
        let content = "```json\n{\n  \"mcpServers\": {\n    \"my-server\": {\n      \"command\": \"npx\",\n      \"args\": [\"mcp-remote\", \"https://my-mcp.workers.dev/mcp\"]\n    }\n  }\n}\n```\n";

        assert_eq!(find_markdown_command_launcher_relative_span(content), None);
    }

    #[test]
    fn ignores_remote_bridge_cli_example() {
        let content = "claude mcp add exa uvx mcp-remote https://mcp.exa.ai/mcp\n";

        assert_eq!(find_mutable_mcp_launcher_relative_span(content), None);
    }

    #[test]
    fn still_detects_real_mutable_mcp_server_package() {
        let content = "```json\n{\n  \"mcpServers\": {\n    \"demo\": {\n      \"command\": \"npx\",\n      \"args\": [\"-y\", \"olostep-mcp\"]\n    }\n  }\n}\n```\n";

        assert!(find_markdown_command_launcher_relative_span(content).is_some());
    }

    #[test]
    fn recognizes_excluded_bridge_packages() {
        assert!(contains_excluded_mutable_mcp_package(
            "\"args\": [\"mcp-remote\", \"https://example.com/mcp\"]"
        ));
        assert!(contains_excluded_mutable_mcp_package(
            "npx @modelcontextprotocol/inspector@latest"
        ));
    }
}
