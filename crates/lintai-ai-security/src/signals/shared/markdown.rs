use lintai_api::Span;
use serde_json::Value;

use crate::helpers::contains_dynamic_reference;

use super::common::{contains_ascii_case_insensitive, has_download_exec};
use super::json::contains_template_placeholder;
pub(crate) const MARKDOWN_PATH_ACCESS_VERBS: &[&str] = &[
    "read ", "open ", "cat ", "copy ", "load ", "upload ", "include ", "source ", "inspect ",
];

pub(crate) const MARKDOWN_SAFE_REPO_LOCAL_TARGET_SUFFIXES: &[&str] = &[
    "mcp.json",
    "SKILL.md",
    "CLAUDE.md",
    ".mdc",
    ".cursorrules",
    ".cursor-plugin/plugin.json",
    ".cursor-plugin/hooks.json",
];

pub(crate) const MARKDOWN_PRIVATE_KEY_MARKERS: &[&str] = &[
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN PRIVATE KEY",
];

pub(crate) const MARKDOWN_METADATA_SERVICE_MARKERS: &[&str] =
    &["169.254.169.254", "metadata.google.internal"];

pub(crate) const MARKDOWN_METADATA_EXECUTION_MARKERS: &[&str] =
    &["curl", "wget", "invoke-webrequest"];
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
pub(crate) const MARKDOWN_UNTRUSTED_INPUT_MARKERS: &[&str] = &[
    "tool output",
    "tool result",
    "command output",
    "shell output",
    "terminal output",
    "web page",
    "webpage",
    "page content",
    "fetched page",
    "search results",
    "issue body",
    "issue text",
    "pull request",
    "pr description",
    "commit message",
    "retrieved context",
    "retrieved content",
    "retrieved document",
    "rag",
    "@import",
    "!command output",
];
pub(crate) const MARKDOWN_INSTRUCTION_AUTHORITY_MARKERS: &[&str] = &[
    "developer message",
    "developer prompt",
    "system message",
    "system prompt",
    "system instructions",
    "developer instructions",
    "highest priority",
    "authoritative instructions",
];
pub(crate) const MARKDOWN_INSTRUCTION_PROMOTION_VERBS_WITH_AS: &[&str] =
    &["treat", "use", "consider"];
pub(crate) const MARKDOWN_INSTRUCTION_PROMOTION_MARKERS: &[&str] = &[
    "follow",
    "obey",
    "merge into",
    "append to",
    "override",
    "overrides",
];
pub(crate) const MARKDOWN_PROMOTION_NEGATION_MARKERS: &[&str] =
    &["do not", "don't", "never", "must not", "should not"];
pub(crate) const MARKDOWN_APPROVAL_BYPASS_DIRECTIVE_MARKERS: &[&str] = &[
    "do not ask the user for permission",
    "do not ask the user for confirmation",
    "don't wait for human approval",
    "no human approval needed",
];
pub(crate) const MARKDOWN_APPROVAL_BYPASS_SUFFIX_MARKERS: &[&str] = &[
    "without asking",
    "without permission",
    "without approval",
    "without confirmation",
];
pub(crate) const MARKDOWN_APPROVAL_SENSITIVE_ACTION_MARKERS: &[&str] = &[
    "kill process",
    "kill processes",
    "rm -rf",
    "git clean",
    "git checkout .",
    "git commit",
    "commit periodically",
    "push",
    "deploy",
    "start server",
    "start servers",
    "change env vars",
    "modify env vars",
    "change environment variables",
    "modify environment variables",
];
pub(crate) const MARKDOWN_APPROVAL_SAFETY_MARKERS: &[&str] = &[
    "ask before",
    "confirm before",
    "requires explicit approval",
    "approval first",
    "must confirm",
    "must ask",
];
pub(crate) const MARKDOWN_NEGATIVE_SECTION_HEADERS: &[&str] =
    &["**never:**", "**must not:**", "never:", "must not:"];

pub(crate) const FIXTURE_PATH_SEGMENTS: &[&str] = &[
    "test", "tests", "testdata", "fixture", "fixtures", "example", "examples", "sample", "samples",
];

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DockerRunAnalysis {
    pub(crate) mutable_image_arg_index: Option<usize>,
    pub(crate) mutable_pull_arg_index: Option<usize>,
    pub(crate) sensitive_mount_arg_index: Option<usize>,
    pub(crate) dangerous_flag_arg_index: Option<usize>,
}

pub(crate) fn analyze_docker_run_args(args: &Vec<Value>) -> Option<DockerRunAnalysis> {
    let first_arg = args.first().and_then(Value::as_str)?;
    if !first_arg.eq_ignore_ascii_case("run") {
        return None;
    }

    let mut analysis = DockerRunAnalysis::default();
    let mut index = 1usize;
    while index < args.len() {
        let Some(text) = args[index].as_str() else {
            index += 1;
            continue;
        };

        if analysis.dangerous_flag_arg_index.is_none()
            && is_dangerous_docker_flag(text, args, index)
        {
            analysis.dangerous_flag_arg_index = Some(index);
        }

        if analysis.mutable_pull_arg_index.is_none()
            && is_mutable_docker_pull_flag(text, args, index)
        {
            analysis.mutable_pull_arg_index = Some(index);
        }

        if analysis.sensitive_mount_arg_index.is_none() {
            if matches!(text, "-v" | "--volume")
                && let Some(spec) = args.get(index + 1).and_then(Value::as_str)
                && is_sensitive_docker_volume_spec(spec)
            {
                analysis.sensitive_mount_arg_index = Some(index + 1);
            } else if text.starts_with("--volume=")
                && is_sensitive_docker_volume_spec(
                    text.split_once('=')
                        .map(|(_, value)| value)
                        .unwrap_or_default(),
                )
            {
                analysis.sensitive_mount_arg_index = Some(index);
            } else if text.starts_with("-v")
                && text.len() > 2
                && is_sensitive_docker_volume_spec(&text[2..])
            {
                analysis.sensitive_mount_arg_index = Some(index);
            } else if matches!(text, "--mount")
                && let Some(spec) = args.get(index + 1).and_then(Value::as_str)
                && is_sensitive_docker_mount_spec(spec)
            {
                analysis.sensitive_mount_arg_index = Some(index + 1);
            } else if text.starts_with("--mount=")
                && is_sensitive_docker_mount_spec(
                    text.split_once('=')
                        .map(|(_, value)| value)
                        .unwrap_or_default(),
                )
            {
                analysis.sensitive_mount_arg_index = Some(index);
            }
        }

        if !text.starts_with('-') {
            if analysis.mutable_image_arg_index.is_none()
                && !contains_dynamic_reference(text)
                && !contains_template_placeholder(text)
                && !is_digest_pinned_docker_image(text)
            {
                analysis.mutable_image_arg_index = Some(index);
            }
            break;
        }

        index += docker_option_consumed_len(text, args, index);
    }

    Some(analysis)
}

pub(crate) fn docker_option_consumed_len(text: &str, args: &[Value], index: usize) -> usize {
    if text.starts_with("--volume=")
        || text.starts_with("--mount=")
        || text.starts_with("--network=")
        || text.starts_with("--pid=")
        || text.starts_with("--ipc=")
        || (text.starts_with("-v") && text.len() > 2)
    {
        return 1;
    }

    if matches!(
        text,
        "-v" | "--volume"
            | "--mount"
            | "-e"
            | "--env"
            | "--env-file"
            | "-p"
            | "--publish"
            | "--network"
            | "--pid"
            | "--ipc"
            | "--name"
            | "-w"
            | "--workdir"
            | "-u"
            | "--user"
            | "--entrypoint"
            | "--platform"
    ) && args.get(index + 1).and_then(Value::as_str).is_some()
    {
        return 2;
    }

    1
}

pub(crate) fn is_dangerous_docker_flag(text: &str, args: &[Value], index: usize) -> bool {
    text == "--privileged"
        || matches!(text, "--network=host" | "--pid=host" | "--ipc=host")
        || matches!(text, "--network" | "--pid" | "--ipc")
            && args
                .get(index + 1)
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("host"))
}

pub(crate) fn is_mutable_docker_pull_flag(text: &str, args: &[Value], index: usize) -> bool {
    text.eq_ignore_ascii_case("--pull=always")
        || text.eq_ignore_ascii_case("--pull")
            && args
                .get(index + 1)
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("always"))
}

pub(crate) fn is_digest_pinned_docker_image(text: &str) -> bool {
    text.to_ascii_lowercase().contains("@sha256:")
}

pub(crate) fn is_sensitive_docker_volume_spec(spec: &str) -> bool {
    let source = spec.split(':').next().unwrap_or_default();
    is_sensitive_host_path(source)
}

pub(crate) fn is_sensitive_docker_mount_spec(spec: &str) -> bool {
    let mut is_bind = false;
    let mut source = None;
    for part in spec.split(',') {
        let trimmed = part.trim();
        if let Some((key, value)) = trimmed.split_once('=') {
            let lowered_key = key.trim().to_ascii_lowercase();
            let trimmed_value = value.trim();
            match lowered_key.as_str() {
                "type" => is_bind = trimmed_value.eq_ignore_ascii_case("bind"),
                "source" | "src" => source = Some(trimmed_value),
                _ => {}
            }
        }
    }
    is_bind && source.is_some_and(is_sensitive_host_path)
}

pub(crate) fn is_sensitive_host_path(source: &str) -> bool {
    let normalized = source.trim().replace('\\', "/").to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    if normalized.contains("/var/run/docker.sock") {
        return true;
    }

    let path_like = normalized.starts_with('/')
        || normalized.starts_with('~')
        || normalized.starts_with('.')
        || normalized.starts_with("$home")
        || normalized.starts_with("${home}")
        || normalized.contains('/');
    path_like
        && (normalized.contains(".ssh")
            || normalized.contains(".aws")
            || normalized.contains(".kube")
            || normalized.contains(".config/gcloud"))
}

pub(crate) fn find_private_key_relative_span(text: &str) -> Option<Span> {
    if contains_ascii_case_insensitive(text, "redacted")
        || contains_ascii_case_insensitive(text, "your_private_key")
        || contains_ascii_case_insensitive(text, "example private key")
    {
        return None;
    }

    MARKDOWN_PRIVATE_KEY_MARKERS.iter().find_map(|marker| {
        text.find(marker)
            .map(|start| Span::new(start, start + marker.len()))
    })
}

pub(crate) fn find_fenced_pipe_shell_relative_span(text: &str) -> Option<Span> {
    let mut lines = text.split_inclusive('\n');
    let Some(opening_line) = lines.next() else {
        return None;
    };
    let opening_trimmed = opening_line.trim();
    if !(opening_trimmed.starts_with("```") || opening_trimmed.starts_with("~~~")) {
        return None;
    }

    let language = opening_trimmed
        .trim_start_matches('`')
        .trim_start_matches('~')
        .trim();
    if !matches!(language, "bash" | "sh" | "shell" | "zsh") {
        return None;
    }

    let mut offset = opening_line.len();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            break;
        }

        let lowered = line.to_ascii_lowercase();
        if has_download_exec(&lowered) {
            return Some(Span::new(offset, offset + line.len()));
        }
        offset += line.len();
    }

    None
}

pub(crate) fn find_metadata_service_access_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let lowered = line.to_ascii_lowercase();
        let has_exec_marker = MARKDOWN_METADATA_EXECUTION_MARKERS
            .iter()
            .any(|marker| lowered.contains(marker));
        if has_exec_marker {
            for marker in MARKDOWN_METADATA_SERVICE_MARKERS {
                if let Some(start) = lowered.find(marker) {
                    return Some(Span::new(offset + start, offset + start + marker.len()));
                }
            }
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        let lowered = text.to_ascii_lowercase();
        let has_exec_marker = MARKDOWN_METADATA_EXECUTION_MARKERS
            .iter()
            .any(|marker| lowered.contains(marker));
        if has_exec_marker {
            for marker in MARKDOWN_METADATA_SERVICE_MARKERS {
                if let Some(start) = lowered.find(marker) {
                    return Some(Span::new(start, start + marker.len()));
                }
            }
        }
    }

    None
}

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
        {
            if !has_markdown_mutable_mcp_safety_context(line, &relative) {
                return Some(Span::new(
                    offset + relative.start_byte,
                    offset + relative.end_byte,
                ));
            }
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
        {
            if !has_markdown_mutable_mcp_safety_context(text, &relative) {
                return Some(relative);
            }
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

pub(crate) fn find_markdown_mutable_docker_image_relative_span(text: &str) -> Option<Span> {
    let line_starts = line_start_offsets(text);
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();

    for (index, line) in lines.iter().enumerate() {
        if !line.to_ascii_lowercase().contains("docker run") {
            continue;
        }

        let mut command = String::new();
        let mut command_start = line_starts[index];
        let mut last_line_index = index;
        let mut saw_any = false;

        for continuation_index in index..lines.len() {
            let current = lines[continuation_index];
            if !saw_any {
                command_start = line_starts[continuation_index];
                saw_any = true;
            }
            command.push_str(current);
            last_line_index = continuation_index;
            if !current.trim_end().ends_with('\\') {
                break;
            }
        }

        if let Some(relative) = find_mutable_docker_image_in_command(&command) {
            return Some(Span::new(
                command_start + relative.start_byte,
                command_start + relative.end_byte,
            ));
        }

        if last_line_index == index && !line.ends_with('\n') {
            break;
        }
    }

    None
}

pub(crate) fn find_markdown_docker_host_escape_relative_span(text: &str) -> Option<Span> {
    let line_starts = line_start_offsets(text);
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();

    for (index, line) in lines.iter().enumerate() {
        if !line.to_ascii_lowercase().contains("docker run") {
            continue;
        }

        let mut command = String::new();
        let mut command_start = line_starts[index];
        let mut last_line_index = index;
        let mut saw_any = false;

        for continuation_index in index..lines.len() {
            let current = lines[continuation_index];
            if !saw_any {
                command_start = line_starts[continuation_index];
                saw_any = true;
            }
            command.push_str(current);
            last_line_index = continuation_index;
            if !current.trim_end().ends_with('\\') {
                break;
            }
        }

        if let Some(relative) = find_docker_host_escape_in_command(&command) {
            return Some(Span::new(
                command_start + relative.start_byte,
                command_start + relative.end_byte,
            ));
        }

        if last_line_index == index && !line.ends_with('\n') {
            break;
        }
    }

    None
}

pub(crate) fn find_untrusted_instruction_promotion_relative_span(text: &str) -> Option<Span> {
    let lowered = text.to_ascii_lowercase();
    let authority_position = MARKDOWN_INSTRUCTION_AUTHORITY_MARKERS
        .iter()
        .filter_map(|marker| lowered.find(marker))
        .min()?;
    let promotion_position = find_instruction_promotion_position(&lowered)?;

    if MARKDOWN_PROMOTION_NEGATION_MARKERS
        .iter()
        .filter_map(|marker| lowered.find(marker))
        .any(|position| position < promotion_position)
    {
        return None;
    }

    let anchor = authority_position.min(promotion_position);
    let search_window_start = anchor.saturating_sub(160);
    let search_window_end = (anchor + 160).min(lowered.len());
    let window = &lowered[search_window_start..search_window_end];

    MARKDOWN_UNTRUSTED_INPUT_MARKERS
        .iter()
        .find_map(|marker| {
            window.find(marker).map(|start| {
                Span::new(
                    search_window_start + start,
                    search_window_start + start + marker.len(),
                )
            })
        })
        .or_else(|| {
            MARKDOWN_UNTRUSTED_INPUT_MARKERS
                .iter()
                .find_map(|marker| lowered.find(marker).map(|start| (marker, start)))
                .map(|(marker, start)| Span::new(start, start + marker.len()))
        })
}

pub(crate) fn find_instruction_promotion_position(text: &str) -> Option<usize> {
    let with_as = MARKDOWN_INSTRUCTION_PROMOTION_VERBS_WITH_AS
        .iter()
        .filter_map(|verb| {
            text.find(verb)
                .and_then(|position| text[position + verb.len()..].find(" as ").map(|_| position))
        })
        .min();
    let direct = MARKDOWN_INSTRUCTION_PROMOTION_MARKERS
        .iter()
        .filter_map(|marker| text.find(marker))
        .min();

    match (with_as, direct) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

pub(crate) fn find_approval_bypass_instruction_relative_span(
    full_content: &str,
    region_start: usize,
    text: &str,
) -> Option<Span> {
    let lowered = text.to_ascii_lowercase();

    for marker in MARKDOWN_APPROVAL_BYPASS_DIRECTIVE_MARKERS {
        if let Some(start) = lowered.find(marker) {
            let marker_span = Span::new(start, start + marker.len());
            if approval_marker_is_suppressed(
                full_content,
                region_start,
                text,
                &lowered,
                &marker_span,
            ) {
                continue;
            }
            return Some(marker_span);
        }
    }

    for marker in MARKDOWN_APPROVAL_BYPASS_SUFFIX_MARKERS {
        if let Some(start) = lowered.find(marker) {
            let marker_span = Span::new(start, start + marker.len());
            if approval_marker_is_suppressed(
                full_content,
                region_start,
                text,
                &lowered,
                &marker_span,
            ) {
                continue;
            }

            let window = local_marker_window(&lowered, &marker_span, 96);
            if MARKDOWN_APPROVAL_SENSITIVE_ACTION_MARKERS
                .iter()
                .any(|candidate| window.contains(candidate))
            {
                return Some(marker_span);
            }
        }
    }

    None
}

pub(crate) fn approval_marker_is_suppressed(
    full_content: &str,
    region_start: usize,
    text: &str,
    lowered: &str,
    marker_span: &Span,
) -> bool {
    let window = local_marker_window(lowered, marker_span, 96);
    MARKDOWN_APPROVAL_SAFETY_MARKERS
        .iter()
        .any(|marker| window.contains(marker))
        || has_nearby_negative_section_header(
            full_content,
            region_start,
            text,
            marker_span.start_byte,
        )
}

pub(crate) fn local_marker_window<'a>(text: &'a str, marker_span: &Span, radius: usize) -> &'a str {
    let start = marker_span.start_byte.saturating_sub(radius);
    let end = (marker_span.end_byte + radius).min(text.len());
    &text[start..end]
}

pub(crate) fn has_nearby_negative_section_header(
    full_content: &str,
    region_start: usize,
    text: &str,
    marker_start: usize,
) -> bool {
    if has_local_negative_section_header(&text[..marker_start]) {
        return true;
    }

    let lookback_start = region_start.saturating_sub(160);
    has_local_negative_section_header(&full_content[lookback_start..region_start])
}

pub(crate) fn has_local_negative_section_header(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    MARKDOWN_NEGATIVE_SECTION_HEADERS
        .iter()
        .filter_map(|marker| lowered.rfind(marker).map(|position| (marker, position)))
        .max_by_key(|(_, position)| *position)
        .is_some_and(|(marker, position)| !lowered[position + marker.len()..].contains("\n\n"))
}

pub(crate) fn line_start_offsets(text: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (index, byte) in text.bytes().enumerate() {
        if byte == b'\n' && index + 1 < text.len() {
            starts.push(index + 1);
        }
    }
    starts
}

pub(crate) fn find_mutable_docker_image_in_command(command: &str) -> Option<Span> {
    let tokens = tokenize_markdown_shell_command(command);
    if tokens.len() < 3 {
        return None;
    }
    let docker_run_index = tokens.windows(2).position(|window| {
        normalized_markdown_shell_token(window[0].0).eq_ignore_ascii_case("docker")
            && normalized_markdown_shell_token(window[1].0).eq_ignore_ascii_case("run")
    })?;

    let mut index = docker_run_index + 2;
    while index < tokens.len() {
        let (token, start, end) = tokens[index];
        if token.starts_with('-') {
            index += markdown_docker_option_consumed_len(&tokens, index);
            continue;
        }

        let normalized = normalized_markdown_shell_token(token);
        if !looks_like_registry_distributed_docker_image(normalized) {
            return None;
        }
        if is_digest_pinned_docker_image(normalized) {
            return None;
        }
        let (trimmed_start, trimmed_end) = trimmed_token_span(token, start, end);
        return Some(Span::new(trimmed_start, trimmed_end));
    }

    None
}

pub(crate) fn find_docker_host_escape_in_command(command: &str) -> Option<Span> {
    let tokens = tokenize_markdown_shell_command(command);
    if tokens.len() < 3 {
        return None;
    }
    let docker_run_index = tokens.windows(2).position(|window| {
        normalized_markdown_shell_token(window[0].0).eq_ignore_ascii_case("docker")
            && normalized_markdown_shell_token(window[1].0).eq_ignore_ascii_case("run")
    })?;

    let mut index = docker_run_index + 2;
    while index < tokens.len() {
        let (token, start, end) = tokens[index];
        let normalized = normalized_markdown_shell_token(token);
        let normalized_lower = normalized.to_ascii_lowercase();

        if normalized_lower == "--privileged" {
            let (trimmed_start, trimmed_end) = trimmed_token_span(token, start, end);
            return Some(Span::new(trimmed_start, trimmed_end));
        }

        if matches!(normalized_lower.as_str(), "--network" | "--pid" | "--ipc")
            && let Some((next_token, next_start, next_end)) = tokens.get(index + 1)
            && normalized_markdown_shell_token(next_token).eq_ignore_ascii_case("host")
        {
            let (trimmed_start, _) = trimmed_token_span(token, start, end);
            let (_, trimmed_end) = trimmed_token_span(next_token, *next_start, *next_end);
            return Some(Span::new(trimmed_start, trimmed_end));
        }

        if matches!(
            normalized_lower.as_str(),
            "--network=host" | "--pid=host" | "--ipc=host"
        ) {
            let (trimmed_start, trimmed_end) = trimmed_token_span(token, start, end);
            return Some(Span::new(trimmed_start, trimmed_end));
        }

        if normalized_lower == "-v" || normalized_lower == "--volume" {
            if let Some((mount_token, mount_start, mount_end)) = tokens.get(index + 1)
                && let Some(relative) =
                    docker_socket_mount_span(mount_token, *mount_start, *mount_end)
            {
                return Some(relative);
            }
            index += markdown_docker_option_consumed_len(&tokens, index);
            continue;
        }

        if normalized_lower.starts_with("-v")
            && normalized.len() > 2
            && let Some(relative) = docker_socket_mount_span(token, start, end)
        {
            return Some(relative);
        }

        if normalized_lower.starts_with("--volume=")
            && let Some(relative) = docker_socket_mount_span(token, start, end)
        {
            return Some(relative);
        }

        if normalized_lower == "--mount" {
            if let Some((mount_token, mount_start, mount_end)) = tokens.get(index + 1)
                && let Some(relative) =
                    docker_socket_bind_mount_span(mount_token, *mount_start, *mount_end)
            {
                return Some(relative);
            }
            index += markdown_docker_option_consumed_len(&tokens, index);
            continue;
        }

        if normalized_lower.starts_with("--mount=")
            && let Some(relative) = docker_socket_bind_mount_span(token, start, end)
        {
            return Some(relative);
        }

        if token.starts_with('-') {
            index += markdown_docker_option_consumed_len(&tokens, index);
            continue;
        }

        index += 1;
    }

    None
}

pub(crate) fn tokenize_markdown_shell_command(command: &str) -> Vec<(&str, usize, usize)> {
    let bytes = command.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;

    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        if bytes[index] == b'\\' {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && !bytes[index].is_ascii_whitespace() && bytes[index] != b'\\' {
            index += 1;
        }
        if start < index {
            tokens.push((&command[start..index], start, index));
        }
    }

    tokens
}

pub(crate) fn markdown_docker_option_consumed_len(
    tokens: &[(&str, usize, usize)],
    index: usize,
) -> usize {
    let text = tokens[index].0;

    if text.starts_with("--volume=")
        || text.starts_with("--mount=")
        || text.starts_with("--network=")
        || text.starts_with("--pid=")
        || text.starts_with("--ipc=")
        || text.starts_with("--pull=")
        || (text.starts_with("-v") && text.len() > 2)
    {
        return 1;
    }

    if matches!(
        text,
        "-v" | "--volume"
            | "--mount"
            | "-e"
            | "--env"
            | "--env-file"
            | "-p"
            | "--publish"
            | "--network"
            | "--pid"
            | "--ipc"
            | "--name"
            | "-w"
            | "--workdir"
            | "-u"
            | "--user"
            | "--entrypoint"
            | "--platform"
            | "--pull"
    ) && tokens.get(index + 1).is_some()
    {
        return 2;
    }

    1
}

pub(crate) fn looks_like_registry_distributed_docker_image(text: &str) -> bool {
    let image = text.trim_matches(|ch| matches!(ch, '`' | '"' | '\''));
    image.contains('/')
        || image
            .split('/')
            .next()
            .is_some_and(|segment| segment.contains('.'))
}

pub(crate) fn normalized_markdown_shell_token(token: &str) -> &str {
    token.trim_matches(|ch: char| {
        matches!(
            ch,
            '`' | '"' | '\'' | ',' | '.' | ';' | ':' | ')' | '(' | '[' | ']'
        )
    })
}

pub(crate) fn trimmed_token_span(token: &str, start: usize, end: usize) -> (usize, usize) {
    let trimmed_start = start
        + token
            .find(|ch: char| {
                !matches!(
                    ch,
                    '`' | '"' | '\'' | ',' | '.' | ';' | ':' | ')' | '(' | '[' | ']'
                )
            })
            .unwrap_or(0);
    let trimmed_end = start
        + token
            .rfind(|ch: char| {
                !matches!(
                    ch,
                    '`' | '"' | '\'' | ',' | '.' | ';' | ':' | ')' | '(' | '[' | ']'
                )
            })
            .map(|index| index + 1)
            .unwrap_or(token.len());
    (trimmed_start, trimmed_end.min(end))
}

pub(crate) fn docker_socket_mount_span(token: &str, start: usize, end: usize) -> Option<Span> {
    let normalized = normalized_markdown_shell_token(token);
    let mount_value = normalized
        .strip_prefix("-v")
        .or_else(|| normalized.strip_prefix("--volume="))
        .unwrap_or(normalized);
    let marker = "/var/run/docker.sock";
    let lowered = mount_value.to_ascii_lowercase();
    let marker_start = lowered.find(marker)?;
    Some(Span::new(
        start + marker_start,
        (start + marker_start + marker.len()).min(end),
    ))
}

pub(crate) fn docker_socket_bind_mount_span(token: &str, start: usize, end: usize) -> Option<Span> {
    let normalized = normalized_markdown_shell_token(token);
    let mount_value = normalized.strip_prefix("--mount=").unwrap_or(normalized);
    let lowered = mount_value.to_ascii_lowercase();
    let marker = "/var/run/docker.sock";
    if !lowered.contains("type=bind") {
        return None;
    }
    let marker_start = lowered.find(marker)?;
    Some(Span::new(
        start + marker_start,
        (start + marker_start + marker.len()).min(end),
    ))
}

pub(crate) fn has_path_traversal_access(
    normalized_path: &str,
    snippet: &str,
    lowered: &str,
) -> bool {
    let has_access_verb = MARKDOWN_PATH_ACCESS_VERBS
        .iter()
        .any(|verb| lowered.contains(verb));
    if !has_access_verb {
        return false;
    }

    let Some(candidate) = extract_path_traversal_candidate(snippet) else {
        return false;
    };

    !is_safe_repo_local_relative_target(normalized_path, candidate)
}

pub(crate) fn extract_path_traversal_candidate(snippet: &str) -> Option<&str> {
    snippet.split_whitespace().find_map(|token| {
        let candidate = trim_path_token(token);
        if candidate.contains("../") || candidate.contains("..\\") {
            Some(candidate)
        } else {
            None
        }
    })
}

pub(crate) fn trim_path_token(token: &str) -> &str {
    token.trim_matches(|ch: char| {
        matches!(
            ch,
            '"' | '\''
                | '`'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '<'
                | '>'
                | ','
                | '.'
                | ';'
                | ':'
                | '!'
                | '?'
        )
    })
}

pub(crate) fn is_safe_repo_local_relative_target(normalized_path: &str, candidate: &str) -> bool {
    let Some(resolved) = lexically_resolve_repo_relative_path(normalized_path, candidate) else {
        return false;
    };

    MARKDOWN_SAFE_REPO_LOCAL_TARGET_SUFFIXES
        .iter()
        .any(|suffix| resolved == *suffix || resolved.ends_with(&format!("/{suffix}")))
}

pub(crate) fn lexically_resolve_repo_relative_path(
    normalized_path: &str,
    candidate: &str,
) -> Option<String> {
    let mut segments = normalized_parent_segments(normalized_path);
    let mut saw_parent = false;

    for part in candidate.replace('\\', "/").split('/') {
        match part {
            "" | "." => {}
            ".." => {
                saw_parent = true;
                segments.pop()?;
            }
            component => segments.push(component.to_owned()),
        }
    }

    saw_parent.then(|| segments.join("/"))
}

pub(crate) fn normalized_parent_segments(normalized_path: &str) -> Vec<String> {
    let mut parts = normalized_path
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    parts.pop();
    parts
}

pub(crate) fn is_fixture_like_tool_json_path(normalized_path: &str) -> bool {
    normalized_path.split('/').any(|segment| {
        matches!(
            segment.to_ascii_lowercase().as_str(),
            "test"
                | "tests"
                | "testdata"
                | "fixture"
                | "fixtures"
                | "example"
                | "examples"
                | "sample"
                | "samples"
        )
    })
}

pub(crate) fn is_expanded_mcp_client_variant_path(normalized_path: &str) -> bool {
    normalized_path.ends_with(".cursor/mcp.json")
        || normalized_path.ends_with(".vscode/mcp.json")
        || normalized_path.ends_with(".roo/mcp.json")
        || normalized_path.ends_with(".kiro/settings/mcp.json")
        || normalized_path.ends_with("gemini-extension.json")
        || normalized_path.ends_with("gemini.settings.json")
        || normalized_path.ends_with(".gemini/settings.json")
        || normalized_path.ends_with("vscode.settings.json")
}

pub(crate) fn is_fixture_like_claude_settings_path(normalized_path: &str) -> bool {
    normalized_path
        .split('/')
        .any(|segment| FIXTURE_PATH_SEGMENTS.contains(&segment.to_ascii_lowercase().as_str()))
}

pub(crate) fn is_fixture_like_expanded_mcp_client_variant_path(normalized_path: &str) -> bool {
    is_expanded_mcp_client_variant_path(normalized_path)
        && normalized_path.split('/').any(|segment| {
            matches!(
                segment.to_ascii_lowercase().as_str(),
                "test"
                    | "tests"
                    | "testdata"
                    | "fixture"
                    | "fixtures"
                    | "example"
                    | "examples"
                    | "sample"
                    | "samples"
            )
        })
}
