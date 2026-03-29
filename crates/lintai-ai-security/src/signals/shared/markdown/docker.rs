use lintai_api::Span;
use serde_json::Value;

use crate::helpers::contains_dynamic_reference;

use super::super::common::{contains_ascii_case_insensitive, has_download_exec};
use super::super::json::contains_template_placeholder;
use super::tokens::{
    docker_socket_bind_mount_span, docker_socket_mount_span,
    looks_like_registry_distributed_docker_image, markdown_docker_option_consumed_len,
    normalized_markdown_shell_token, tokenize_markdown_shell_command, trimmed_token_span,
};

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
