use lintai_api::Span;

use super::docker_args::is_digest_pinned_docker_image;
use super::tokens::{
    docker_socket_bind_mount_span, docker_socket_mount_span,
    looks_like_registry_distributed_docker_image, markdown_docker_option_consumed_len,
    normalized_markdown_shell_token, tokenize_markdown_shell_command, trimmed_token_span,
};

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
