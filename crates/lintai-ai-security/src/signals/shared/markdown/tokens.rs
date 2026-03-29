use lintai_api::Span;

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
