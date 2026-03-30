use lintai_api::Span;

use super::super::common::{
    contains_ascii_case_insensitive, find_ascii_case_insensitive, has_download_exec,
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

pub(crate) fn find_private_key_relative_span(text: &str) -> Option<Span> {
    if contains_ascii_case_insensitive(text, "redacted")
        || contains_ascii_case_insensitive(text, "your_private_key")
        || contains_ascii_case_insensitive(text, "example private key")
    {
        return None;
    }

    MARKDOWN_PRIVATE_KEY_MARKERS.iter().find_map(|marker| {
        let pem_marker = format!("-----{marker}-----");
        find_ascii_case_insensitive(text, &pem_marker).map(|start| {
            let marker_start = pem_marker.find(marker).unwrap_or_default();
            Span::new(start + marker_start, start + marker_start + marker.len())
        })
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
