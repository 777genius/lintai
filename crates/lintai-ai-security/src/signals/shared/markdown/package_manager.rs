use lintai_api::Span;

const UV_PREFERENCE_MARKERS: &[&str] = &[
    "use uv not pip",
    "always use `uv` instead of `pip`",
    "use `uv` instead of `pip`",
    "always use uv instead of pip",
    "use uv instead of pip",
];

const CLAUDE_PIP_INSTALL_MARKERS: &[&str] = &["python -m pip install", "pip install"];

pub(crate) fn has_uv_instead_of_pip_preference(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    UV_PREFERENCE_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
}

pub(crate) fn find_claude_bare_pip_install_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_claude_bare_pip_install_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_claude_bare_pip_install_in_line(text);
    }

    None
}

fn find_claude_bare_pip_install_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let Some(claude_start) = lowered.find("claude:") else {
        return None;
    };
    if lowered[claude_start..].contains("uv pip install") {
        return None;
    }

    let search_start = claude_start + "claude:".len();
    let search_slice = &lowered[search_start..];
    for marker in CLAUDE_PIP_INSTALL_MARKERS {
        if let Some(relative) = search_slice.find(marker) {
            let start = search_start + relative;
            return Some(Span::new(start, start + marker.len()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{find_claude_bare_pip_install_relative_span, has_uv_instead_of_pip_preference};

    #[test]
    fn finds_claude_bare_pip_install_in_transcript() {
        let content = "Claude: pip install pytest\n";
        assert!(find_claude_bare_pip_install_relative_span(content).is_some());
    }

    #[test]
    fn ignores_uv_pip_install_in_transcript() {
        let content = "Claude: uv pip install pytest\n";
        assert_eq!(find_claude_bare_pip_install_relative_span(content), None);
    }

    #[test]
    fn detects_uv_preference_markers() {
        assert!(has_uv_instead_of_pip_preference(
            "Always use `uv` instead of `pip` for Python packages"
        ));
    }
}
