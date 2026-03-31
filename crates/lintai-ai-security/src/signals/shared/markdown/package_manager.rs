use lintai_api::Span;

const UV_PREFERENCE_MARKERS: &[&str] = &[
    "use uv not pip",
    "always use `uv` instead of `pip`",
    "use `uv` instead of `pip`",
    "always use uv instead of pip",
    "use uv instead of pip",
];

const CLAUDE_PIP_INSTALL_MARKERS: &[&str] = &["python -m pip install", "pip install"];
const PIP_GIT_INSTALL_MARKERS: &[&str] = &["python -m pip install", "pip install", "pip3 install"];
const NPM_INSTALL_MARKERS: &[&str] = &["npm install", "npm i", "pnpm install", "pnpm add"];

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

pub(crate) fn find_unpinned_pip_git_install_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_unpinned_pip_git_install_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_unpinned_pip_git_install_in_line(text);
    }

    None
}

pub(crate) fn find_pip_trusted_host_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_pip_trusted_host_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_pip_trusted_host_in_line(text);
    }

    None
}

pub(crate) fn find_pip_http_index_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_pip_http_index_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_pip_http_index_in_line(text);
    }

    None
}

pub(crate) fn find_npm_http_registry_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_npm_http_registry_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_npm_http_registry_in_line(text);
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

fn find_unpinned_pip_git_install_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut install_start = None;
    for marker in PIP_GIT_INSTALL_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            install_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = install_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    let Some(relative_git) = search_slice.find("git+https://") else {
        return None;
    };
    let url_start = search_start + relative_git;
    let url_end = line[url_start..]
        .find(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '`' | ')' | '>'))
        .map(|end| url_start + end)
        .unwrap_or(line.len());
    let url = &line[url_start..url_end];

    if has_immutable_git_ref(url) {
        return None;
    }

    Some(Span::new(url_start, url_end))
}

fn find_pip_trusted_host_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut install_start = None;
    for marker in PIP_GIT_INSTALL_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            install_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = install_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    let relative_flag = search_slice.find("--trusted-host")?;
    let start = search_start + relative_flag;
    Some(Span::new(start, start + "--trusted-host".len()))
}

fn find_pip_http_index_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut install_start = None;
    for marker in PIP_GIT_INSTALL_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            install_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = install_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    for marker in ["--index-url http://", "--extra-index-url http://"] {
        if let Some(relative_http) = search_slice.find(marker) {
            let start = search_start + relative_http + marker.len() - "http://".len();
            return Some(Span::new(start, start + "http://".len()));
        }
    }

    None
}

fn find_npm_http_registry_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut install_start = None;
    for marker in NPM_INSTALL_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            install_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = install_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    let marker = "--registry http://";
    let relative_http = search_slice.find(marker)?;
    let start = search_start + relative_http + marker.len() - "http://".len();
    Some(Span::new(start, start + "http://".len()))
}

fn has_immutable_git_ref(url: &str) -> bool {
    let Some(scheme_start) = url.find("git+https://") else {
        return false;
    };
    let after_scheme = &url[scheme_start + "git+https://".len()..];
    let Some(ref_sep) = after_scheme.rfind('@') else {
        return false;
    };
    let reference = after_scheme[ref_sep + 1..]
        .split('#')
        .next()
        .unwrap_or_default()
        .trim();
    reference.len() >= 7 && reference.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{
        find_claude_bare_pip_install_relative_span, find_npm_http_registry_relative_span,
        find_pip_http_index_relative_span, find_pip_trusted_host_relative_span,
        find_unpinned_pip_git_install_relative_span, has_uv_instead_of_pip_preference,
    };

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

    #[test]
    fn finds_unpinned_pip_git_install() {
        let content = "pip install git+https://github.com/pytorch/ao.git\n";
        assert!(find_unpinned_pip_git_install_relative_span(content).is_some());
    }

    #[test]
    fn ignores_commit_pinned_pip_git_install() {
        let content = r#"pip3 install "pkg @ git+https://github.com/org/repo.git@8a1a0ec""#;
        assert_eq!(find_unpinned_pip_git_install_relative_span(content), None);
    }

    #[test]
    fn finds_branch_pinned_pip_git_install_as_mutable() {
        let content =
            "pip install git+https://github.com/facebookresearch/xformers.git@main#egg=xformers\n";
        assert!(find_unpinned_pip_git_install_relative_span(content).is_some());
    }

    #[test]
    fn finds_pip_trusted_host() {
        let content = "pip install --trusted-host pypi.example.test demo\n";
        assert!(find_pip_trusted_host_relative_span(content).is_some());
    }

    #[test]
    fn ignores_non_pip_trusted_host() {
        let content = "curl --trusted-host pypi.example.test https://example.test/install.sh\n";
        assert_eq!(find_pip_trusted_host_relative_span(content), None);
    }

    #[test]
    fn finds_pip_http_index() {
        let content = "pip install --index-url http://pypi.example.test/simple demo\n";
        assert!(find_pip_http_index_relative_span(content).is_some());
    }

    #[test]
    fn ignores_pip_https_index() {
        let content = "pip install --index-url https://pypi.example.test/simple demo\n";
        assert_eq!(find_pip_http_index_relative_span(content), None);
    }

    #[test]
    fn finds_npm_http_registry() {
        let content = "npm install demo --registry http://registry.example.test/\n";
        assert!(find_npm_http_registry_relative_span(content).is_some());
    }

    #[test]
    fn ignores_npm_https_registry() {
        let content = "pnpm add demo --registry https://registry.example.test/\n";
        assert_eq!(find_npm_http_registry_relative_span(content), None);
    }
}
