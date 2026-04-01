use crate::signals::shared::common::find_command_tls_bypass_relative_span;
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
const PIP_CONFIG_SET_MARKERS: &[&str] = &[
    "python -m pip config set",
    "pip config set",
    "pip3 config set",
];
const NPM_INSTALL_MARKERS: &[&str] = &[
    "npm install",
    "npm i",
    "pnpm install",
    "pnpm add",
    "yarn add",
    "bun add",
];
const JS_PACKAGE_CONFIG_MARKERS: &[&str] =
    &["npm config set", "pnpm config set", "yarn config set"];
const CARGO_INSTALL_MARKERS: &[&str] = &["cargo install"];
const GIT_CLONE_MARKERS: &[&str] = &["git clone"];
const GIT_REMOTE_ADD_MARKERS: &[&str] = &["git remote add"];
const SAFETY_WARNING_MARKERS: &[&str] = &[
    "do not use",
    "don't use",
    "avoid",
    "replace with",
    "instead of",
];

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

pub(crate) fn find_pip_http_git_install_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_pip_http_git_install_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_pip_http_git_install_in_line(text);
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

pub(crate) fn find_pip_http_find_links_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_pip_http_find_links_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_pip_http_find_links_in_line(text);
    }

    None
}

pub(crate) fn find_pip_config_http_index_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_pip_config_http_index_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_pip_config_http_index_in_line(text);
    }

    None
}

pub(crate) fn find_pip_config_http_find_links_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_pip_config_http_find_links_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_pip_config_http_find_links_in_line(text);
    }

    None
}

pub(crate) fn find_pip_config_trusted_host_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_pip_config_trusted_host_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_pip_config_trusted_host_in_line(text);
    }

    None
}

pub(crate) fn find_network_tls_bypass_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_network_tls_bypass_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_network_tls_bypass_in_line(text);
    }

    None
}

pub(crate) fn find_pip_http_source_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_pip_http_source_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_pip_http_source_in_line(text);
    }

    None
}

pub(crate) fn find_js_package_config_http_registry_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_js_package_config_http_registry_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_js_package_config_http_registry_in_line(text);
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

pub(crate) fn find_js_package_strict_ssl_false_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_js_package_strict_ssl_false_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_js_package_strict_ssl_false_in_line(text);
    }

    None
}

pub(crate) fn find_npm_http_source_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_npm_http_source_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_npm_http_source_in_line(text);
    }

    None
}

pub(crate) fn find_cargo_http_git_install_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_cargo_http_git_install_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_cargo_http_git_install_in_line(text);
    }

    None
}

pub(crate) fn find_cargo_http_index_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_cargo_http_index_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_cargo_http_index_in_line(text);
    }

    None
}

pub(crate) fn find_git_http_clone_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_git_http_clone_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_git_http_clone_in_line(text);
    }

    None
}

pub(crate) fn find_git_http_remote_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_git_http_remote_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_git_http_remote_in_line(text);
    }

    None
}

pub(crate) fn find_git_sslverify_false_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_git_sslverify_false_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_git_sslverify_false_in_line(text);
    }

    None
}

pub(crate) fn find_git_ssl_no_verify_relative_span(text: &str) -> Option<Span> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if let Some(relative) = find_git_ssl_no_verify_in_line(line) {
            return Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        }
        offset += line.len();
    }

    if !text.ends_with('\n') {
        return find_git_ssl_no_verify_in_line(text);
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

fn find_pip_http_git_install_in_line(line: &str) -> Option<Span> {
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
    let relative_http = search_slice.find("git+http://")?;
    let start = search_start + relative_http + "git+".len();
    Some(Span::new(start, start + "http://".len()))
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
    for marker in [
        "--index-url http://",
        "--extra-index-url http://",
        "--index-url=http://",
        "--extra-index-url=http://",
        "-i http://",
    ] {
        if let Some(relative_http) = search_slice.find(marker) {
            let start = search_start + relative_http + marker.len() - "http://".len();
            return Some(Span::new(start, start + "http://".len()));
        }
    }

    None
}

fn find_pip_http_source_in_line(line: &str) -> Option<Span> {
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
    let relative_http = search_slice.find("http://")?;
    let absolute_http = search_start + relative_http;

    for marker in [
        "--index-url ",
        "--extra-index-url ",
        "--index-url=",
        "--extra-index-url=",
        "-i ",
    ] {
        if let Some(relative_flag) = search_slice.find(marker) {
            let flag_start = search_start + relative_flag;
            let flag_end = flag_start + marker.len();
            if flag_end == absolute_http {
                return None;
            }
        }
    }

    Some(Span::new(absolute_http, absolute_http + "http://".len()))
}

fn find_pip_http_find_links_in_line(line: &str) -> Option<Span> {
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
    for marker in ["--find-links http://", "--find-links=http://", "-f http://"] {
        if let Some(relative_http) = search_slice.find(marker) {
            let start = search_start + relative_http + marker.len() - "http://".len();
            return Some(Span::new(start, start + "http://".len()));
        }
    }

    None
}

fn find_pip_config_http_index_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut command_start = None;
    for marker in PIP_CONFIG_SET_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            command_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = command_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    for marker in [
        "global.index-url http://",
        "global.extra-index-url http://",
        "global.index-url=http://",
        "global.extra-index-url=http://",
    ] {
        if let Some(relative_http) = search_slice.find(marker) {
            let start = search_start + relative_http + marker.len() - "http://".len();
            return Some(Span::new(start, start + "http://".len()));
        }
    }

    None
}

fn find_pip_config_http_find_links_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut command_start = None;
    for marker in PIP_CONFIG_SET_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            command_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = command_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    for marker in ["global.find-links http://", "global.find-links=http://"] {
        if let Some(relative_http) = search_slice.find(marker) {
            let start = search_start + relative_http + marker.len() - "http://".len();
            return Some(Span::new(start, start + "http://".len()));
        }
    }

    None
}

fn find_pip_config_trusted_host_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut command_start = None;
    for marker in PIP_CONFIG_SET_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            command_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = command_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    for marker in ["global.trusted-host ", "global.trusted-host="] {
        if let Some(relative_marker) = search_slice.find(marker) {
            let start = search_start + relative_marker;
            return Some(Span::new(start, start + "global.trusted-host".len()));
        }
    }

    None
}

fn find_network_tls_bypass_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    if SAFETY_WARNING_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return None;
    }

    if !(lowered.contains("curl ")
        || lowered.contains("wget ")
        || lowered.contains("invoke-webrequest")
        || lowered.contains("http://")
        || lowered.contains("https://")
        || lowered.contains("fetch(")
        || lowered.contains("axios"))
    {
        return None;
    }

    if let Some(start) = lowered.find("--no-check-certificate") {
        return Some(Span::new(start, start + "--no-check-certificate".len()));
    }

    if let Some(start) = lowered.find("-skipcertificatecheck") {
        return Some(Span::new(start, start + "-skipcertificatecheck".len()));
    }

    find_command_tls_bypass_relative_span(line)
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
    for marker in ["--registry http://", "--registry=http://"] {
        if let Some(relative_http) = search_slice.find(marker) {
            let start = search_start + relative_http + marker.len() - "http://".len();
            return Some(Span::new(start, start + "http://".len()));
        }
    }

    None
}

fn find_js_package_config_http_registry_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut command_start = None;
    for marker in JS_PACKAGE_CONFIG_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            command_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = command_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    for marker in ["registry http://", "registry=http://"] {
        if let Some(relative_http) = search_slice.find(marker) {
            let start = search_start + relative_http + marker.len() - "http://".len();
            return Some(Span::new(start, start + "http://".len()));
        }
    }

    None
}

fn find_npm_http_source_in_line(line: &str) -> Option<Span> {
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
    let relative_http = search_slice.find("http://")?;
    let absolute_http = search_start + relative_http;

    for marker in ["--registry ", "--registry="] {
        if let Some(relative_flag) = search_slice.find(marker) {
            let flag_start = search_start + relative_flag;
            let flag_end = flag_start + marker.len();
            if flag_end == absolute_http {
                return None;
            }
        }
    }

    Some(Span::new(absolute_http, absolute_http + "http://".len()))
}

fn find_js_package_strict_ssl_false_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut command_start = None;
    for marker in JS_PACKAGE_CONFIG_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            command_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = command_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    for marker in ["strict-ssl false", "strict-ssl=false"] {
        if let Some(relative_marker) = search_slice.find(marker) {
            let start = search_start + relative_marker;
            return Some(Span::new(start, start + marker.len()));
        }
    }

    None
}

fn find_cargo_http_git_install_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut install_start = None;
    for marker in CARGO_INSTALL_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            install_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = install_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    for marker in ["--git http://", "--git=http://"] {
        if let Some(relative_http) = search_slice.find(marker) {
            let start = search_start + relative_http + marker.len() - "http://".len();
            return Some(Span::new(start, start + "http://".len()));
        }
    }

    None
}

fn find_cargo_http_index_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut install_start = None;
    for marker in CARGO_INSTALL_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            install_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = install_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    for marker in ["--index http://", "--index=http://"] {
        if let Some(relative_http) = search_slice.find(marker) {
            let start = search_start + relative_http + marker.len() - "http://".len();
            return Some(Span::new(start, start + "http://".len()));
        }
    }

    None
}

fn find_git_http_clone_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut clone_start = None;
    for marker in GIT_CLONE_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            clone_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = clone_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    let relative_http = search_slice.find("http://")?;
    let start = search_start + relative_http;
    Some(Span::new(start, start + "http://".len()))
}

fn find_git_http_remote_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    let mut command_start = None;
    for marker in GIT_REMOTE_ADD_MARKERS {
        if let Some(relative) = lowered.find(marker) {
            command_start = Some(relative + marker.len());
            break;
        }
    }
    let Some(search_start) = command_start else {
        return None;
    };

    let search_slice = &lowered[search_start..];
    let relative_http = search_slice.find("http://")?;
    let start = search_start + relative_http;
    Some(Span::new(start, start + "http://".len()))
}

fn find_git_sslverify_false_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    if SAFETY_WARNING_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return None;
    }

    let Some(command_start) = lowered.find("git config") else {
        return None;
    };

    let search_slice = &lowered[command_start + "git config".len()..];
    for marker in ["http.sslverify false", "http.sslverify=false"] {
        if let Some(relative_marker) = search_slice.find(marker) {
            let start = command_start + "git config".len() + relative_marker;
            return Some(Span::new(start, start + marker.len()));
        }
    }

    None
}

fn find_git_ssl_no_verify_in_line(line: &str) -> Option<Span> {
    let lowered = line.to_ascii_lowercase();
    if SAFETY_WARNING_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return None;
    }

    for marker in ["git_ssl_no_verify=1", "git_ssl_no_verify=true"] {
        if let Some(relative_marker) = lowered.find(marker) {
            let search_start = relative_marker + marker.len();
            if lowered[search_start..].contains("git ") {
                return Some(Span::new(relative_marker, relative_marker + marker.len()));
            }
        }
    }

    None
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
        find_cargo_http_git_install_relative_span, find_cargo_http_index_relative_span,
        find_claude_bare_pip_install_relative_span, find_git_http_clone_relative_span,
        find_git_http_remote_relative_span, find_git_sslverify_false_relative_span,
        find_js_package_config_http_registry_relative_span,
        find_js_package_strict_ssl_false_relative_span, find_network_tls_bypass_relative_span,
        find_npm_http_registry_relative_span, find_npm_http_source_relative_span,
        find_pip_config_http_find_links_relative_span, find_pip_config_http_index_relative_span,
        find_pip_config_trusted_host_relative_span, find_pip_http_find_links_relative_span,
        find_pip_http_git_install_relative_span, find_pip_http_index_relative_span,
        find_pip_http_source_relative_span, find_pip_trusted_host_relative_span,
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
    fn finds_pip_http_git_install() {
        let content = "pip install git+http://git.example.test/demo.git\n";
        assert!(find_pip_http_git_install_relative_span(content).is_some());
    }

    #[test]
    fn finds_python_dash_m_pip_http_git_install() {
        let content = "python -m pip install git+http://git.example.test/demo.git\n";
        assert!(find_pip_http_git_install_relative_span(content).is_some());
    }

    #[test]
    fn ignores_pip_https_git_install_for_http_git_rule() {
        let content = "pip install git+https://github.com/pytorch/ao.git\n";
        assert_eq!(find_pip_http_git_install_relative_span(content), None);
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
    fn finds_pip_http_index_short_flag() {
        let content = "pip install -i http://pypi.example.test/simple demo\n";
        assert!(find_pip_http_index_relative_span(content).is_some());
    }

    #[test]
    fn finds_pip_http_index_equals_form() {
        let content = "pip install --index-url=http://pypi.example.test/simple demo\n";
        assert!(find_pip_http_index_relative_span(content).is_some());
    }

    #[test]
    fn ignores_pip_https_index() {
        let content = "pip install --index-url https://pypi.example.test/simple demo\n";
        assert_eq!(find_pip_http_index_relative_span(content), None);
    }

    #[test]
    fn finds_pip_http_find_links() {
        let content = "pip install --find-links http://packages.example.test/simple demo\n";
        assert!(find_pip_http_find_links_relative_span(content).is_some());
    }

    #[test]
    fn finds_pip_http_find_links_equals_form() {
        let content = "pip install --find-links=http://packages.example.test/simple demo\n";
        assert!(find_pip_http_find_links_relative_span(content).is_some());
    }

    #[test]
    fn finds_pip_http_find_links_short_flag() {
        let content = "python -m pip install -f http://packages.example.test/simple demo\n";
        assert!(find_pip_http_find_links_relative_span(content).is_some());
    }

    #[test]
    fn finds_pip_config_http_index() {
        let content = "pip config set global.index-url http://pypi.example.test/simple\n";
        assert!(find_pip_config_http_index_relative_span(content).is_some());
    }

    #[test]
    fn finds_python_dash_m_pip_config_http_extra_index_equals_form() {
        let content =
            "python -m pip config set global.extra-index-url=http://pypi.example.test/simple\n";
        assert!(find_pip_config_http_index_relative_span(content).is_some());
    }

    #[test]
    fn ignores_pip_config_https_index() {
        let content = "pip config set global.index-url https://pypi.example.test/simple\n";
        assert_eq!(find_pip_config_http_index_relative_span(content), None);
    }

    #[test]
    fn finds_pip_config_http_find_links() {
        let content = "pip config set global.find-links http://packages.example.test/simple\n";
        assert!(find_pip_config_http_find_links_relative_span(content).is_some());
    }

    #[test]
    fn finds_pip3_config_http_find_links_equals_form() {
        let content = "pip3 config set global.find-links=http://packages.example.test/simple\n";
        assert!(find_pip_config_http_find_links_relative_span(content).is_some());
    }

    #[test]
    fn ignores_pip_config_https_find_links() {
        let content = "pip config set global.find-links https://packages.example.test/simple\n";
        assert_eq!(find_pip_config_http_find_links_relative_span(content), None);
    }

    #[test]
    fn finds_pip_config_trusted_host() {
        let content = "pip config set global.trusted-host pypi.example.test\n";
        assert!(find_pip_config_trusted_host_relative_span(content).is_some());
    }

    #[test]
    fn finds_python_dash_m_pip_config_trusted_host_equals_form() {
        let content = "python -m pip config set global.trusted-host=pypi.example.test\n";
        assert!(find_pip_config_trusted_host_relative_span(content).is_some());
    }

    #[test]
    fn ignores_pip_config_unrelated_key() {
        let content = "pip config set global.timeout 60\n";
        assert_eq!(find_pip_config_trusted_host_relative_span(content), None);
    }

    #[test]
    fn finds_network_tls_bypass_with_curl_insecure() {
        let content = "curl --insecure https://internal.test/bootstrap.sh -o bootstrap.sh\n";
        assert!(find_network_tls_bypass_relative_span(content).is_some());
    }

    #[test]
    fn finds_network_tls_bypass_with_wget_no_check_certificate() {
        let content = "wget --no-check-certificate https://internal.test/bootstrap.tgz\n";
        assert!(find_network_tls_bypass_relative_span(content).is_some());
    }

    #[test]
    fn finds_network_tls_bypass_with_invoke_webrequest_skip_certificate_check() {
        let content =
            "Invoke-WebRequest https://internal.test/bootstrap.ps1 -SkipCertificateCheck\n";
        assert!(find_network_tls_bypass_relative_span(content).is_some());
    }

    #[test]
    fn finds_network_tls_bypass_with_node_tls_reject_unauthorized() {
        let content =
            "NODE_TLS_REJECT_UNAUTHORIZED=0 node fetch.js https://internal.test/bootstrap.json\n";
        assert!(find_network_tls_bypass_relative_span(content).is_some());
    }

    #[test]
    fn ignores_network_tls_bypass_in_safety_guidance() {
        let content = "Do not use curl --insecure https://internal.test/bootstrap.sh\n";
        assert_eq!(find_network_tls_bypass_relative_span(content), None);
    }

    #[test]
    fn ignores_powershell_network_tls_bypass_in_safety_guidance() {
        let content =
            "Avoid Invoke-WebRequest https://internal.test/bootstrap.ps1 -SkipCertificateCheck\n";
        assert_eq!(find_network_tls_bypass_relative_span(content), None);
    }

    #[test]
    fn ignores_secure_network_command() {
        let content = "curl https://internal.test/bootstrap.sh -o bootstrap.sh\n";
        assert_eq!(find_network_tls_bypass_relative_span(content), None);
    }

    #[test]
    fn ignores_pip_https_find_links() {
        let content = "pip install --find-links https://packages.example.test/simple demo\n";
        assert_eq!(find_pip_http_find_links_relative_span(content), None);
    }

    #[test]
    fn finds_pip_http_source() {
        let content = "pip install http://packages.example.test/demo.whl\n";
        assert!(find_pip_http_source_relative_span(content).is_some());
    }

    #[test]
    fn finds_python_dash_m_pip_http_source() {
        let content = "python -m pip install http://packages.example.test/demo.whl\n";
        assert!(find_pip_http_source_relative_span(content).is_some());
    }

    #[test]
    fn ignores_pip_http_index_for_direct_source_rule() {
        let content = "pip install --index-url http://pypi.example.test/simple demo\n";
        assert_eq!(find_pip_http_source_relative_span(content), None);
    }

    #[test]
    fn ignores_pip_https_source() {
        let content = "pip install https://packages.example.test/demo.whl\n";
        assert_eq!(find_pip_http_source_relative_span(content), None);
    }

    #[test]
    fn finds_npm_http_registry() {
        let content = "npm install demo --registry http://registry.example.test/\n";
        assert!(find_npm_http_registry_relative_span(content).is_some());
    }

    #[test]
    fn finds_npm_http_registry_equals_form() {
        let content = "yarn add demo --registry=http://registry.example.test/\n";
        assert!(find_npm_http_registry_relative_span(content).is_some());
    }

    #[test]
    fn ignores_npm_https_registry() {
        let content = "pnpm add demo --registry https://registry.example.test/\n";
        assert_eq!(find_npm_http_registry_relative_span(content), None);
    }

    #[test]
    fn finds_npm_http_source() {
        let content = "npm install http://registry.example.test/demo.tgz\n";
        assert!(find_npm_http_source_relative_span(content).is_some());
    }

    #[test]
    fn finds_pnpm_http_source() {
        let content = "pnpm add http://registry.example.test/demo.tgz\n";
        assert!(find_npm_http_source_relative_span(content).is_some());
    }

    #[test]
    fn finds_yarn_http_source() {
        let content = "yarn add http://registry.example.test/demo.tgz\n";
        assert!(find_npm_http_source_relative_span(content).is_some());
    }

    #[test]
    fn finds_bun_http_source() {
        let content = "bun add http://registry.example.test/demo.tgz\n";
        assert!(find_npm_http_source_relative_span(content).is_some());
    }

    #[test]
    fn ignores_npm_http_registry_for_direct_source_rule() {
        let content = "npm install demo --registry http://registry.example.test/\n";
        assert_eq!(find_npm_http_source_relative_span(content), None);
    }

    #[test]
    fn finds_npm_strict_ssl_false() {
        let content = "npm config set strict-ssl false\n";
        assert!(find_js_package_strict_ssl_false_relative_span(content).is_some());
    }

    #[test]
    fn finds_npm_config_http_registry() {
        let content = "npm config set registry http://registry.example.test/\n";
        assert!(find_js_package_config_http_registry_relative_span(content).is_some());
    }

    #[test]
    fn finds_yarn_config_http_registry_equals_form() {
        let content = "yarn config set registry=http://registry.example.test/\n";
        assert!(find_js_package_config_http_registry_relative_span(content).is_some());
    }

    #[test]
    fn ignores_pnpm_config_https_registry() {
        let content = "pnpm config set registry https://registry.example.test/\n";
        assert_eq!(
            find_js_package_config_http_registry_relative_span(content),
            None
        );
    }

    #[test]
    fn finds_pnpm_strict_ssl_false_equals_form() {
        let content = "pnpm config set strict-ssl=false\n";
        assert!(find_js_package_strict_ssl_false_relative_span(content).is_some());
    }

    #[test]
    fn finds_yarn_strict_ssl_false() {
        let content = "yarn config set strict-ssl false\n";
        assert!(find_js_package_strict_ssl_false_relative_span(content).is_some());
    }

    #[test]
    fn ignores_npm_strict_ssl_true() {
        let content = "npm config set strict-ssl true\n";
        assert_eq!(
            find_js_package_strict_ssl_false_relative_span(content),
            None
        );
    }

    #[test]
    fn ignores_npm_https_source() {
        let content = "npm install https://registry.example.test/demo.tgz\n";
        assert_eq!(find_npm_http_source_relative_span(content), None);
    }

    #[test]
    fn finds_yarn_http_registry() {
        let content = "yarn add demo --registry http://registry.example.test/\n";
        assert!(find_npm_http_registry_relative_span(content).is_some());
    }

    #[test]
    fn finds_bun_http_registry() {
        let content = "bun add demo --registry http://registry.example.test/\n";
        assert!(find_npm_http_registry_relative_span(content).is_some());
    }

    #[test]
    fn finds_cargo_http_git_install() {
        let content = "cargo install --git http://git.example.test/demo.git\n";
        assert!(find_cargo_http_git_install_relative_span(content).is_some());
    }

    #[test]
    fn finds_cargo_http_git_install_equals_form() {
        let content = "cargo install --git=http://git.example.test/demo.git\n";
        assert!(find_cargo_http_git_install_relative_span(content).is_some());
    }

    #[test]
    fn ignores_cargo_https_git_install() {
        let content = "cargo install --git https://git.example.test/demo.git\n";
        assert_eq!(find_cargo_http_git_install_relative_span(content), None);
    }

    #[test]
    fn finds_cargo_http_index() {
        let content = "cargo install ripgrep --index http://index.example.test/\n";
        assert!(find_cargo_http_index_relative_span(content).is_some());
    }

    #[test]
    fn finds_cargo_http_index_equals_form() {
        let content = "cargo install ripgrep --index=http://index.example.test/\n";
        assert!(find_cargo_http_index_relative_span(content).is_some());
    }

    #[test]
    fn ignores_cargo_https_index() {
        let content = "cargo install ripgrep --index https://index.example.test/\n";
        assert_eq!(find_cargo_http_index_relative_span(content), None);
    }

    #[test]
    fn finds_git_http_clone() {
        let content = "git clone http://git.example.test/demo.git\n";
        assert!(find_git_http_clone_relative_span(content).is_some());
    }

    #[test]
    fn finds_git_http_clone_with_depth_flag() {
        let content = "git clone --depth 1 http://git.example.test/demo.git\n";
        assert!(find_git_http_clone_relative_span(content).is_some());
    }

    #[test]
    fn ignores_git_https_clone() {
        let content = "git clone https://github.com/acme/demo.git\n";
        assert_eq!(find_git_http_clone_relative_span(content), None);
    }

    #[test]
    fn finds_git_http_remote_add() {
        let content = "git remote add origin http://git.example.test/demo.git\n";
        assert!(find_git_http_remote_relative_span(content).is_some());
    }

    #[test]
    fn finds_git_http_remote_add_with_flag() {
        let content = "git remote add --fetch origin http://git.example.test/demo.git\n";
        assert!(find_git_http_remote_relative_span(content).is_some());
    }

    #[test]
    fn ignores_git_https_remote_add() {
        let content = "git remote add origin https://github.com/acme/demo.git\n";
        assert_eq!(find_git_http_remote_relative_span(content), None);
    }

    #[test]
    fn finds_git_sslverify_false() {
        let content = "git config http.sslVerify false\n";
        assert!(find_git_sslverify_false_relative_span(content).is_some());
    }

    #[test]
    fn finds_git_sslverify_false_equals_form() {
        let content = "git config --global http.sslVerify=false\n";
        assert!(find_git_sslverify_false_relative_span(content).is_some());
    }

    #[test]
    fn ignores_git_sslverify_true() {
        let content = "git config http.sslVerify true\n";
        assert_eq!(find_git_sslverify_false_relative_span(content), None);
    }

    #[test]
    fn ignores_git_sslverify_false_in_safety_guidance() {
        let content = "Do not use git config http.sslVerify false\n";
        assert_eq!(find_git_sslverify_false_relative_span(content), None);
    }
}
