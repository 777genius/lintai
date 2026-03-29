use lintai_api::Span;

use crate::helpers::find_url_userinfo_span;

use super::super::{HookSignals, SignalWorkBudget};
use super::common::{find_literal_value_after_prefixes_case_insensitive, has_download_exec};
pub(crate) const HOOK_SECRET_MARKERS: &[&str] = &[
    "openai_api_key",
    "anthropic_api_key",
    "aws_secret_access_key",
    "authorization:",
    "bearer ",
];

#[derive(Clone, Copy)]
pub(crate) struct HookToken<'a> {
    pub(crate) text: &'a str,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct McpCommandSignalSpan {
    pub(crate) inline_download_exec: Option<Span>,
    pub(crate) network_tls_bypass: Option<Span>,
    pub(crate) mutable_docker_image: Option<Span>,
    pub(crate) mutable_docker_pull: Option<Span>,
    pub(crate) sensitive_docker_mount: Option<Span>,
    pub(crate) dangerous_docker_flag: Option<Span>,
}

pub(crate) fn collect_hook_line(
    signals: &mut HookSignals,
    line: &str,
    offset: usize,
    metrics: &mut SignalWorkBudget,
) {
    metrics.hook_lines_visited += 1;
    if line.trim_start().starts_with('#') {
        return;
    }

    let line_span = Span::new(offset, offset + line.len());
    signals.non_comment_line_spans.push(line_span.clone());

    let lowered = line.to_ascii_lowercase();
    let tokens = shell_tokens(line);
    metrics.hook_tokens_visited += tokens.len();

    if signals.download_exec_span.is_none() && has_download_exec(&lowered) {
        signals.download_exec_span = Some(line_span.clone());
    }

    if signals.base64_exec_span.is_none() && has_base64_exec(&lowered) {
        signals.base64_exec_span = Some(line_span.clone());
    }

    if signals.secret_exfil_span.is_none() {
        let has_network = lowered.contains("curl ") || lowered.contains("wget ");
        if has_network
            && HOOK_SECRET_MARKERS
                .iter()
                .any(|marker| lowered.contains(marker))
        {
            signals.secret_exfil_span = Some(line_span.clone());
        }
    }

    if signals.plain_http_secret_exfil_span.is_none()
        && lowered.contains("http://")
        && HOOK_SECRET_MARKERS
            .iter()
            .any(|marker| lowered.contains(marker))
    {
        if let Some(relative) = lowered.find("http://") {
            signals.plain_http_secret_exfil_span = Some(Span::new(
                offset + relative,
                offset + relative + "http://".len(),
            ));
        }
    }

    if signals.static_auth_exposure_span.is_none() {
        if let Some(relative) = find_url_userinfo_span(line) {
            signals.static_auth_exposure_span = Some(Span::new(
                offset + relative.start_byte,
                offset + relative.end_byte,
            ));
        } else if lowered.contains("curl ") {
            if let Some(relative) = find_literal_value_after_prefixes_case_insensitive(
                line,
                &["authorization: bearer ", "authorization: basic "],
            ) {
                signals.static_auth_exposure_span = Some(Span::new(
                    offset + relative.start_byte,
                    offset + relative.end_byte,
                ));
            }
        }
    }

    if signals.tls_bypass_span.is_none() {
        let has_curl = tokens.iter().any(|token| token.text == "curl");
        let has_wget = tokens.iter().any(|token| token.text == "wget");
        let has_network_context = has_curl
            || has_wget
            || tokens
                .iter()
                .any(|token| token.text.contains("http://") || token.text.contains("https://"));

        if has_curl {
            if let Some(token) = tokens
                .iter()
                .find(|token| matches!(token.text, "-k" | "--insecure"))
            {
                signals.tls_bypass_span = Some(Span::new(offset + token.start, offset + token.end));
                return;
            }
        }

        if has_wget {
            if let Some(token) = tokens
                .iter()
                .find(|token| token.text == "--no-check-certificate")
            {
                signals.tls_bypass_span = Some(Span::new(offset + token.start, offset + token.end));
                return;
            }
        }

        if has_network_context {
            if let Some(token) = tokens
                .iter()
                .find(|token| token.text == "NODE_TLS_REJECT_UNAUTHORIZED=0")
            {
                signals.tls_bypass_span = Some(Span::new(offset + token.start, offset + token.end));
            }
        }
    }
}

pub(crate) fn has_base64_exec(lowered: &str) -> bool {
    let has_base64_decode = lowered.contains("base64 -d") || lowered.contains("base64 --decode");
    let has_exec = lowered.contains("| sh")
        || lowered.contains("| bash")
        || lowered.contains("sh -c")
        || lowered.contains("bash -c");
    has_base64_decode && has_exec
}

pub(crate) fn shell_tokens(line: &str) -> Vec<HookToken<'_>> {
    let mut tokens = Vec::new();
    let mut token_start = None;

    for (index, ch) in line.char_indices() {
        if ch.is_whitespace() {
            if let Some(start) = token_start.take() {
                tokens.push(HookToken {
                    text: &line[start..index],
                    start,
                    end: index,
                });
            }
        } else if token_start.is_none() {
            token_start = Some(index);
        }
    }

    if let Some(start) = token_start {
        tokens.push(HookToken {
            text: &line[start..],
            start,
            end: line.len(),
        });
    }

    tokens
}
