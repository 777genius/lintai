use lintai_api::{Applicability, Finding, Fix, ScanContext, Suggestion};

use super::NativeRuleSpec;

impl NativeRuleSpec {
    pub(crate) fn apply_remediation(self, ctx: &ScanContext, finding: Finding) -> Finding {
        let safe_fix = self.safe_fix.map(|fix| fix(&finding));
        let finding = match self.safe_fix {
            Some(_) => finding.with_fix(safe_fix.expect("safe fix must exist when configured")),
            None => finding,
        };

        match self.suggestion_message {
            Some(message) => {
                let candidate_fix = self.suggestion_fix.and_then(|fix| fix(ctx, &finding));
                finding.with_suggestion(Suggestion::new(message, candidate_fix))
            }
            None => finding,
        }
    }
}

pub(crate) fn remove_hidden_comment_fix(finding: &Finding) -> Fix {
    Fix::new(
        finding.location.span.clone(),
        "",
        Applicability::Safe,
        Some("remove dangerous hidden HTML comment".to_owned()),
    )
}

pub(crate) fn remove_hidden_download_exec_comment_fix(finding: &Finding) -> Fix {
    Fix::new(
        finding.location.span.clone(),
        "",
        Applicability::Safe,
        Some("remove hidden HTML comment download-and-execute instruction".to_owned()),
    )
}

pub(crate) fn markdown_inline_code_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    let span = &finding.location.span;
    let snippet = ctx.content.get(span.start_byte..span.end_byte)?;
    let command = first_download_exec_span(snippet)?;
    let absolute_start = span.start_byte + command.start_byte;
    let absolute_end = span.start_byte + command.end_byte;
    let original = ctx.content.get(absolute_start..absolute_end)?;
    Some(Fix::new(
        lintai_api::Span::new(absolute_start, absolute_end),
        format!("`{original}`"),
        Applicability::Suggestion,
        Some("render the command as inert inline code".to_owned()),
    ))
}

pub(crate) fn hook_download_exec_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    replace_line_with_comment_fix(ctx, finding, "# lintai: remove download-and-exec behavior")
}

pub(crate) fn hook_secret_exfil_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    replace_line_with_comment_fix(ctx, finding, "# lintai: remove secret exfiltration command")
}

pub(crate) fn hook_plain_http_exfil_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    replace_line_with_comment_fix(
        ctx,
        finding,
        "# lintai: remove insecure secret exfiltration command",
    )
}

pub(crate) fn hook_base64_exec_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    replace_line_with_comment_fix(
        ctx,
        finding,
        "# lintai: remove base64 decode-and-exec behavior",
    )
}

pub(crate) fn replace_line_with_comment_fix(
    ctx: &ScanContext,
    finding: &Finding,
    replacement: &str,
) -> Option<Fix> {
    let span = line_span_for_offset(&ctx.content, finding.location.span.start_byte)?;
    Some(Fix::new(
        span,
        replacement,
        Applicability::Suggestion,
        Some("disable the unsafe hook command".to_owned()),
    ))
}

pub(crate) fn https_rewrite_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    let start = finding.location.span.start_byte;
    let snippet = ctx.content.get(start..finding.location.span.end_byte)?;
    let relative = snippet.find("http://")?;
    let absolute_start = start + relative;
    let absolute_end = absolute_start + "http://".len();
    Some(Fix::new(
        lintai_api::Span::new(absolute_start, absolute_end),
        "https://",
        Applicability::Suggestion,
        Some("rewrite the endpoint to HTTPS".to_owned()),
    ))
}

pub(crate) fn line_span_for_offset(content: &str, offset: usize) -> Option<lintai_api::Span> {
    if offset > content.len() {
        return None;
    }

    let line_start = content[..offset].rfind('\n').map_or(0, |index| index + 1);
    let line_end = content[offset..]
        .find('\n')
        .map_or(content.len(), |index| offset + index);
    Some(lintai_api::Span::new(line_start, line_end))
}

pub(crate) fn first_download_exec_span(content: &str) -> Option<lintai_api::Span> {
    let lowered = content.to_ascii_lowercase();
    let curl = lowered.find("curl ");
    let wget = lowered.find("wget ");
    let start = match (curl, wget) {
        (Some(left), Some(right)) => left.min(right),
        (Some(left), None) => left,
        (None, Some(right)) => right,
        (None, None) => return None,
    };
    let tail = &lowered[start..];
    if !(tail.contains("| sh") || tail.contains("| bash")) {
        return None;
    }
    Some(lintai_api::Span::new(
        start,
        content.trim_end_matches(['\r', '\n']).len(),
    ))
}
