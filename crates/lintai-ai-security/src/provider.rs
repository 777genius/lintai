use lintai_api::{
    Applicability, Finding, Fix, ProviderScanResult, RuleMetadata, RuleProvider, ScanContext,
    Suggestion,
};

use crate::registry::{RULE_METADATA, RULES};

pub struct AiSecurityProvider {
    rules: Vec<RuleMetadata>,
}

impl Default for AiSecurityProvider {
    fn default() -> Self {
        Self {
            rules: RULE_METADATA.to_vec(),
        }
    }
}

impl RuleProvider for AiSecurityProvider {
    fn id(&self) -> &str {
        "lintai-ai-security"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &self.rules
    }

    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult {
        let mut findings = Vec::new();
        for rule in RULES {
            findings.extend((rule.check)(ctx, &rule.metadata));
        }
        ProviderScanResult::new(
            findings
                .into_iter()
                .map(|finding| attach_remediation_suggestion(ctx, finding))
                .collect(),
            Vec::new(),
        )
    }

    fn supports_fix(&self) -> bool {
        true
    }

    fn fix(&self, _ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
        match finding.rule_code.as_str() {
            "SEC101" => Some(Fix::new(
                finding.location.span.clone(),
                "",
                Applicability::Safe,
                Some("remove dangerous hidden HTML comment".to_owned()),
            )),
            "SEC103" => Some(Fix::new(
                finding.location.span.clone(),
                "",
                Applicability::Safe,
                Some("remove hidden HTML comment download-and-execute instruction".to_owned()),
            )),
            _ => None,
        }
    }
}

fn attach_remediation_suggestion(ctx: &ScanContext, finding: Finding) -> Finding {
    let Some(message) = remediation_message(&finding) else {
        return finding;
    };
    let candidate_fix = remediation_candidate_fix(ctx, &finding);

    finding.with_suggestion(Suggestion::new(message, candidate_fix))
}

fn remediation_message(finding: &Finding) -> Option<&'static str> {
    match finding.rule_code.as_str() {
        "SEC102" => {
            Some("rewrite the command as inert prose or move it into a fenced example block")
        }
        "SEC201" => {
            Some("vendor or pin the script locally instead of downloading and executing it inline")
        }
        "SEC202" => {
            Some("remove the secret-bearing network exfil flow and keep secret access local")
        }
        "SEC203" => {
            Some("remove insecure HTTP secret exfil and keep secret handling local or over HTTPS")
        }
        "SEC204" => {
            Some("remove TLS-bypass flags or env overrides and use normal certificate verification")
        }
        "SEC205" => Some(
            "move embedded credentials out of URLs and headers into environment or provider-local auth configuration",
        ),
        "SEC301" => Some("replace the shell wrapper with a direct command and explicit args"),
        "SEC302" => {
            Some("replace the insecure http:// endpoint with https:// or a local/stdio transport")
        }
        "SEC303" => Some(
            "remove credential env passthrough and configure secrets only inside the target service",
        ),
        "SEC304" => Some(
            "re-enable certificate verification and use trusted HTTPS or local/stdio transport",
        ),
        "SEC305" => Some(
            "remove embedded credentials from config values and source auth from environment or provider-local secret configuration",
        ),
        _ => None,
    }
}

fn remediation_candidate_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
    match finding.rule_code.as_str() {
        "SEC102" => markdown_inline_code_fix(ctx, finding),
        "SEC201" => replace_line_with_comment_fix(
            ctx,
            finding,
            "# lintai: remove download-and-exec behavior",
        ),
        "SEC202" => replace_line_with_comment_fix(
            ctx,
            finding,
            "# lintai: remove secret exfiltration command",
        ),
        "SEC203" => replace_line_with_comment_fix(
            ctx,
            finding,
            "# lintai: remove insecure secret exfiltration command",
        ),
        "SEC302" => https_rewrite_fix(ctx, finding),
        _ => None,
    }
}

fn markdown_inline_code_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
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

fn replace_line_with_comment_fix(
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

fn https_rewrite_fix(ctx: &ScanContext, finding: &Finding) -> Option<Fix> {
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

fn line_span_for_offset(content: &str, offset: usize) -> Option<lintai_api::Span> {
    if offset > content.len() {
        return None;
    }

    let line_start = content[..offset].rfind('\n').map_or(0, |index| index + 1);
    let line_end = content[offset..]
        .find('\n')
        .map_or(content.len(), |index| offset + index);
    Some(lintai_api::Span::new(line_start, line_end))
}

fn first_download_exec_span(content: &str) -> Option<lintai_api::Span> {
    let lowered = content.to_lowercase();
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
