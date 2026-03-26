use lintai_api::{Applicability, Finding, Fix, RuleMetadata, RuleProvider, ScanContext, Suggestion};

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

    fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for rule in RULES {
            findings.extend((rule.check)(ctx, &rule.metadata));
        }
        findings.into_iter().map(attach_remediation_suggestion).collect()
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

fn attach_remediation_suggestion(finding: Finding) -> Finding {
    let Some(message) = remediation_suggestion(&finding) else {
        return finding;
    };

    finding.with_suggestion(Suggestion::new(message, None))
}

fn remediation_suggestion(finding: &Finding) -> Option<&'static str> {
    match finding.rule_code.as_str() {
        "SEC102" => {
            Some("rewrite the command as inert prose or move it into a fenced example block")
        }
        "SEC201" => {
            Some("vendor or pin the script locally instead of downloading and executing it inline")
        }
        "SEC202" => Some("remove the secret-bearing network exfil flow and keep secret access local"),
        "SEC203" => {
            Some("remove insecure HTTP secret exfil and keep secret handling local or over HTTPS")
        }
        "SEC301" => Some("replace the shell wrapper with a direct command and explicit args"),
        "SEC302" => Some("replace the insecure http:// endpoint with https:// or a local/stdio transport"),
        "SEC303" => Some("remove credential env passthrough and configure secrets only inside the target service"),
        _ => None,
    }
}
