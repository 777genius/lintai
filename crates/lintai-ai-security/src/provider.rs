use lintai_api::{Applicability, Finding, Fix, RuleMetadata, RuleProvider, ScanContext};

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
        findings
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
