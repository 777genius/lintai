use lintai_api::{Finding, RuleMetadata, RuleProvider, ScanContext};

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
}
