use lintai_api::{ProviderScanResult, RuleMetadata, RuleProvider, ScanContext};

use crate::registry::RULE_SPECS;
use crate::signals::ArtifactSignals;

pub struct AiSecurityProvider {
    rules: Vec<RuleMetadata>,
}

impl Default for AiSecurityProvider {
    fn default() -> Self {
        Self {
            rules: RULE_SPECS.iter().map(|spec| spec.metadata).collect(),
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
        let signals = ArtifactSignals::from_context(ctx);
        let findings = RULE_SPECS
            .iter()
            .filter(|spec| spec.surface.matches(ctx.artifact.kind))
            .flat_map(|spec| {
                (spec.check)(ctx, &signals, spec.metadata)
                    .into_iter()
                    .map(|finding| spec.apply_remediation(ctx, finding))
            })
            .collect();

        ProviderScanResult::new(findings, Vec::new())
    }
}
