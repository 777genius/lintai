use lintai_api::{FileRuleProvider, ProviderScanResult, RuleMetadata, ScanContext};

use crate::registry::rule_specs;
use crate::signals::{ArtifactSignals, SignalWorkBudget};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct ProviderPerfProfile {
    pub(crate) signal_builds: usize,
    pub(crate) applicable_rules: usize,
    pub(crate) signal_work_budget: SignalWorkBudget,
}

pub struct AiSecurityProvider {
    rules: Vec<RuleMetadata>,
}

impl Default for AiSecurityProvider {
    fn default() -> Self {
        Self {
            rules: rule_specs().iter().map(|spec| spec.metadata).collect(),
        }
    }
}

impl FileRuleProvider for AiSecurityProvider {
    fn id(&self) -> &str {
        "lintai-ai-security"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &self.rules
    }

    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult {
        let (findings, _) = scan_rule_specs(ctx);

        ProviderScanResult::new(findings, Vec::new())
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn profile_scan_context(ctx: &ScanContext) -> ProviderPerfProfile {
    scan_rule_specs(ctx).1
}

fn scan_rule_specs(ctx: &ScanContext) -> (Vec<lintai_api::Finding>, ProviderPerfProfile) {
    let signals = ArtifactSignals::from_context(ctx);
    let active_rule_codes = ctx.active_rule_codes.as_ref();
    let applicable_specs = rule_specs()
        .iter()
        .filter(|spec| {
            spec.surface.matches(ctx.artifact.kind)
                && match active_rule_codes {
                    Some(active) => active.contains(spec.metadata.code),
                    None => true,
                }
        })
        .copied()
        .collect::<Vec<_>>();
    let findings = applicable_specs
        .iter()
        .flat_map(|spec| {
            (spec.check)(ctx, &signals, spec.metadata)
                .into_iter()
                .map(|finding| spec.apply_remediation(ctx, finding))
        })
        .collect();
    let profile = ProviderPerfProfile {
        signal_builds: 1,
        applicable_rules: applicable_specs.len(),
        signal_work_budget: signals.metrics(),
    };

    (findings, profile)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use lintai_api::{Artifact, ArtifactKind, ParsedDocument, ScanContext, SourceFormat};

    use super::profile_scan_context;

    #[test]
    fn provider_profile_respects_active_rule_codes() {
        let context = ScanContext::new(
            Artifact::new("SKILL.md", ArtifactKind::Skill, SourceFormat::Markdown),
            "# title\n",
            ParsedDocument::new(Vec::new(), None),
            None,
        )
        .with_active_rule_codes(BTreeSet::from(["SEC101".to_owned()]));

        let profile = profile_scan_context(&context);
        assert_eq!(profile.applicable_rules, 1);
    }
}
