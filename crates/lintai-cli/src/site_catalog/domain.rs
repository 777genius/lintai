use lintai_api::{BuiltinPresetKind, BuiltinPresetSpec, RuleMetadata};

use crate::shipped_rules::{
    CatalogRuleLifecycle, SecurityRuleCatalogEntry, provider_sort_key, shipped_rule_alias,
};

#[derive(Debug)]
pub(super) struct SiteCatalogModel {
    pub(super) version: u32,
    pub(super) providers: Vec<SiteProviderModel>,
    pub(super) presets: Vec<SitePresetModel>,
    pub(super) rules: Vec<SiteRuleModel>,
}

#[derive(Debug)]
pub(super) struct SiteProviderModel {
    pub(super) id: String,
    pub(super) title: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SitePresetKindModel {
    Membership,
    Overlay,
}

#[derive(Debug)]
pub(super) struct SitePresetModel {
    pub(super) id: String,
    pub(super) kind: SitePresetKindModel,
    pub(super) title: String,
    pub(super) description: String,
    pub(super) extends: Vec<String>,
    pub(super) rule_ids: Vec<String>,
}

#[derive(Debug)]
pub(super) struct SiteRuleModel {
    pub(super) provider_id: String,
    pub(super) rule_code: String,
    pub(super) alias: Option<String>,
    pub(super) doc_title: String,
    pub(super) summary: String,
    pub(super) public_lane: String,
    pub(super) scope: String,
    pub(super) surface: String,
    pub(super) tier: String,
    pub(super) default_severity: String,
    pub(super) default_confidence: String,
    pub(super) detection_class: String,
    pub(super) remediation_support: String,
    pub(super) default_presets: Vec<String>,
    pub(super) lifecycle_state: String,
    pub(super) lifecycle: SiteRuleLifecycleModel,
    pub(super) canonical_note: String,
    pub(super) related_rule_ids: Vec<String>,
}

#[derive(Debug)]
pub(super) enum SiteRuleLifecycleModel {
    Preview {
        blocker: String,
        promotion_requirements: String,
    },
    Stable {
        rationale: String,
        malicious_case_ids: Vec<String>,
        benign_case_ids: Vec<String>,
        requires_structured_evidence: bool,
        remediation_reviewed: bool,
        deterministic_signal_basis: String,
    },
}

pub(super) fn build_site_catalog_model(
    entries: &[SecurityRuleCatalogEntry],
    presets: &[BuiltinPresetSpec],
) -> SiteCatalogModel {
    let providers = build_providers(entries);
    let rules = build_rules(entries);
    let presets = build_presets(&rules, presets);

    SiteCatalogModel {
        version: 1,
        providers,
        presets,
        rules,
    }
}

fn build_providers(entries: &[SecurityRuleCatalogEntry]) -> Vec<SiteProviderModel> {
    let mut providers = Vec::new();
    for entry in entries {
        if providers
            .iter()
            .any(|provider: &SiteProviderModel| provider.id == entry.provider_id)
        {
            continue;
        }

        providers.push(SiteProviderModel {
            id: entry.provider_id.to_owned(),
            title: entry.provider_id.to_owned(),
        });
    }

    providers.sort_by_key(|provider| provider_sort_key(provider.id.as_str()));
    providers
}

fn build_rules(entries: &[SecurityRuleCatalogEntry]) -> Vec<SiteRuleModel> {
    let mut rules = entries
        .iter()
        .copied()
        .map(site_rule_model)
        .collect::<Vec<_>>();
    rules.sort_by(|left, right| {
        (left.provider_id.as_str(), left.rule_code.as_str())
            .cmp(&(right.provider_id.as_str(), right.rule_code.as_str()))
    });
    rules
}

fn site_rule_model(entry: SecurityRuleCatalogEntry) -> SiteRuleModel {
    SiteRuleModel {
        provider_id: entry.provider_id.to_owned(),
        rule_code: entry.metadata.code.to_owned(),
        alias: shipped_rule_alias(entry.metadata.code).map(str::to_owned),
        doc_title: entry.metadata.doc_title.to_owned(),
        summary: entry.metadata.summary.to_owned(),
        public_lane: entry.public_lane().slug().to_owned(),
        scope: entry.scope.slug().to_owned(),
        surface: entry.surface.slug().to_owned(),
        tier: entry.metadata.tier.slug().to_owned(),
        default_severity: severity_name(entry.metadata).to_owned(),
        default_confidence: confidence_name(entry.metadata).to_owned(),
        detection_class: entry.detection_class.slug().to_owned(),
        remediation_support: entry.remediation_support.slug().to_owned(),
        default_presets: entry
            .default_presets()
            .into_iter()
            .map(str::to_owned)
            .collect(),
        lifecycle_state: entry.lifecycle_state().to_owned(),
        lifecycle: lifecycle_model(entry.lifecycle),
        canonical_note: entry.canonical_note().to_owned(),
        related_rule_ids: Vec::new(),
    }
}

fn build_presets(rules: &[SiteRuleModel], presets: &[BuiltinPresetSpec]) -> Vec<SitePresetModel> {
    presets
        .iter()
        .map(|preset| {
            let mut rule_ids = rules
                .iter()
                .filter(|rule| {
                    rule.default_presets
                        .iter()
                        .any(|candidate| candidate == preset.id)
                })
                .map(|rule| format!("{}:{}", rule.provider_id, rule.rule_code))
                .collect::<Vec<_>>();
            rule_ids.sort();

            SitePresetModel {
                id: preset.id.to_owned(),
                kind: preset_kind_model(preset.kind),
                title: preset.id.to_owned(),
                description: preset.description.to_owned(),
                extends: preset
                    .extends
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                rule_ids,
            }
        })
        .collect()
}

fn preset_kind_model(kind: BuiltinPresetKind) -> SitePresetKindModel {
    match kind {
        BuiltinPresetKind::Membership => SitePresetKindModel::Membership,
        BuiltinPresetKind::Overlay => SitePresetKindModel::Overlay,
    }
}

fn lifecycle_model(lifecycle: CatalogRuleLifecycle) -> SiteRuleLifecycleModel {
    match lifecycle {
        CatalogRuleLifecycle::Preview {
            blocker,
            promotion_requirements,
        } => SiteRuleLifecycleModel::Preview {
            blocker: blocker.to_owned(),
            promotion_requirements: promotion_requirements.to_owned(),
        },
        CatalogRuleLifecycle::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        } => SiteRuleLifecycleModel::Stable {
            rationale: rationale.to_owned(),
            malicious_case_ids: malicious_case_ids
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            benign_case_ids: benign_case_ids
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis: deterministic_signal_basis.to_owned(),
        },
    }
}

fn severity_name(metadata: RuleMetadata) -> &'static str {
    metadata.default_severity.slug()
}

fn confidence_name(metadata: RuleMetadata) -> &'static str {
    metadata.default_confidence.slug()
}
