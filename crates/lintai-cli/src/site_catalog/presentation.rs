use serde::Serialize;

use crate::shipped_rules::{canonical_rule_path, provider_slug, rule_slug};

use super::domain::{
    SiteCatalogModel, SitePresetKindModel, SitePresetModel, SiteProviderModel,
    SiteRuleLifecycleModel, SiteRuleModel,
};

#[derive(Debug, Serialize)]
pub(super) struct SiteCatalog {
    pub(super) version: u32,
    pub(super) providers: Vec<SiteProvider>,
    pub(super) presets: Vec<SitePreset>,
    pub(super) rules: Vec<SiteRule>,
}

#[derive(Debug, Serialize)]
pub(super) struct SiteProvider {
    pub(super) id: String,
    pub(super) slug: String,
    pub(super) title: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SitePresetKind {
    Membership,
    Overlay,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SitePreset {
    pub(super) id: String,
    pub(super) kind: SitePresetKind,
    pub(super) title: String,
    pub(super) description: String,
    pub(super) extends: Vec<String>,
    pub(super) rule_ids: Vec<String>,
    pub(super) canonical_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SiteRule {
    pub(super) rule_id: String,
    pub(super) provider_id: String,
    pub(super) provider_slug: String,
    pub(super) display_code: Option<String>,
    pub(super) alias: Option<String>,
    pub(super) display_label: String,
    pub(super) doc_title: String,
    pub(super) slug: String,
    pub(super) canonical_path: String,
    pub(super) summary: String,
    pub(super) public_lane: String,
    pub(super) category: String,
    pub(super) scope: String,
    pub(super) surface: String,
    pub(super) tier: String,
    pub(super) default_severity: String,
    pub(super) default_confidence: String,
    pub(super) detection_class: String,
    pub(super) remediation_support: String,
    pub(super) default_presets: Vec<String>,
    pub(super) lifecycle_state: String,
    pub(super) lifecycle: SiteRuleLifecycle,
    pub(super) canonical_note: String,
    pub(super) related_rule_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub(super) enum SiteRuleLifecycle {
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

pub(super) fn present_site_catalog(model: SiteCatalogModel) -> SiteCatalog {
    SiteCatalog {
        version: model.version,
        providers: model.providers.into_iter().map(site_provider).collect(),
        presets: model.presets.into_iter().map(site_preset).collect(),
        rules: model.rules.into_iter().map(site_rule).collect(),
    }
}

pub(super) fn render_site_catalog_json(catalog: &SiteCatalog) -> String {
    let mut json =
        serde_json::to_string_pretty(catalog).expect("site catalog should serialize to JSON");
    json.push('\n');
    json
}

fn site_provider(provider: SiteProviderModel) -> SiteProvider {
    SiteProvider {
        slug: provider_slug(&provider.id),
        id: provider.id,
        title: provider.title,
    }
}

fn site_preset(preset: SitePresetModel) -> SitePreset {
    SitePreset {
        canonical_path: format!("/presets/{}", preset.id),
        id: preset.id,
        kind: site_preset_kind(preset.kind),
        title: preset.title,
        description: preset.description,
        extends: preset.extends,
        rule_ids: preset.rule_ids,
    }
}

fn site_rule(rule: SiteRuleModel) -> SiteRule {
    let provider_slug = provider_slug(&rule.provider_id);
    let display_code = rule.rule_code;
    let alias = rule.alias;
    let display_label = alias
        .as_ref()
        .map(|alias| format!("{display_code} / {alias}"))
        .unwrap_or_else(|| display_code.clone());

    SiteRule {
        rule_id: format!("{}:{}", rule.provider_id, display_code),
        provider_id: rule.provider_id.clone(),
        provider_slug,
        display_code: Some(display_code.clone()),
        alias,
        display_label,
        doc_title: rule.doc_title,
        slug: rule_slug(&display_code),
        canonical_path: canonical_rule_path(&rule.provider_id, &display_code),
        summary: rule.summary,
        public_lane: rule.public_lane,
        category: rule.category,
        scope: rule.scope,
        surface: rule.surface,
        tier: rule.tier,
        default_severity: rule.default_severity,
        default_confidence: rule.default_confidence,
        detection_class: rule.detection_class,
        remediation_support: rule.remediation_support,
        default_presets: rule.default_presets,
        lifecycle_state: rule.lifecycle_state,
        lifecycle: site_lifecycle(rule.lifecycle),
        canonical_note: rule.canonical_note,
        related_rule_ids: rule.related_rule_ids,
    }
}

fn site_preset_kind(kind: SitePresetKindModel) -> SitePresetKind {
    match kind {
        SitePresetKindModel::Membership => SitePresetKind::Membership,
        SitePresetKindModel::Overlay => SitePresetKind::Overlay,
    }
}

fn site_lifecycle(lifecycle: SiteRuleLifecycleModel) -> SiteRuleLifecycle {
    match lifecycle {
        SiteRuleLifecycleModel::Preview {
            blocker,
            promotion_requirements,
        } => SiteRuleLifecycle::Preview {
            blocker,
            promotion_requirements,
        },
        SiteRuleLifecycleModel::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        } => SiteRuleLifecycle::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        },
    }
}
