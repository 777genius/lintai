use std::collections::{BTreeMap, BTreeSet};

use crate::{RuleTier, builtin_preset_ids};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogDetectionClassKind {
    Structural,
    Heuristic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogLifecycleClass {
    Preview,
    Stable,
}

#[derive(Clone, Copy, Debug)]
pub struct CatalogRuleIdentity<'a> {
    pub owner: &'a str,
    pub code: &'a str,
    pub doc_title: &'a str,
}

pub fn validate_group_ids<'a>(
    catalog_name: &str,
    group_kind: &str,
    groups: impl IntoIterator<Item = (&'a str, bool)>,
) {
    let mut ids = BTreeSet::new();
    for (group_id, is_empty) in groups {
        assert!(
            ids.insert(group_id),
            "duplicate {catalog_name} {group_kind} id {group_id}"
        );
        assert!(
            !is_empty,
            "{catalog_name} {group_kind} {group_id} should not be empty"
        );
    }
}

pub fn validate_rule_identities<'a>(
    catalog_name: &str,
    rules: impl IntoIterator<Item = CatalogRuleIdentity<'a>>,
) {
    let mut codes = BTreeSet::new();
    let mut doc_titles = BTreeMap::new();

    for rule in rules {
        assert!(
            codes.insert(rule.code),
            "duplicate {catalog_name} rule code {}",
            rule.code
        );
        if let Some(previous_owner) = doc_titles.insert(rule.doc_title, rule.owner) {
            panic!(
                "duplicate {catalog_name} rule doc title {:?} used by {} and {}",
                rule.doc_title, previous_owner, rule.owner
            );
        }
    }
}

pub fn validate_rule_presets(catalog_name: &str, rule_code: &str, preset_ids: &[&str]) {
    let known_preset_ids = builtin_preset_ids();
    let mut seen = BTreeSet::new();
    for preset_id in preset_ids {
        assert!(
            seen.insert(*preset_id),
            "{catalog_name} rule {rule_code} repeats preset {preset_id}"
        );
        assert!(
            known_preset_ids.contains(preset_id),
            "{catalog_name} rule {rule_code} references unknown preset {preset_id}"
        );
    }
}

pub fn validate_rule_quality_contract(
    catalog_name: &str,
    rule_code: &str,
    tier: RuleTier,
    detection_class: CatalogDetectionClassKind,
    lifecycle_class: CatalogLifecycleClass,
    preset_ids: &[&str],
) {
    if tier == RuleTier::Stable {
        assert!(
            lifecycle_class == CatalogLifecycleClass::Stable,
            "stable-tier {catalog_name} rule {rule_code} must declare stable lifecycle"
        );
    } else {
        assert!(
            !preset_ids.contains(&"base"),
            "preview-tier {catalog_name} rule {rule_code} must not ship in the base preset"
        );
    }

    if detection_class == CatalogDetectionClassKind::Heuristic {
        assert!(
            tier == RuleTier::Preview,
            "heuristic {catalog_name} rule {rule_code} must stay preview"
        );
        assert!(
            lifecycle_class == CatalogLifecycleClass::Preview,
            "heuristic {catalog_name} rule {rule_code} cannot declare stable lifecycle"
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::RuleTier;

    use super::{
        CatalogDetectionClassKind, CatalogLifecycleClass, CatalogRuleIdentity, validate_group_ids,
        validate_rule_identities, validate_rule_presets, validate_rule_quality_contract,
    };

    #[test]
    fn validation_helpers_accept_valid_catalog_shapes() {
        validate_group_ids("demo", "group", [("markdown", false), ("hooks", false)]);
        validate_rule_identities(
            "demo",
            [
                CatalogRuleIdentity {
                    owner: "demo:SEC101",
                    code: "SEC101",
                    doc_title: "A",
                },
                CatalogRuleIdentity {
                    owner: "demo:SEC102",
                    code: "SEC102",
                    doc_title: "B",
                },
            ],
        );
        validate_rule_presets("demo", "SEC101", &["preview", "skills"]);
        validate_rule_quality_contract(
            "demo",
            "SEC101",
            RuleTier::Preview,
            CatalogDetectionClassKind::Heuristic,
            CatalogLifecycleClass::Preview,
            &["preview", "skills"],
        );
        validate_rule_quality_contract(
            "demo",
            "SEC201",
            RuleTier::Stable,
            CatalogDetectionClassKind::Structural,
            CatalogLifecycleClass::Stable,
            &["base"],
        );
    }
}
