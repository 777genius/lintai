use std::collections::BTreeSet;

use super::presentation::SiteCatalog;

pub(super) fn validate_site_catalog(catalog: &SiteCatalog) {
    let known_preset_ids = catalog
        .presets
        .iter()
        .map(|preset| preset.id.as_str())
        .collect::<BTreeSet<_>>();

    let mut provider_ids = BTreeSet::new();
    let mut provider_slugs = BTreeSet::new();
    for provider in &catalog.providers {
        assert!(
            provider_ids.insert(provider.id.as_str()),
            "duplicate site catalog provider id {}",
            provider.id
        );
        assert!(
            provider_slugs.insert(provider.slug.as_str()),
            "duplicate site catalog provider slug {}",
            provider.slug
        );
    }

    let mut rule_ids = BTreeSet::new();
    let mut rule_paths = BTreeSet::new();
    for rule in &catalog.rules {
        assert!(
            rule_ids.insert(rule.rule_id.as_str()),
            "duplicate site catalog rule id {}",
            rule.rule_id
        );
        assert!(
            rule_paths.insert(rule.canonical_path.as_str()),
            "duplicate site catalog rule path {}",
            rule.canonical_path
        );
        for preset_id in &rule.default_presets {
            assert!(
                known_preset_ids.contains(preset_id.as_str()),
                "rule {} references unknown preset {}",
                rule.rule_id,
                preset_id
            );
        }
    }

    let mut preset_ids = BTreeSet::new();
    let mut preset_paths = BTreeSet::new();
    for preset in &catalog.presets {
        assert!(
            preset_ids.insert(preset.id.as_str()),
            "duplicate site catalog preset id {}",
            preset.id
        );
        assert!(
            preset_paths.insert(preset.canonical_path.as_str()),
            "duplicate site catalog preset path {}",
            preset.canonical_path
        );
        for extended in &preset.extends {
            assert!(
                known_preset_ids.contains(extended.as_str()),
                "preset {} extends unknown preset {}",
                preset.id,
                extended
            );
        }
    }
}
