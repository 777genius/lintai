use std::collections::BTreeSet;

use lintai_ai_security::native_rule_catalog_entries;
use lintai_api::{
    CatalogDetectionClassKind, CatalogLifecycleClass, CatalogRuleIdentity,
    validate_rule_identities, validate_rule_presets, validate_rule_quality_contract,
};
use lintai_dep_vulns::dep_vuln_rule_catalog_entries;
use lintai_policy::policy_rule_catalog_entries;

pub use lintai_api::{
    CatalogDetectionClass as BuiltinCatalogDetectionClass,
    CatalogRemediationSupport as BuiltinCatalogRemediationSupport,
    CatalogRuleEntry as BuiltinRuleCatalogEntry,
    CatalogRuleLifecycle as BuiltinCatalogRuleLifecycle, CatalogRuleScope as BuiltinRuleScope,
    CatalogSurface as BuiltinCatalogSurface,
};

pub fn builtin_rule_catalog_entries() -> Vec<BuiltinRuleCatalogEntry> {
    let mut entries = native_rule_catalog_entries()
        .into_iter()
        .map(BuiltinRuleCatalogEntry::from)
        .collect::<Vec<_>>();
    entries.extend(
        policy_rule_catalog_entries()
            .iter()
            .copied()
            .map(BuiltinRuleCatalogEntry::from),
    );
    entries.extend(
        dep_vuln_rule_catalog_entries()
            .iter()
            .copied()
            .map(BuiltinRuleCatalogEntry::from),
    );
    validate_builtin_rule_catalog_entries(&entries);
    entries
}

pub fn builtin_known_rule_codes() -> BTreeSet<String> {
    builtin_rule_catalog_entries()
        .into_iter()
        .map(|entry| entry.metadata.code.to_owned())
        .collect()
}

pub fn builtin_rule_codes_for_preset(preset: &str) -> BTreeSet<String> {
    builtin_rule_catalog_entries()
        .into_iter()
        .filter(|entry| entry.default_presets.contains(&preset))
        .map(|entry| entry.metadata.code.to_owned())
        .collect()
}

fn validate_builtin_rule_catalog_entries(entries: &[BuiltinRuleCatalogEntry]) {
    let mut provider_rule_ids = BTreeSet::new();
    validate_rule_identities(
        "builtin",
        entries.iter().map(|entry| CatalogRuleIdentity {
            owner: entry.metadata.code,
            code: entry.metadata.code,
            doc_title: entry.metadata.doc_title,
        }),
    );

    for entry in entries {
        let provider_rule_id = (entry.provider_id, entry.metadata.code);
        assert!(
            provider_rule_ids.insert(provider_rule_id),
            "duplicate builtin provider/rule pair {}:{}",
            entry.provider_id,
            entry.metadata.code
        );
        validate_rule_presets("builtin", entry.metadata.code, entry.default_presets);
        validate_rule_quality_contract(
            "builtin",
            entry.metadata.code,
            entry.metadata.tier,
            match entry.detection_class {
                BuiltinCatalogDetectionClass::Structural => CatalogDetectionClassKind::Structural,
                BuiltinCatalogDetectionClass::Heuristic => CatalogDetectionClassKind::Heuristic,
            },
            match entry.lifecycle {
                BuiltinCatalogRuleLifecycle::Preview { .. } => CatalogLifecycleClass::Preview,
                BuiltinCatalogRuleLifecycle::Stable { .. } => CatalogLifecycleClass::Stable,
            },
            entry.default_presets,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::builtin_rule_catalog_entries;

    #[test]
    fn builtin_rule_catalog_entries_pass_validation_contracts() {
        let entries = builtin_rule_catalog_entries();
        assert!(
            !entries.is_empty(),
            "builtin rule catalog should not be empty"
        );
    }
}
