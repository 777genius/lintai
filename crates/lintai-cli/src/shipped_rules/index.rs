use std::collections::BTreeMap;

use lintai_api::RuleTier;

use super::shipped_security_rule_catalog_entries;

pub(crate) fn shipped_rule_tiers() -> BTreeMap<String, RuleTier> {
    shipped_security_rule_catalog_entries()
        .into_iter()
        .map(|entry| (entry.metadata.code.to_owned(), entry.metadata.tier))
        .collect()
}

pub(crate) fn provider_sort_key(provider_id: &str) -> usize {
    match provider_id {
        "lintai-ai-security" => 0,
        "lintai-policy-mismatch" => 1,
        _ => usize::MAX,
    }
}
