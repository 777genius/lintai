#[path = "shipped_rules/aliases.rs"]
mod aliases;
#[path = "shipped_rules/index.rs"]
mod index;
#[path = "shipped_rules/map.rs"]
mod map;
#[path = "shipped_rules/model.rs"]
mod model;

pub(crate) use aliases::{shipped_rule_alias, shipped_rule_display_label};
pub(crate) use index::{
    canonical_rule_path, provider_slug, provider_sort_key, rule_slug, shipped_rule_doc_title,
    shipped_rule_docs_url, shipped_rule_tiers,
};
pub(crate) use model::{
    CatalogDetectionClass, CatalogRemediationSupport, CatalogRuleLifecycle, CatalogSurface,
    RuleScope, SecurityRuleCatalogEntry,
};

use lintai_ai_security::native_rule_catalog_entries;
use lintai_policy::policy_rule_catalog_entries;
use map::{native_catalog_entry, policy_catalog_entry};

pub(crate) fn shipped_security_rule_catalog_entries() -> Vec<SecurityRuleCatalogEntry> {
    let mut entries = Vec::new();
    entries.extend(
        native_rule_catalog_entries()
            .into_iter()
            .map(native_catalog_entry),
    );
    entries.extend(
        policy_rule_catalog_entries()
            .iter()
            .copied()
            .map(policy_catalog_entry),
    );
    entries.sort_by_key(|entry| (provider_sort_key(entry.provider_id), entry.metadata.code));
    entries
}
