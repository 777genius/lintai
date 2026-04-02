mod catalog;
mod provider;
mod snapshot;

#[cfg(test)]
mod tests;

pub use catalog::{
    DepVulnDetectionClass, DepVulnRemediationSupport, DepVulnRuleCatalogEntry,
    DepVulnRuleLifecycle, DepVulnSurface, dep_vuln_rule_catalog_entries,
    dep_vuln_shared_rule_catalog_entries,
};
pub use provider::{DependencyVulnProvider, PROVIDER_ID};
pub use snapshot::{
    Advisory, AdvisorySnapshot, AffectedRange, bundled_snapshot, bundled_snapshot_json_pretty,
    normalize_snapshot_json,
};
