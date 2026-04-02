use std::collections::BTreeSet;

use lintai_ai_security::ai_security_rule_catalog_entries;
use lintai_api::{
    CatalogDetectionClassKind, CatalogLifecycleDetails, CatalogRuleIdentity,
    validate_rule_identities, validate_rule_presets, validate_rule_quality_contract,
};
use lintai_dep_vulns::dep_vuln_shared_rule_catalog_entries;
use lintai_policy::policy_shared_rule_catalog_entries;

pub use lintai_api::{
    CatalogDetectionClass as BuiltinCatalogDetectionClass,
    CatalogRemediationSupport as BuiltinCatalogRemediationSupport,
    CatalogRuleEntry as BuiltinRuleCatalogEntry,
    CatalogRuleLifecycle as BuiltinCatalogRuleLifecycle, CatalogRuleScope as BuiltinRuleScope,
    CatalogSurface as BuiltinCatalogSurface,
};

pub fn builtin_rule_catalog_entries() -> Vec<BuiltinRuleCatalogEntry> {
    let mut entries = ai_security_rule_catalog_entries();
    entries.extend(policy_shared_rule_catalog_entries().iter().copied());
    entries.extend(dep_vuln_shared_rule_catalog_entries().iter().copied());
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
                BuiltinCatalogRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => CatalogLifecycleDetails::Preview {
                    blocker,
                    promotion_requirements,
                },
                BuiltinCatalogRuleLifecycle::Stable {
                    rationale,
                    malicious_case_ids,
                    benign_case_ids,
                    requires_structured_evidence,
                    remediation_reviewed,
                    deterministic_signal_basis,
                } => CatalogLifecycleDetails::Stable {
                    rationale,
                    malicious_case_ids,
                    benign_case_ids,
                    requires_structured_evidence,
                    remediation_reviewed,
                    deterministic_signal_basis,
                },
            },
            entry.remediation_support,
            entry.default_presets,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use lintai_testing::{CaseManifest, discover_case_dirs};

    use super::{BuiltinCatalogRuleLifecycle, builtin_rule_catalog_entries};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("workspace root should be discoverable from lintai-builtins")
    }

    fn bucket_case_ids(bucket: &str) -> BTreeSet<String> {
        let bucket_root = repo_root().join("corpus").join(bucket);
        let mut ids = BTreeSet::new();

        for case_dir in discover_case_dirs(&bucket_root).expect("corpus bucket should load") {
            let manifest = CaseManifest::load(&case_dir).expect("corpus manifest should load");
            assert!(
                ids.insert(manifest.id.clone()),
                "duplicate corpus manifest id {} in bucket {}",
                manifest.id,
                bucket
            );
        }

        assert!(
            !ids.is_empty(),
            "expected corpus bucket {} to contain checked-in cases",
            bucket
        );

        ids
    }

    #[test]
    fn builtin_rule_catalog_entries_pass_validation_contracts() {
        let entries = builtin_rule_catalog_entries();
        assert!(
            !entries.is_empty(),
            "builtin rule catalog should not be empty"
        );
    }

    #[test]
    fn stable_rule_corpus_links_resolve_to_checked_in_cases() {
        let malicious_case_ids = bucket_case_ids("malicious");
        let benign_case_ids = bucket_case_ids("benign");
        let mut stable_rule_count = 0usize;

        for entry in builtin_rule_catalog_entries() {
            if let BuiltinCatalogRuleLifecycle::Stable {
                malicious_case_ids: expected_malicious,
                benign_case_ids: expected_benign,
                ..
            } = entry.lifecycle
            {
                stable_rule_count += 1;

                for case_id in expected_malicious {
                    assert!(
                        malicious_case_ids.contains(*case_id),
                        "stable rule {} references missing malicious corpus case {}",
                        entry.metadata.code,
                        case_id
                    );
                }

                for case_id in expected_benign {
                    assert!(
                        benign_case_ids.contains(*case_id),
                        "stable rule {} references missing benign corpus case {}",
                        entry.metadata.code,
                        case_id
                    );
                }
            }
        }

        assert!(
            stable_rule_count > 0,
            "expected shipped rule catalog to contain stable rules"
        );
    }
}
