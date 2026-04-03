use std::collections::{BTreeMap, BTreeSet};

use crate::{CatalogPublicLane, CatalogRemediationSupport, RuleTier, builtin_preset_ids};

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
pub enum CatalogLifecycleDetails<'a> {
    Preview {
        blocker: &'a str,
        promotion_requirements: &'a str,
    },
    Stable {
        rationale: &'a str,
        malicious_case_ids: &'a [&'a str],
        benign_case_ids: &'a [&'a str],
        requires_structured_evidence: bool,
        remediation_reviewed: bool,
        deterministic_signal_basis: &'a str,
    },
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

pub fn validate_rule_presets(
    catalog_name: &str,
    rule_code: &str,
    preset_ids: &[&str],
    public_lane: CatalogPublicLane,
) {
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

    let expected_public_lane = if preset_ids.contains(&"governance") {
        CatalogPublicLane::Governance
    } else if preset_ids.contains(&"recommended") {
        CatalogPublicLane::Recommended
    } else {
        CatalogPublicLane::Preview
    };
    assert!(
        public_lane == expected_public_lane,
        "{catalog_name} rule {rule_code} declares public lane {:?} but presets imply {:?}",
        public_lane,
        expected_public_lane
    );
}

pub fn validate_rule_quality_contract(
    catalog_name: &str,
    rule_code: &str,
    tier: RuleTier,
    detection_class: CatalogDetectionClassKind,
    lifecycle: CatalogLifecycleDetails<'_>,
    _remediation_support: CatalogRemediationSupport,
    preset_ids: &[&str],
) {
    let lifecycle_class = match lifecycle {
        CatalogLifecycleDetails::Preview {
            blocker,
            promotion_requirements,
        } => {
            assert!(
                !is_blank(blocker),
                "preview {catalog_name} rule {rule_code} must declare a non-empty blocker"
            );
            assert!(
                !is_blank(promotion_requirements),
                "preview {catalog_name} rule {rule_code} must declare non-empty promotion requirements"
            );
            CatalogLifecycleClass::Preview
        }
        CatalogLifecycleDetails::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        } => {
            assert!(
                !is_blank(rationale),
                "stable {catalog_name} rule {rule_code} must declare rationale"
            );
            assert!(
                !is_blank(deterministic_signal_basis),
                "stable {catalog_name} rule {rule_code} must declare deterministic signal basis"
            );
            assert!(
                requires_structured_evidence,
                "stable {catalog_name} rule {rule_code} must require structured evidence"
            );
            assert!(
                remediation_reviewed,
                "stable {catalog_name} rule {rule_code} must mark remediation as reviewed"
            );
            validate_case_ids(catalog_name, rule_code, "malicious", malicious_case_ids);
            validate_case_ids(catalog_name, rule_code, "benign", benign_case_ids);

            let malicious = malicious_case_ids.iter().copied().collect::<BTreeSet<_>>();
            let benign = benign_case_ids.iter().copied().collect::<BTreeSet<_>>();
            let overlap = malicious.intersection(&benign).next().copied();
            assert!(
                overlap.is_none(),
                "stable {catalog_name} rule {rule_code} reuses corpus id {} across malicious and benign cases",
                overlap.unwrap_or_default()
            );

            CatalogLifecycleClass::Stable
        }
    };

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

fn validate_case_ids(catalog_name: &str, rule_code: &str, case_kind: &str, case_ids: &[&str]) {
    assert!(
        !case_ids.is_empty(),
        "stable {catalog_name} rule {rule_code} must link {case_kind} corpus cases"
    );

    let mut seen = BTreeSet::new();
    for case_id in case_ids {
        assert!(
            !is_blank(case_id),
            "stable {catalog_name} rule {rule_code} contains blank {case_kind} corpus id"
        );
        assert!(
            is_valid_case_id(case_id),
            "stable {catalog_name} rule {rule_code} uses invalid {case_kind} corpus id {case_id:?}; expected lowercase slug"
        );
        assert!(
            seen.insert(*case_id),
            "stable {catalog_name} rule {rule_code} repeats {case_kind} corpus id {case_id}"
        );
    }
}

fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}

fn is_valid_case_id(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use crate::{CatalogPublicLane, CatalogRemediationSupport, RuleTier};

    use super::{
        CatalogDetectionClassKind, CatalogLifecycleDetails, CatalogRuleIdentity,
        validate_group_ids, validate_rule_identities, validate_rule_presets,
        validate_rule_quality_contract,
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
        validate_rule_presets(
            "demo",
            "SEC101",
            &["preview", "skills"],
            CatalogPublicLane::Preview,
        );
        validate_rule_quality_contract(
            "demo",
            "SEC101",
            RuleTier::Preview,
            CatalogDetectionClassKind::Heuristic,
            CatalogLifecycleDetails::Preview {
                blocker: "Depends on heuristic text markers.",
                promotion_requirements: "Needs broader false-positive review.",
            },
            CatalogRemediationSupport::MessageOnly,
            &["preview", "skills"],
        );
        validate_rule_quality_contract(
            "demo",
            "SEC201",
            RuleTier::Stable,
            CatalogDetectionClassKind::Structural,
            CatalogLifecycleDetails::Stable {
                rationale: "Checks exact config mismatches with deterministic evidence.",
                malicious_case_ids: &["demo-malicious-case"],
                benign_case_ids: &["demo-benign-case"],
                requires_structured_evidence: true,
                remediation_reviewed: true,
                deterministic_signal_basis: "Exact parsed key/value comparison.",
            },
            CatalogRemediationSupport::SafeFix,
            &["base"],
        );
    }

    #[test]
    #[should_panic(expected = "must require structured evidence")]
    fn validation_helpers_reject_stable_rules_without_structured_evidence() {
        validate_rule_quality_contract(
            "demo",
            "SEC201",
            RuleTier::Stable,
            CatalogDetectionClassKind::Structural,
            CatalogLifecycleDetails::Stable {
                rationale: "Checks exact config mismatches with deterministic evidence.",
                malicious_case_ids: &["demo-malicious-case"],
                benign_case_ids: &["demo-benign-case"],
                requires_structured_evidence: false,
                remediation_reviewed: true,
                deterministic_signal_basis: "Exact parsed key/value comparison.",
            },
            CatalogRemediationSupport::SafeFix,
            &["base"],
        );
    }

    #[test]
    #[should_panic(expected = "reuses corpus id")]
    fn validation_helpers_reject_overlapping_corpus_ids() {
        validate_rule_quality_contract(
            "demo",
            "SEC201",
            RuleTier::Stable,
            CatalogDetectionClassKind::Structural,
            CatalogLifecycleDetails::Stable {
                rationale: "Checks exact config mismatches with deterministic evidence.",
                malicious_case_ids: &["shared-case"],
                benign_case_ids: &["shared-case"],
                requires_structured_evidence: true,
                remediation_reviewed: true,
                deterministic_signal_basis: "Exact parsed key/value comparison.",
            },
            CatalogRemediationSupport::SafeFix,
            &["base"],
        );
    }

    #[test]
    #[should_panic(expected = "declares public lane Preview but presets imply Recommended")]
    fn validation_helpers_reject_public_lane_preset_drift() {
        validate_rule_presets(
            "demo",
            "SEC101",
            &["recommended", "preview"],
            CatalogPublicLane::Preview,
        );
    }
}
