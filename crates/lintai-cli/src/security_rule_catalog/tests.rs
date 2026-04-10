use std::collections::BTreeSet;

use super::format::{escape_markdown_table_cell, escape_markdown_text, render_inline_code};
use super::render_security_rules_markdown;
use crate::shipped_rules::{
    CatalogDetectionClass, CatalogRuleLifecycle, PublicLane, provider_sort_key, shipped_rule_alias,
    shipped_security_rule_catalog_entries,
};
use lintai_api::RuleTier;
use lintai_builtins::{BuiltinCatalogDetectionClass, builtin_rule_catalog_entries};

#[test]
fn catalog_render_matches_checked_in_markdown() {
    let expected = include_str!("../../../../docs/SECURITY_RULES.md");
    assert_eq!(render_security_rules_markdown(), expected);
}

#[test]
fn all_shipped_security_rules_are_documented() {
    let entries = shipped_security_rule_catalog_entries();
    let documented_codes: BTreeSet<_> = entries.iter().map(|entry| entry.metadata.code).collect();
    let expected_codes: BTreeSet<_> = builtin_rule_catalog_entries()
        .into_iter()
        .map(|entry| entry.metadata.code)
        .collect();
    assert_eq!(documented_codes, expected_codes);
    assert_eq!(entries.len(), expected_codes.len());
}

#[test]
fn catalog_order_is_stable() {
    let entries = shipped_security_rule_catalog_entries();
    let actual: Vec<_> = entries
        .iter()
        .map(|entry| (entry.provider_id, entry.metadata.code))
        .collect();
    let mut expected: Vec<_> = builtin_rule_catalog_entries()
        .into_iter()
        .map(|entry| (entry.provider_id, entry.metadata.code))
        .collect();
    expected.sort_by_key(|(provider_id, code)| (provider_sort_key(provider_id), *code));
    assert_eq!(actual, expected);
}

#[test]
fn heuristic_entries_remain_preview() {
    for entry in shipped_security_rule_catalog_entries() {
        if entry.detection_class == CatalogDetectionClass::Heuristic {
            assert_eq!(entry.metadata.tier, RuleTier::Preview);
        }
    }

    assert!(
        builtin_rule_catalog_entries()
            .into_iter()
            .any(|entry| entry.detection_class == BuiltinCatalogDetectionClass::Heuristic)
    );
}

#[test]
fn stable_entries_have_completed_metadata() {
    for entry in shipped_security_rule_catalog_entries() {
        if entry.metadata.tier != RuleTier::Stable {
            continue;
        }
        match entry.lifecycle {
            CatalogRuleLifecycle::Stable {
                rationale,
                malicious_case_ids,
                benign_case_ids,
                deterministic_signal_basis,
                ..
            } => {
                assert!(!rationale.is_empty());
                assert!(!malicious_case_ids.is_empty());
                assert!(!benign_case_ids.is_empty());
                assert!(!deterministic_signal_basis.is_empty());
            }
            CatalogRuleLifecycle::Preview { .. } => {
                panic!("stable rule {} has preview lifecycle", entry.metadata.code);
            }
        }
    }
}

#[test]
fn shipped_rules_have_expected_default_preset_mapping() {
    let entries = shipped_security_rule_catalog_entries();

    let sec201 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC201")
        .unwrap();
    assert_eq!(sec201.default_presets(), vec!["threat-review"]);
    assert_eq!(sec201.public_lane(), PublicLane::ThreatReview);

    let sec101 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC101")
        .unwrap();
    assert_eq!(sec101.default_presets(), vec!["threat-review", "skills"]);

    let sec323 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC323")
        .unwrap();
    assert_eq!(sec323.default_presets(), vec!["compat", "mcp"]);
    assert_eq!(sec323.public_lane(), PublicLane::Compat);

    let sec319 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC319")
        .unwrap();
    assert_eq!(sec319.default_presets(), vec!["supply-chain", "mcp"]);
    assert_eq!(sec319.public_lane(), PublicLane::SupplyChain);

    let sec321 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC321")
        .unwrap();
    assert_eq!(sec321.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec321.public_lane(), PublicLane::ThreatReview);

    let sec320 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC320")
        .unwrap();
    assert_eq!(sec320.default_presets(), vec!["compat", "mcp"]);
    assert_eq!(sec320.public_lane(), PublicLane::Compat);

    let sec322 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC322")
        .unwrap();
    assert_eq!(sec322.default_presets(), vec!["compat", "mcp"]);
    assert_eq!(sec322.public_lane(), PublicLane::Compat);

    let sec314 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC314")
        .unwrap();
    assert_eq!(sec314.default_presets(), vec!["compat", "mcp"]);
    assert_eq!(sec314.public_lane(), PublicLane::Compat);

    let sec315 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC315")
        .unwrap();
    assert_eq!(sec315.default_presets(), vec!["compat", "mcp"]);
    assert_eq!(sec315.public_lane(), PublicLane::Compat);

    let sec316 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC316")
        .unwrap();
    assert_eq!(sec316.default_presets(), vec!["compat", "mcp"]);
    assert_eq!(sec316.public_lane(), PublicLane::Compat);

    let sec317 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC317")
        .unwrap();
    assert_eq!(sec317.default_presets(), vec!["compat", "mcp"]);
    assert_eq!(sec317.public_lane(), PublicLane::Compat);

    let sec318 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC318")
        .unwrap();
    assert_eq!(sec318.default_presets(), vec!["compat", "mcp"]);
    assert_eq!(sec318.public_lane(), PublicLane::Compat);

    let sec340 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC340")
        .unwrap();
    assert_eq!(
        sec340.default_presets(),
        vec!["recommended", "base", "claude"]
    );
    assert_eq!(sec340.public_lane(), PublicLane::Recommended);

    let sec324 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC324")
        .unwrap();
    assert_eq!(sec324.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec324.public_lane(), PublicLane::SupplyChain);

    let sec302 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC302")
        .unwrap();
    assert_eq!(sec302.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec302.public_lane(), PublicLane::SupplyChain);

    let sec304 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC304")
        .unwrap();
    assert_eq!(sec304.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec304.public_lane(), PublicLane::SupplyChain);

    let sec331 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC331")
        .unwrap();
    assert_eq!(sec331.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec331.public_lane(), PublicLane::SupplyChain);

    let sec342 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC342")
        .unwrap();
    assert_eq!(sec342.default_presets(), vec!["supply-chain", "claude"]);
    assert_eq!(sec342.public_lane(), PublicLane::SupplyChain);

    let sec364 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC364")
        .unwrap();
    assert_eq!(sec364.default_presets(), vec!["governance", "claude"]);
    assert_eq!(sec364.public_lane(), PublicLane::Governance);

    let sec365 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC365")
        .unwrap();
    assert_eq!(sec365.default_presets(), vec!["supply-chain", "claude"]);
    assert_eq!(sec365.public_lane(), PublicLane::SupplyChain);

    let sec366 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC366")
        .unwrap();
    assert_eq!(sec366.default_presets(), vec!["supply-chain", "claude"]);
    assert_eq!(sec366.public_lane(), PublicLane::SupplyChain);

    let sec328 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC328")
        .unwrap();
    assert_eq!(sec328.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec328.public_lane(), PublicLane::SupplyChain);

    let sec448 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC448")
        .unwrap();
    assert_eq!(sec448.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec448.public_lane(), PublicLane::SupplyChain);

    let sec462 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC462")
        .unwrap();
    assert_eq!(sec462.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec462.public_lane(), PublicLane::SupplyChain);

    let sec352 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC352")
        .unwrap();
    assert_eq!(sec352.default_presets(), vec!["governance"]);
    assert_eq!(sec352.public_lane(), PublicLane::Governance);

    let sec347 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC347")
        .unwrap();
    assert_eq!(sec347.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec347.public_lane(), PublicLane::SupplyChain);

    let sec337 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC337")
        .unwrap();
    assert_eq!(sec337.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec337.public_lane(), PublicLane::SupplyChain);

    let sec343 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC343")
        .unwrap();
    assert_eq!(sec343.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec343.public_lane(), PublicLane::SupplyChain);

    let sec345 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC345")
        .unwrap();
    assert_eq!(sec345.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec345.public_lane(), PublicLane::SupplyChain);

    let sec346 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC346")
        .unwrap();
    assert_eq!(sec346.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec346.public_lane(), PublicLane::SupplyChain);

    let sec348 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC348")
        .unwrap();
    assert_eq!(sec348.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec348.public_lane(), PublicLane::SupplyChain);

    let sec417 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC417")
        .unwrap();
    assert_eq!(sec417.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec417.public_lane(), PublicLane::SupplyChain);

    let sec353 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC353")
        .unwrap();
    assert_eq!(sec353.default_presets(), vec!["guidance"]);
    assert_eq!(sec353.public_lane(), PublicLane::Guidance);

    let sec303 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC303")
        .unwrap();
    assert_eq!(sec303.default_presets(), vec!["governance", "mcp"]);
    assert_eq!(sec303.public_lane(), PublicLane::Governance);

    let sec307 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC307")
        .unwrap();
    assert_eq!(sec307.default_presets(), vec!["governance", "mcp"]);
    assert_eq!(sec307.public_lane(), PublicLane::Governance);

    let sec311 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC311")
        .unwrap();
    assert_eq!(sec311.default_presets(), vec!["compat", "mcp"]);
    assert_eq!(sec311.public_lane(), PublicLane::Compat);

    let sec336 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC336")
        .unwrap();
    assert_eq!(sec336.default_presets(), vec!["governance", "mcp"]);
    assert_eq!(sec336.public_lane(), PublicLane::Governance);

    let sec330 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC330")
        .unwrap();
    assert_eq!(sec330.default_presets(), vec!["supply-chain", "mcp"]);
    assert_eq!(sec330.public_lane(), PublicLane::SupplyChain);

    let sec341 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC341")
        .unwrap();
    assert_eq!(sec341.default_presets(), vec!["supply-chain", "claude"]);
    assert_eq!(sec341.public_lane(), PublicLane::SupplyChain);

    let sec344 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC344")
        .unwrap();
    assert_eq!(sec344.default_presets(), vec!["supply-chain", "mcp"]);
    assert_eq!(sec344.public_lane(), PublicLane::SupplyChain);

    let sec301 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC301")
        .unwrap();
    assert_eq!(sec301.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec301.public_lane(), PublicLane::ThreatReview);

    let sec306 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC306")
        .unwrap();
    assert_eq!(sec306.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec306.public_lane(), PublicLane::ThreatReview);

    let sec310 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC310")
        .unwrap();
    assert_eq!(sec310.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec310.public_lane(), PublicLane::ThreatReview);

    let sec338 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC338")
        .unwrap();
    assert_eq!(sec338.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec338.public_lane(), PublicLane::ThreatReview);

    let sec339 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC339")
        .unwrap();
    assert_eq!(sec339.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec339.public_lane(), PublicLane::ThreatReview);

    let sec422 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC422")
        .unwrap();
    assert_eq!(sec422.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec422.public_lane(), PublicLane::ThreatReview);

    let sec312 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC312")
        .unwrap();
    assert_eq!(sec312.default_presets(), vec!["threat-review", "skills"]);
    assert_eq!(sec312.public_lane(), PublicLane::ThreatReview);

    let sec446 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC446")
        .unwrap();
    assert_eq!(sec446.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec446.public_lane(), PublicLane::ThreatReview);

    let sec633 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC633")
        .unwrap();
    assert_eq!(sec633.default_presets(), vec!["threat-review"]);
    assert_eq!(sec633.public_lane(), PublicLane::ThreatReview);

    let sec649 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC649")
        .unwrap();
    assert_eq!(sec649.default_presets(), vec!["threat-review"]);
    assert_eq!(sec649.public_lane(), PublicLane::ThreatReview);

    let sec687 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC687")
        .unwrap();
    assert_eq!(sec687.default_presets(), vec!["threat-review"]);
    assert_eq!(sec687.public_lane(), PublicLane::ThreatReview);

    let sec703 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC703")
        .unwrap();
    assert_eq!(sec703.default_presets(), vec!["threat-review"]);
    assert_eq!(sec703.public_lane(), PublicLane::ThreatReview);

    let sec727 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC727")
        .unwrap();
    assert_eq!(sec727.default_presets(), vec!["threat-review"]);
    assert_eq!(sec727.public_lane(), PublicLane::ThreatReview);

    let sec637 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC637")
        .unwrap();
    assert_eq!(sec637.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec637.public_lane(), PublicLane::ThreatReview);

    let sec652 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC652")
        .unwrap();
    assert_eq!(sec652.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec652.public_lane(), PublicLane::ThreatReview);

    let sec674 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC674")
        .unwrap();
    assert_eq!(sec674.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec674.public_lane(), PublicLane::ThreatReview);

    let sec705 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC705")
        .unwrap();
    assert_eq!(sec705.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec705.public_lane(), PublicLane::ThreatReview);

    let sec729 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC729")
        .unwrap();
    assert_eq!(sec729.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec729.public_lane(), PublicLane::ThreatReview);

    let sec737 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC737")
        .unwrap();
    assert_eq!(sec737.default_presets(), vec!["threat-review", "mcp"]);
    assert_eq!(sec737.public_lane(), PublicLane::ThreatReview);

    let sec641 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC641")
        .unwrap();
    assert_eq!(sec641.default_presets(), vec!["threat-review", "claude"]);
    assert_eq!(sec641.public_lane(), PublicLane::ThreatReview);

    let sec655 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC655")
        .unwrap();
    assert_eq!(sec655.default_presets(), vec!["threat-review", "claude"]);
    assert_eq!(sec655.public_lane(), PublicLane::ThreatReview);

    let sec677 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC677")
        .unwrap();
    assert_eq!(sec677.default_presets(), vec!["threat-review", "claude"]);
    assert_eq!(sec677.public_lane(), PublicLane::ThreatReview);

    let sec707 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC707")
        .unwrap();
    assert_eq!(sec707.default_presets(), vec!["threat-review", "claude"]);
    assert_eq!(sec707.public_lane(), PublicLane::ThreatReview);

    let sec731 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC731")
        .unwrap();
    assert_eq!(sec731.default_presets(), vec!["threat-review", "claude"]);
    assert_eq!(sec731.public_lane(), PublicLane::ThreatReview);

    let sec739 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC739")
        .unwrap();
    assert_eq!(sec739.default_presets(), vec!["threat-review", "claude"]);
    assert_eq!(sec739.public_lane(), PublicLane::ThreatReview);

    let sec355 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC355")
        .unwrap();
    assert_eq!(sec355.default_presets(), vec!["guidance"]);
    assert_eq!(sec355.public_lane(), PublicLane::Guidance);

    let sec359 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC359")
        .unwrap();
    assert_eq!(sec359.default_presets(), vec!["guidance"]);
    assert_eq!(sec359.public_lane(), PublicLane::Guidance);

    let sec378 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC378")
        .unwrap();
    assert_eq!(sec378.default_presets(), vec!["guidance"]);
    assert_eq!(sec378.public_lane(), PublicLane::Guidance);

    let sec416 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC416")
        .unwrap();
    assert_eq!(sec416.default_presets(), vec!["guidance"]);
    assert_eq!(sec416.public_lane(), PublicLane::Guidance);

    let sec419 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC419")
        .unwrap();
    assert_eq!(sec419.default_presets(), vec!["governance"]);
    assert_eq!(sec419.public_lane(), PublicLane::Governance);

    let sec466 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC466")
        .unwrap();
    assert_eq!(sec466.default_presets(), vec!["governance"]);
    assert_eq!(sec466.public_lane(), PublicLane::Governance);

    let sec520 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC520")
        .unwrap();
    assert_eq!(sec520.default_presets(), vec!["governance"]);
    assert_eq!(sec520.public_lane(), PublicLane::Governance);

    let sec428 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC428")
        .unwrap();
    assert_eq!(sec428.default_presets(), vec!["governance"]);
    assert_eq!(sec428.public_lane(), PublicLane::Governance);

    let sec447 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC447")
        .unwrap();
    assert_eq!(sec447.default_presets(), vec!["governance"]);
    assert_eq!(sec447.public_lane(), PublicLane::Governance);

    let sec394 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC394")
        .unwrap();
    assert_eq!(sec394.default_presets(), vec!["governance", "mcp"]);
    assert_eq!(sec394.public_lane(), PublicLane::Governance);

    let sec397 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC397")
        .unwrap();
    assert_eq!(sec397.default_presets(), vec!["governance", "mcp"]);
    assert_eq!(sec397.public_lane(), PublicLane::Governance);

    let sec546 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC546")
        .unwrap();
    assert_eq!(sec546.default_presets(), vec!["governance", "mcp"]);
    assert_eq!(sec546.public_lane(), PublicLane::Governance);

    let sec625 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC625")
        .unwrap();
    assert_eq!(sec625.default_presets(), vec!["governance", "mcp"]);
    assert_eq!(sec625.public_lane(), PublicLane::Governance);

    let sec385 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC385")
        .unwrap();
    assert_eq!(sec385.default_presets(), vec!["governance", "claude"]);
    assert_eq!(sec385.public_lane(), PublicLane::Governance);

    let sec400 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC400")
        .unwrap();
    assert_eq!(sec400.default_presets(), vec!["governance", "claude"]);
    assert_eq!(sec400.public_lane(), PublicLane::Governance);

    let sec405 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC405")
        .unwrap();
    assert_eq!(sec405.default_presets(), vec!["governance", "claude"]);
    assert_eq!(sec405.public_lane(), PublicLane::Governance);

    let sec399 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC399")
        .unwrap();
    assert_eq!(sec399.default_presets(), vec!["governance", "claude"]);
    assert_eq!(sec399.public_lane(), PublicLane::Governance);

    let sec362 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC362")
        .unwrap();
    assert_eq!(sec362.default_presets(), vec!["governance", "claude"]);
    assert_eq!(sec362.public_lane(), PublicLane::Governance);

    let sec369 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC369")
        .unwrap();
    assert_eq!(sec369.default_presets(), vec!["governance", "claude"]);
    assert_eq!(sec369.public_lane(), PublicLane::Governance);

    let sec475 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC475")
        .unwrap();
    assert_eq!(sec475.default_presets(), vec!["governance", "claude"]);
    assert_eq!(sec475.public_lane(), PublicLane::Governance);

    let sec627 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC627")
        .unwrap();
    assert_eq!(sec627.default_presets(), vec!["governance", "claude"]);
    assert_eq!(sec627.public_lane(), PublicLane::Governance);

    let sec626 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC626")
        .unwrap();
    assert_eq!(sec626.default_presets(), vec!["governance", "claude"]);
    assert_eq!(sec626.public_lane(), PublicLane::Governance);

    let sec401 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC401")
        .unwrap();
    assert_eq!(sec401.default_presets(), vec!["compat"]);
    assert_eq!(sec401.public_lane(), PublicLane::Compat);

    let sec361 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC361")
        .unwrap();
    assert_eq!(sec361.default_presets(), vec!["compat", "claude"]);
    assert_eq!(sec361.public_lane(), PublicLane::Compat);

    let sec381 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC381")
        .unwrap();
    assert_eq!(sec381.default_presets(), vec!["compat", "claude"]);
    assert_eq!(sec381.public_lane(), PublicLane::Compat);

    let sec382 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC382")
        .unwrap();
    assert_eq!(sec382.default_presets(), vec!["compat", "claude"]);
    assert_eq!(sec382.public_lane(), PublicLane::Compat);

    let sec383 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC383")
        .unwrap();
    assert_eq!(sec383.default_presets(), vec!["compat", "claude"]);
    assert_eq!(sec383.public_lane(), PublicLane::Compat);

    let sec756 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC756")
        .unwrap();
    assert_eq!(sec756.default_presets(), vec!["advisory"]);
    assert_eq!(sec756.public_lane(), PublicLane::Advisory);

    let sec423 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC423")
        .unwrap();
    assert_eq!(sec423.public_lane(), PublicLane::Governance);
}

#[test]
fn detail_sections_cover_every_provider_and_rule() {
    let markdown = render_security_rules_markdown();
    let mut provider_ids = BTreeSet::new();

    for entry in shipped_security_rule_catalog_entries() {
        provider_ids.insert(entry.provider_id);
        let rendered_code = match shipped_rule_alias(entry.metadata.code) {
            Some(alias) => render_inline_code(&format!("{} / {}", entry.metadata.code, alias)),
            None => render_inline_code(entry.metadata.code),
        };
        assert!(
            markdown.contains(&format!(
                "### {} — {}",
                rendered_code,
                escape_markdown_text(entry.metadata.summary)
            )),
            "missing detail section for {}",
            entry.metadata.code
        );
    }

    for provider_id in provider_ids {
        assert!(
            markdown.contains(&format!("## Provider: {}", render_inline_code(provider_id))),
            "missing provider section for {provider_id}"
        );
    }
}

#[test]
fn markdown_escape_helpers_neutralize_tables_html_and_line_breaks() {
    assert_eq!(
        escape_markdown_table_cell("rule | <b>x</b>\nnext & more"),
        "rule \\| &lt;b&gt;x&lt;/b&gt; next &amp; more"
    );
    assert_eq!(
        escape_markdown_text("alpha\r\nbeta<gamma>"),
        "alpha beta&lt;gamma&gt;"
    );
    assert_eq!(
        render_inline_code("tick`value`\nnext"),
        "``tick`value` next``"
    );
}
