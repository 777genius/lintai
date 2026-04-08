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
    assert_eq!(sec201.default_presets(), vec!["base"]);

    let sec101 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC101")
        .unwrap();
    assert_eq!(sec101.default_presets(), vec!["preview", "skills"]);

    let sec323 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC323")
        .unwrap();
    assert_eq!(sec323.default_presets(), vec!["preview", "mcp"]);

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
    assert_eq!(sec324.public_lane(), PublicLane::Preview);

    let sec328 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC328")
        .unwrap();
    assert_eq!(sec328.default_presets(), vec!["supply-chain"]);
    assert_eq!(sec328.public_lane(), PublicLane::Preview);

    let sec352 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC352")
        .unwrap();
    assert_eq!(sec352.default_presets(), vec!["preview", "skills"]);
    assert_eq!(sec352.public_lane(), PublicLane::Preview);

    let sec417 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC417")
        .unwrap();
    assert_eq!(sec417.public_lane(), PublicLane::Preview);

    let sec353 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC353")
        .unwrap();
    assert_eq!(sec353.default_presets(), vec!["guidance"]);

    let sec401 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC401")
        .unwrap();
    assert_eq!(sec401.default_presets(), vec!["compat"]);

    let sec756 = entries
        .iter()
        .find(|entry| entry.metadata.code == "SEC756")
        .unwrap();
    assert_eq!(sec756.default_presets(), vec!["advisory"]);

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
