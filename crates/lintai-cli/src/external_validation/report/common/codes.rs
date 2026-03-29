use std::collections::BTreeSet;

use crate::external_validation::ExternalValidationLedger;

pub(crate) fn preview_signal_repos(
    ledger: &ExternalValidationLedger,
) -> Vec<(String, usize, Vec<String>)> {
    ledger
        .evaluations
        .iter()
        .filter(|entry| entry.preview_findings > 0)
        .map(|entry| {
            (
                entry.repo.clone(),
                entry.preview_findings,
                entry.preview_rule_codes.clone(),
            )
        })
        .collect()
}

pub(crate) fn unique_rule_codes_from_hits(hits: &[(String, usize, Vec<String>)]) -> Vec<String> {
    let mut codes = Vec::new();
    for (_, _, hit_codes) in hits {
        for code in hit_codes {
            if !codes.contains(code) {
                codes.push(code.clone());
            }
        }
    }
    codes
}

pub(crate) fn missing_rule_codes(expected: &[&str], observed: &[String]) -> Vec<String> {
    expected
        .iter()
        .filter(|code| !observed.iter().any(|observed| observed == **code))
        .map(|code| (*code).to_owned())
        .collect()
}

pub(crate) fn format_rule_codes(rule_codes: &[String]) -> String {
    if rule_codes.is_empty() {
        "`unspecified`".to_owned()
    } else {
        rule_codes
            .iter()
            .map(|rule_code| format!("`{rule_code}`"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub(crate) fn repos_with_rule_hits(
    ledger: &ExternalValidationLedger,
    wanted_rules: &[&str],
    stable: bool,
) -> Vec<(String, usize, Vec<String>)> {
    let wanted = wanted_rules.iter().copied().collect::<BTreeSet<_>>();
    ledger
        .evaluations
        .iter()
        .filter_map(|entry| {
            let matching_codes = if stable {
                entry
                    .stable_rule_codes
                    .iter()
                    .filter(|code| wanted.contains(code.as_str()))
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                entry
                    .preview_rule_codes
                    .iter()
                    .filter(|code| wanted.contains(code.as_str()))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if matching_codes.is_empty() {
                return None;
            }
            let count = if stable {
                entry
                    .stable_rule_codes
                    .iter()
                    .filter(|code| wanted.contains(code.as_str()))
                    .count()
            } else {
                entry
                    .preview_rule_codes
                    .iter()
                    .filter(|code| wanted.contains(code.as_str()))
                    .count()
            };
            Some((entry.repo.clone(), count, matching_codes))
        })
        .collect()
}
