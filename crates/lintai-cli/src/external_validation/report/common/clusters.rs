use std::collections::BTreeMap;

use crate::external_validation::ExternalValidationLedger;

pub(crate) fn render_clusters(output: &mut String, clusters: &[(String, usize)], label: &str) {
    for index in 0..3 {
        if let Some((rule_code, count)) = clusters.get(index) {
            output.push_str(&format!(
                "{}. `{}` observed in `{}` repo(s).\n",
                index + 1,
                rule_code,
                count
            ));
        } else {
            output.push_str(&format!(
                "{}. No {} cluster observed in this wave.\n",
                index + 1,
                label
            ));
        }
    }
}

pub(crate) enum ClusterKind {
    FalsePositive,
    FalseNegative,
}

pub(crate) fn top_clusters(
    ledger: &ExternalValidationLedger,
    kind: ClusterKind,
) -> Vec<(String, usize)> {
    let mut counts = BTreeMap::new();
    for entry in &ledger.evaluations {
        let notes = match kind {
            ClusterKind::FalsePositive => &entry.false_positive_notes,
            ClusterKind::FalseNegative => &entry.possible_false_negative_notes,
        };
        for note in notes {
            let key = note
                .rule_code
                .clone()
                .unwrap_or_else(|| "unspecified".to_owned());
            *counts.entry(key).or_insert(0usize) += 1;
        }
    }
    let mut pairs = counts.into_iter().collect::<Vec<_>>();
    pairs.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    pairs
}
