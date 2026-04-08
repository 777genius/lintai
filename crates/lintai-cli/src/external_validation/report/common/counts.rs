use std::collections::{BTreeMap, BTreeSet};

use crate::external_validation::ExternalValidationLedger;

pub(crate) fn category_counts(ledger: &ExternalValidationLedger) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for entry in &ledger.evaluations {
        *counts.entry(entry.category.clone()).or_insert(0usize) += 1;
    }
    counts
}

pub(crate) fn ownership_counts(ledger: &ExternalValidationLedger) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for entry in &ledger.evaluations {
        *counts.entry(entry.ownership.clone()).or_insert(0usize) += 1;
    }
    counts
}

pub(crate) fn count_surface_presence(ledger: &ExternalValidationLedger, surface: &str) -> usize {
    count_any_surface_presence(ledger, &[surface])
}

pub(crate) fn count_any_surface_presence(
    ledger: &ExternalValidationLedger,
    surfaces: &[&str],
) -> usize {
    let wanted = surfaces.iter().copied().collect::<BTreeSet<_>>();
    ledger
        .evaluations
        .iter()
        .filter(|entry| {
            entry
                .surfaces_present
                .iter()
                .any(|present| wanted.contains(present.as_str()))
        })
        .count()
}

pub(crate) fn rule_count(ledger: &ExternalValidationLedger, rules: &[&str]) -> usize {
    let wanted = rules.iter().copied().collect::<BTreeSet<_>>();
    ledger
        .evaluations
        .iter()
        .map(|entry| {
            entry
                .stable_rule_codes
                .iter()
                .chain(entry.preview_rule_codes.iter())
                .filter(|rule_code| wanted.contains(rule_code.as_str()))
                .count()
        })
        .sum()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]

pub(crate) struct AggregateCounts {
    pub(crate) stable_findings: usize,
    pub(crate) preview_findings: usize,
    pub(crate) runtime_errors: usize,
    pub(crate) diagnostics: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct LaneAggregateCounts {
    pub(crate) stable_findings: usize,
    pub(crate) preview_findings: usize,
}

pub(crate) fn aggregate_counts(ledger: &ExternalValidationLedger) -> AggregateCounts {
    AggregateCounts {
        stable_findings: ledger
            .evaluations
            .iter()
            .map(|entry| entry.stable_findings)
            .sum(),
        preview_findings: ledger
            .evaluations
            .iter()
            .map(|entry| entry.preview_findings)
            .sum(),
        runtime_errors: ledger
            .evaluations
            .iter()
            .map(|entry| entry.runtime_errors.len())
            .sum(),
        diagnostics: ledger
            .evaluations
            .iter()
            .map(|entry| entry.diagnostics.len())
            .sum(),
    }
}

pub(crate) fn aggregate_lane_counts(
    ledger: &ExternalValidationLedger,
    lane_id: &str,
) -> LaneAggregateCounts {
    let mut counts = LaneAggregateCounts::default();

    for entry in &ledger.evaluations {
        if let Some(lane) = entry
            .lane_summaries
            .iter()
            .find(|lane| lane.lane_id == lane_id)
        {
            counts.stable_findings += lane.stable_findings;
            counts.preview_findings += lane.preview_findings;
        }
    }

    counts
}

pub(crate) fn aggregate_remaining_lane_counts(
    ledger: &ExternalValidationLedger,
    excluded_lane_ids: &[&str],
) -> Vec<(String, LaneAggregateCounts)> {
    let excluded = excluded_lane_ids.iter().copied().collect::<BTreeSet<_>>();
    let mut counts = BTreeMap::<String, LaneAggregateCounts>::new();

    for entry in &ledger.evaluations {
        for lane in &entry.lane_summaries {
            if excluded.contains(lane.lane_id.as_str()) {
                continue;
            }
            let aggregate = counts.entry(lane.lane_id.clone()).or_default();
            aggregate.stable_findings += lane.stable_findings;
            aggregate.preview_findings += lane.preview_findings;
        }
    }

    counts.into_iter().collect()
}
