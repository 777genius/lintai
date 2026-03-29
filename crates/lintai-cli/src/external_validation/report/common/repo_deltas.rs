use std::collections::BTreeSet;

use crate::external_validation::{ExternalValidationLedger, RepoShortlist, template_map};

pub(crate) struct RepoVerdictChange {
    pub(crate) repo: String,
    pub(crate) from: String,
    pub(crate) to: String,
}

pub(crate) fn repo_verdict_changes(
    baseline: &ExternalValidationLedger,
    current: &ExternalValidationLedger,
) -> Vec<RepoVerdictChange> {
    let baseline_map = template_map(baseline);
    current
        .evaluations
        .iter()
        .filter_map(|entry| {
            baseline_map.get(&entry.repo).and_then(|prior| {
                (prior.repo_verdict != entry.repo_verdict).then(|| RepoVerdictChange {
                    repo: entry.repo.clone(),
                    from: prior.repo_verdict.clone(),
                    to: entry.repo_verdict.clone(),
                })
            })
        })
        .collect()
}

pub(crate) fn admitted_repo_set_changes(
    shortlist: &RepoShortlist,
    baseline: &ExternalValidationLedger,
) -> Vec<String> {
    let current = shortlist
        .repos
        .iter()
        .map(|repo| repo.repo.as_str())
        .collect::<BTreeSet<_>>();
    let previous = baseline
        .evaluations
        .iter()
        .map(|entry| entry.repo.as_str())
        .collect::<BTreeSet<_>>();
    let mut changes = Vec::new();
    for repo in current.difference(&previous) {
        changes.push(format!("added `{repo}`"));
    }
    for repo in previous.difference(&current) {
        changes.push(format!("removed `{repo}`"));
    }
    changes
}
