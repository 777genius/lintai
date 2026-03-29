use std::collections::BTreeMap;

use crate::external_validation::{ExternalValidationLedger, RepoShortlist};

pub(crate) fn repos_with_runtime_issues(
    ledger: &ExternalValidationLedger,
    shortlist: &RepoShortlist,
) -> Vec<(String, usize, usize, Vec<String>)> {
    let admission_map = shortlist
        .repos
        .iter()
        .map(|repo| (repo.repo.as_str(), repo.admission_paths.as_slice()))
        .collect::<BTreeMap<_, _>>();
    ledger
        .evaluations
        .iter()
        .filter_map(|entry| {
            let runtime_count = entry.runtime_errors.len();
            let diagnostic_count = entry.diagnostics.len();
            ((runtime_count + diagnostic_count) > 0).then(|| {
                let admission_paths = admission_map
                    .get(entry.repo.as_str())
                    .copied()
                    .unwrap_or(&[]);
                let mut labels = Vec::new();
                labels.extend(
                    entry
                        .runtime_errors
                        .iter()
                        .map(|error| issue_scope_label(&error.path, admission_paths)),
                );
                labels.extend(
                    entry
                        .diagnostics
                        .iter()
                        .map(|diagnostic| issue_scope_label(&diagnostic.path, admission_paths)),
                );
                labels.sort();
                labels.dedup();
                (entry.repo.clone(), runtime_count, diagnostic_count, labels)
            })
        })
        .collect()
}

pub(crate) fn issue_scope_label(path: &str, admission_paths: &[String]) -> String {
    if admission_paths.iter().any(|candidate| candidate == path) {
        "admission-path issue".to_owned()
    } else {
        "non-admission-path issue".to_owned()
    }
}
