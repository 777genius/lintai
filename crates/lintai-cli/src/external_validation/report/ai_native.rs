use std::path::Path;

use crate::external_validation::*;

#[path = "ai_native/admission.rs"]
mod admission;
#[path = "ai_native/coverage.rs"]
mod coverage;
#[path = "ai_native/hits.rs"]
mod hits;

pub(crate) fn render_ai_native_discovery_report(
    workspace_root: &Path,
    shortlist: &RepoShortlist,
    ledger: &ExternalValidationLedger,
) -> String {
    let coverage = coverage::coverage_summary(shortlist);
    let mut output = String::new();
    output.push_str("# External Validation AI-Native Discovery Report\n\n");
    output.push_str("> Wave 1 discovery report for real AI-native execution surfaces that are only partially covered by the current shipped detector.\n");
    output.push_str("> Source of truth lives in [validation/external-repos-ai-native/repo-shortlist.toml](../validation/external-repos-ai-native/repo-shortlist.toml) and [validation/external-repos-ai-native/ledger.toml](../validation/external-repos-ai-native/ledger.toml).\n\n");
    hits::append_cohort_and_counts(&mut output, shortlist, ledger);
    admission::append_admission_results(&mut output, shortlist);
    coverage::append_coverage_status(&mut output, &coverage);
    hits::append_hit_sections(&mut output, workspace_root, shortlist, ledger, &coverage);
    output
}
