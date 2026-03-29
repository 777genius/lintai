use crate::external_validation::*;

pub(super) fn append_admission_results(output: &mut String, shortlist: &RepoShortlist) {
    output.push_str("## Admission Results\n\n");
    for repo in &shortlist.repos {
        output.push_str(&format!(
            "- `{}` via {}. {}\n",
            repo.repo,
            format_rule_codes(&repo.admission_paths),
            repo.rationale
        ));
    }
    output.push('\n');
}
