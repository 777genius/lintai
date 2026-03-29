use crate::external_validation::*;

pub(super) fn append_rule_repo_hits(
    output: &mut String,
    label: &str,
    repos: Vec<(String, usize, Vec<String>)>,
) {
    if repos.is_empty() {
        output.push_str(&format!(
            "- `{label}` produced no repo-level preview hits yet on the canonical cohort\n"
        ));
    } else {
        output.push_str(&format!(
            "- `{label}` repo-level preview hits on the canonical cohort:\n"
        ));
        for (repo, count, rule_codes) in repos {
            output.push_str(&format!(
                "  - `{repo}`: `{count}` preview finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
    }
}
