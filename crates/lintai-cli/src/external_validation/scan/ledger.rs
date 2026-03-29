use super::super::*;
use crate::shipped_rules::shipped_rule_tiers;

pub(crate) fn fill_auto_fields(
    entry: &mut EvaluationEntry,
    repo: &ShortlistRepo,
    surfaces_present: Vec<String>,
    parsed: &JsonScanEnvelope,
    tier_map: &BTreeMap<String, RuleTier>,
) -> Result<(), String> {
    let mut stable = BTreeSet::new();
    let mut preview = BTreeSet::new();

    for finding in &parsed.findings {
        match tier_map.get(&finding.rule_code) {
            Some(RuleTier::Stable) => {
                stable.insert(finding.rule_code.clone());
            }
            Some(RuleTier::Preview) => {
                preview.insert(finding.rule_code.clone());
            }
            None => {
                return Err(format!(
                    "unknown rule code `{}` observed during external validation rerun",
                    finding.rule_code
                ));
            }
        }
    }

    entry.repo = repo.repo.clone();
    entry.url = repo.url.clone();
    entry.pinned_ref = repo.pinned_ref.clone();
    entry.category = repo.category.clone();
    entry.subtype = repo.subtype.clone();
    entry.status = "evaluated".to_owned();
    entry.surfaces_present = surfaces_present;
    entry.stable_findings = parsed
        .findings
        .iter()
        .filter(|finding| tier_map.get(&finding.rule_code) == Some(&RuleTier::Stable))
        .count();
    entry.preview_findings = parsed
        .findings
        .iter()
        .filter(|finding| tier_map.get(&finding.rule_code) == Some(&RuleTier::Preview))
        .count();
    entry.stable_rule_codes = stable.into_iter().collect();
    entry.preview_rule_codes = preview.into_iter().collect();
    entry.runtime_errors = parsed
        .runtime_errors
        .iter()
        .map(|error| RuntimeErrorRecord {
            path: error.normalized_path.clone(),
            kind: error.kind.clone(),
            message: error.message.clone(),
        })
        .collect();
    entry.diagnostics = parsed
        .diagnostics
        .iter()
        .map(|diagnostic| DiagnosticRecord {
            path: diagnostic.normalized_path.clone(),
            severity: diagnostic.severity.clone(),
            code: diagnostic.code.clone(),
            message: diagnostic.message.clone(),
        })
        .collect();
    Ok(())
}

pub(crate) fn current_rule_tiers() -> BTreeMap<String, RuleTier> {
    shipped_rule_tiers()
}

pub(crate) fn default_entry_from_shortlist(repo: &ShortlistRepo) -> EvaluationEntry {
    EvaluationEntry {
        repo: repo.repo.clone(),
        url: repo.url.clone(),
        pinned_ref: repo.pinned_ref.clone(),
        category: repo.category.clone(),
        subtype: repo.subtype.clone(),
        status: repo.status.clone(),
        surfaces_present: repo.surfaces_present.clone(),
        stable_findings: 0,
        preview_findings: 0,
        stable_rule_codes: Vec::new(),
        preview_rule_codes: Vec::new(),
        repo_verdict: "strong_fit".to_owned(),
        stable_precision_notes: String::new(),
        preview_signal_notes: String::new(),
        false_positive_notes: Vec::new(),
        possible_false_negative_notes: Vec::new(),
        follow_up_action: "no_action".to_owned(),
        runtime_errors: Vec::new(),
        diagnostics: Vec::new(),
    }
}

pub(crate) fn template_map(ledger: &ExternalValidationLedger) -> BTreeMap<String, EvaluationEntry> {
    ledger
        .evaluations
        .iter()
        .cloned()
        .map(|entry| (entry.repo.clone(), entry))
        .collect()
}

pub(crate) fn load_shortlist(
    workspace_root: &Path,
    package: ValidationPackage,
) -> Result<RepoShortlist, String> {
    let text = fs::read_to_string(workspace_root.join(package.shortlist_path()))
        .map_err(|error| format!("failed to read shortlist: {error}"))?;
    toml::from_str(&text).map_err(|error| format!("failed to parse shortlist TOML: {error}"))
}

pub(crate) fn load_ledger(path: &Path) -> Result<ExternalValidationLedger, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("failed to read ledger {}: {error}", path.display()))?;
    toml::from_str(&text)
        .map_err(|error| format!("failed to parse ledger {}: {error}", path.display()))
}
