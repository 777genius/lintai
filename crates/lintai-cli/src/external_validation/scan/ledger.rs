use super::super::*;
use crate::shipped_rules::shipped_rule_tiers;

#[derive(Clone, Debug)]
pub(crate) struct ParsedLaneScan<'a> {
    pub(crate) lane_id: &'a str,
    pub(crate) parsed: &'a JsonScanEnvelope,
}

pub(crate) fn fill_auto_fields(
    entry: &mut EvaluationEntry,
    repo: &ShortlistRepo,
    surfaces_present: Vec<String>,
    lane_scans: &[ParsedLaneScan<'_>],
    tier_map: &BTreeMap<String, RuleTier>,
) -> Result<(), String> {
    let mut stable = BTreeSet::new();
    let mut preview = BTreeSet::new();
    let mut stable_hits = BTreeMap::new();
    let mut preview_hits = BTreeMap::new();
    let mut lane_summaries = Vec::with_capacity(lane_scans.len());

    for lane in lane_scans {
        let mut lane_stable_rule_codes = BTreeSet::new();
        let mut lane_preview_rule_codes = BTreeSet::new();
        let mut lane_stable_findings = 0usize;
        let mut lane_preview_findings = 0usize;

        for finding in &lane.parsed.findings {
            validate_finding_identity(finding)?;
            let fingerprint = stable_key_fingerprint(&finding.stable_key);
            match tier_map.get(&finding.rule_code) {
                Some(RuleTier::Stable) => {
                    lane_stable_findings += 1;
                    lane_stable_rule_codes.insert(finding.rule_code.clone());
                    stable.insert(finding.rule_code.clone());
                    stable_hits
                        .entry(fingerprint)
                        .or_insert_with(|| finding.clone());
                }
                Some(RuleTier::Preview) => {
                    lane_preview_findings += 1;
                    lane_preview_rule_codes.insert(finding.rule_code.clone());
                    preview.insert(finding.rule_code.clone());
                    preview_hits
                        .entry(fingerprint)
                        .or_insert_with(|| finding.clone());
                }
                None => {
                    return Err(format!(
                        "unknown rule code `{}` observed during external validation rerun",
                        finding.rule_code
                    ));
                }
            }
        }

        lane_summaries.push(LaneSummary {
            lane_id: lane.lane_id.to_owned(),
            stable_findings: lane_stable_findings,
            preview_findings: lane_preview_findings,
            stable_rule_codes: lane_stable_rule_codes.into_iter().collect(),
            preview_rule_codes: lane_preview_rule_codes.into_iter().collect(),
        });
    }

    let recommended_stable_hits = lane_scans
        .iter()
        .find(|lane| lane.lane_id == "recommended")
        .map(|lane| collect_observed_hits(&lane.parsed.findings, tier_map, RuleTier::Stable))
        .transpose()?
        .unwrap_or_default();

    entry.repo = repo.repo.clone();
    entry.url = repo.url.clone();
    entry.pinned_ref = repo.pinned_ref.clone();
    entry.ownership = repo.ownership.clone();
    entry.category = repo.category.clone();
    entry.subtype = repo.subtype.clone();
    entry.status = "evaluated".to_owned();
    entry.surfaces_present = surfaces_present;
    entry.stable_findings = stable_hits.len();
    entry.preview_findings = preview_hits.len();
    entry.stable_rule_codes = stable.into_iter().collect();
    entry.preview_rule_codes = preview.into_iter().collect();
    entry.stable_precision_notes =
        stable_precision_note(entry.stable_findings, &entry.stable_rule_codes);
    entry.preview_signal_notes =
        preview_signal_note(entry.preview_findings, &entry.preview_rule_codes);
    entry.lane_summaries = lane_summaries;
    entry.recommended_stable_hits = recommended_stable_hits;
    entry.runtime_errors = merge_runtime_errors(lane_scans);
    entry.diagnostics = merge_diagnostics(lane_scans);
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
        ownership: repo.ownership.clone(),
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
        lane_summaries: Vec::new(),
        recommended_stable_hits: Vec::new(),
        recommended_stable_adjudications: Vec::new(),
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

fn stable_precision_note(stable_findings: usize, stable_rule_codes: &[String]) -> String {
    if stable_findings == 0 {
        "No stable findings observed on first-pass external scan.".to_owned()
    } else {
        format!(
            "Observed `{stable_findings}` stable finding(s) via {}.",
            format_rule_codes(stable_rule_codes)
        )
    }
}

fn preview_signal_note(preview_findings: usize, preview_rule_codes: &[String]) -> String {
    if preview_findings == 0 {
        "No preview findings observed on first-pass external scan.".to_owned()
    } else {
        format!(
            "Observed `{preview_findings}` preview finding(s) via {}.",
            format_rule_codes(preview_rule_codes)
        )
    }
}

fn format_rule_codes(rule_codes: &[String]) -> String {
    if rule_codes.is_empty() {
        "`no rules`".to_owned()
    } else {
        rule_codes
            .iter()
            .map(|rule_code| format!("`{rule_code}`"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn collect_observed_hits(
    findings: &[JsonFinding],
    tier_map: &BTreeMap<String, RuleTier>,
    wanted_tier: RuleTier,
) -> Result<Vec<ObservedFindingRecord>, String> {
    let mut hits = BTreeMap::new();

    for finding in findings {
        validate_finding_identity(finding)?;
        match tier_map.get(&finding.rule_code) {
            Some(tier) if *tier == wanted_tier => {
                hits.entry(stable_key_fingerprint(&finding.stable_key))
                    .or_insert_with(|| ObservedFindingRecord {
                        stable_key: finding.stable_key.clone(),
                        rule_code: finding.rule_code.clone(),
                        normalized_path: finding.location.normalized_path.clone(),
                    });
            }
            Some(_) => {}
            None => {
                return Err(format!(
                    "unknown rule code `{}` observed during external validation rerun",
                    finding.rule_code
                ));
            }
        }
    }

    Ok(hits.into_values().collect())
}

fn merge_runtime_errors(lane_scans: &[ParsedLaneScan<'_>]) -> Vec<RuntimeErrorRecord> {
    let mut merged = BTreeMap::new();
    for lane in lane_scans {
        for error in &lane.parsed.runtime_errors {
            merged
                .entry((
                    error.normalized_path.clone(),
                    error.kind.clone(),
                    error.message.clone(),
                ))
                .or_insert_with(|| RuntimeErrorRecord {
                    path: error.normalized_path.clone(),
                    kind: error.kind.clone(),
                    message: error.message.clone(),
                });
        }
    }
    merged.into_values().collect()
}

fn merge_diagnostics(lane_scans: &[ParsedLaneScan<'_>]) -> Vec<DiagnosticRecord> {
    let mut merged = BTreeMap::new();
    for lane in lane_scans {
        for diagnostic in &lane.parsed.diagnostics {
            merged
                .entry((
                    diagnostic.normalized_path.clone(),
                    diagnostic.severity.clone(),
                    diagnostic.code.clone(),
                    diagnostic.message.clone(),
                ))
                .or_insert_with(|| DiagnosticRecord {
                    path: diagnostic.normalized_path.clone(),
                    severity: diagnostic.severity.clone(),
                    code: diagnostic.code.clone(),
                    message: diagnostic.message.clone(),
                });
        }
    }
    merged.into_values().collect()
}

pub(crate) fn stable_key_fingerprint(stable_key: &lintai_api::StableKey) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        stable_key.rule_code,
        stable_key.normalized_path,
        stable_key.span.start_byte,
        stable_key.span.end_byte,
        stable_key.subject_id.as_deref().unwrap_or("")
    )
}

fn validate_finding_identity(finding: &JsonFinding) -> Result<(), String> {
    if finding.stable_key.rule_code != finding.rule_code {
        return Err(format!(
            "stable key rule code `{}` did not match finding rule code `{}`",
            finding.stable_key.rule_code, finding.rule_code
        ));
    }
    if finding.stable_key.normalized_path != finding.location.normalized_path {
        return Err(format!(
            "stable key path `{}` did not match finding path `{}` for `{}`",
            finding.stable_key.normalized_path, finding.location.normalized_path, finding.rule_code
        ));
    }
    Ok(())
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
