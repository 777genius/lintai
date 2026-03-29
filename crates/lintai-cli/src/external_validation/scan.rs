use super::*;
use crate::shipped_rules::shipped_rule_tiers;

pub(crate) fn run_scan(lintai_bin: &Path, repo_dir: &Path, json: bool) -> Result<String, String> {
    let mut command = Command::new(lintai_bin);
    command.current_dir(repo_dir).arg("scan").arg(".");
    if json {
        command.arg("--format=json");
    }
    let output = command
        .output()
        .map_err(|error| format!("failed to run lintai in {}: {error}", repo_dir.display()))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("lintai stdout was not valid UTF-8: {error}"))?;
    if matches!(output.status.code(), Some(0 | 1)) {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "lintai scan failed in {} with exit {:?}: {}",
        repo_dir.display(),
        output.status.code(),
        stderr.trim()
    ))
}

pub(crate) fn materialize_repo(repo: &ShortlistRepo, local_dir: &Path) -> Result<(), String> {
    let marker_path = local_dir.join(".lintai-external-validation-ref");
    if marker_path.exists()
        && fs::read_to_string(&marker_path)
            .map(|value| value.trim().to_owned())
            .unwrap_or_default()
            == repo.pinned_ref
    {
        return Ok(());
    }

    if local_dir.exists() {
        fs::remove_dir_all(local_dir).map_err(|error| {
            format!(
                "failed to remove stale repo cache dir {}: {error}",
                local_dir.display()
            )
        })?;
    }
    fs::create_dir_all(local_dir).map_err(|error| {
        format!(
            "failed to create repo cache dir {}: {error}",
            local_dir.display()
        )
    })?;

    let archive_path = local_dir.with_extension("tar.gz");
    let download_url = format!(
        "https://codeload.github.com/{}/tar.gz/{}",
        repo.repo, repo.pinned_ref
    );
    let curl_output = Command::new("curl")
        .args(["-L", "--fail", "-o"])
        .arg(&archive_path)
        .arg(&download_url)
        .output()
        .map_err(|error| format!("failed to download {download_url}: {error}"))?;
    if !curl_output.status.success() {
        return Err(format!(
            "failed to download {download_url}: {}",
            String::from_utf8_lossy(&curl_output.stderr).trim()
        ));
    }

    let tar_output = Command::new("tar")
        .arg("-xzf")
        .arg(&archive_path)
        .arg("--strip-components=1")
        .arg("-C")
        .arg(local_dir)
        .output()
        .map_err(|error| {
            format!(
                "failed to extract archive {}: {error}",
                archive_path.display()
            )
        })?;
    if !tar_output.status.success() {
        return Err(format!(
            "failed to extract archive {}: {}",
            archive_path.display(),
            String::from_utf8_lossy(&tar_output.stderr).trim()
        ));
    }

    let _ = fs::remove_file(&archive_path);
    fs::write(&marker_path, format!("{}\n", repo.pinned_ref)).map_err(|error| {
        format!(
            "failed to write repo materialization marker {}: {error}",
            marker_path.display()
        )
    })?;

    Ok(())
}

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

pub(crate) fn repo_dir_name(repo: &str) -> String {
    repo.replace('/', "__")
}

pub(crate) fn normalize_rel_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|parent| parent.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| "failed to resolve lintai workspace root".to_owned())
}
