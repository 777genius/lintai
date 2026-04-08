use super::*;

#[derive(Clone, Debug)]
struct LaneScanArtifact {
    lane_id: String,
    text: String,
    parsed: JsonScanEnvelope,
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), String> {
    let raw_args = args.collect::<Vec<_>>();
    let Some(command) = raw_args.first().map(String::as_str) else {
        return Err("expected one of: rerun, render-report".to_owned());
    };
    let package = parse_package_flag(&raw_args[1..])?;
    match command {
        "rerun" => {
            rerun(RerunOptions {
                workspace_root: workspace_root()?,
                package,
                lintai_bin: None,
            })?;
            Ok(())
        }
        "render-report" => {
            let markdown = render_report(RenderReportOptions {
                workspace_root: workspace_root()?,
                package,
            })?;
            print!("{markdown}");
            Ok(())
        }
        _ => Err(format!("unknown external validation command `{command}`")),
    }
}

pub(crate) fn rerun(options: RerunOptions) -> Result<(), String> {
    let package = options.package;
    let shortlist = load_shortlist(&options.workspace_root, package)?;
    let template = load_ledger(&options.workspace_root.join(package.ledger_path()))?;
    let repo_root = options
        .workspace_root
        .join("target/external-validation/repos");
    let raw_root = options.workspace_root.join(package.raw_output_root());
    fs::create_dir_all(&repo_root).map_err(|error| {
        format!(
            "failed to create repo cache root {}: {error}",
            repo_root.display()
        )
    })?;
    fs::create_dir_all(&raw_root).map_err(|error| {
        format!(
            "failed to create raw output root {}: {error}",
            raw_root.display()
        )
    })?;

    let lintai_bin = options
        .lintai_bin
        .unwrap_or(resolve_lintai_driver_path().map_err(|error| {
            format!("failed to resolve lintai binary for external validation rerun: {error}")
        })?);
    let tier_map = current_rule_tiers();
    let template_entries = template_map(&template);
    let preset_matrix = package.scan_preset_matrix();

    let mut candidate = ExternalValidationLedger {
        version: 1,
        wave: package.default_wave(),
        baseline: package.baseline_reference().map(str::to_owned),
        evaluations: Vec::new(),
    };

    for repo in &shortlist.repos {
        let local_dir = repo_root.join(repo_dir_name(&repo.repo));
        materialize_repo(repo, &local_dir)?;
        verify_repo_admission(package, repo, &local_dir)?;
        let inventory = inventory_surfaces(&local_dir)?;
        let repo_raw_root = raw_root.join(repo_dir_name(&repo.repo));
        fs::create_dir_all(&repo_raw_root).map_err(|error| {
            format!(
                "failed to create raw output dir {}: {error}",
                repo_raw_root.display()
            )
        })?;

        let lane_artifacts = collect_lane_artifacts(&lintai_bin, &local_dir, preset_matrix)?;
        write_scan_artifacts(&repo_raw_root, &lane_artifacts)?;
        let inventory_text = toml::to_string_pretty(&inventory)
            .map_err(|error| format!("failed to serialize inventory artifact: {error}"))?;
        fs::write(repo_raw_root.join("inventory.toml"), inventory_text)
            .map_err(|error| format!("failed to write inventory artifact: {error}"))?;

        let mut entry = template_entries
            .get(&repo.repo)
            .cloned()
            .unwrap_or_else(|| default_entry_from_shortlist(repo));
        let parsed_lanes = lane_artifacts
            .iter()
            .map(|artifact| ParsedLaneScan {
                lane_id: artifact.lane_id.as_str(),
                parsed: &artifact.parsed,
            })
            .collect::<Vec<_>>();
        fill_auto_fields(
            &mut entry,
            repo,
            inventory.surfaces_present.clone(),
            &parsed_lanes,
            &tier_map,
        )?;
        candidate.evaluations.push(entry);
    }

    let candidate_path = options.workspace_root.join(package.candidate_ledger_path());
    let text = toml::to_string_pretty(&candidate)
        .map_err(|error| format!("failed to serialize candidate ledger: {error}"))?;
    fs::create_dir_all(
        candidate_path
            .parent()
            .ok_or_else(|| "candidate ledger path should have a parent".to_owned())?,
    )
    .map_err(|error| format!("failed to create candidate ledger directory: {error}"))?;
    fs::write(&candidate_path, text)
        .map_err(|error| format!("failed to write candidate ledger: {error}"))?;

    Ok(())
}

pub(crate) fn render_report(options: RenderReportOptions) -> Result<String, String> {
    match options.package {
        ValidationPackage::Canonical => {
            let baseline = load_ledger(&options.workspace_root.join(ARCHIVED_WAVE2_LEDGER_PATH))?;
            let current = load_ledger(&options.workspace_root.join(LEDGER_PATH))?;
            validate_canonical_precision_contract(&current)?;
            Ok(render_report_from_ledgers(
                &options.workspace_root,
                &baseline,
                &current,
            ))
        }
        ValidationPackage::ToolJsonExtension => {
            let shortlist = load_shortlist(&options.workspace_root, options.package)?;
            let baseline = load_ledger(
                &options
                    .workspace_root
                    .join(TOOL_JSON_EXTENSION_ARCHIVED_WAVE3_LEDGER_PATH),
            )?;
            let current = load_ledger(&options.workspace_root.join(options.package.ledger_path()))?;
            Ok(render_tool_json_extension_report(
                &shortlist, &baseline, &current,
            ))
        }
        ValidationPackage::ServerJsonExtension => {
            let shortlist = load_shortlist(&options.workspace_root, options.package)?;
            let baseline = load_ledger(
                &options
                    .workspace_root
                    .join(SERVER_JSON_EXTENSION_ARCHIVED_WAVE1_LEDGER_PATH),
            )?;
            let current = load_ledger(&options.workspace_root.join(options.package.ledger_path()))?;
            Ok(render_server_json_extension_report(
                &shortlist, &baseline, &current,
            ))
        }
        ValidationPackage::GithubActionsExtension => {
            let shortlist = load_shortlist(&options.workspace_root, options.package)?;
            let current = load_ledger(&options.workspace_root.join(options.package.ledger_path()))?;
            Ok(render_github_actions_extension_report(&shortlist, &current))
        }
        ValidationPackage::AiNativeDiscovery => {
            let shortlist = load_shortlist(&options.workspace_root, options.package)?;
            let current = load_ledger(&options.workspace_root.join(options.package.ledger_path()))?;
            Ok(render_ai_native_discovery_report(
                &options.workspace_root,
                &shortlist,
                &current,
            ))
        }
    }
}

fn collect_lane_artifacts(
    lintai_bin: &Path,
    repo_dir: &Path,
    preset_matrix: &[&str],
) -> Result<Vec<LaneScanArtifact>, String> {
    let mut artifacts = Vec::new();

    if preset_matrix.is_empty() {
        let text = run_scan(lintai_bin, repo_dir, false, &[])?;
        let json = run_scan(lintai_bin, repo_dir, true, &[])?;
        let parsed = serde_json::from_str(&json).map_err(|error| {
            format!(
                "failed to parse scan JSON for {}: {error}",
                repo_dir.display()
            )
        })?;
        artifacts.push(LaneScanArtifact {
            lane_id: "default".to_owned(),
            text,
            parsed,
        });
        return Ok(artifacts);
    }

    for preset_id in preset_matrix {
        let text = run_scan(lintai_bin, repo_dir, false, &[*preset_id])?;
        let json = run_scan(lintai_bin, repo_dir, true, &[*preset_id])?;
        let parsed = serde_json::from_str(&json).map_err(|error| {
            format!(
                "failed to parse scan JSON for {} preset `{}`: {error}",
                repo_dir.display(),
                preset_id
            )
        })?;
        artifacts.push(LaneScanArtifact {
            lane_id: (*preset_id).to_owned(),
            text,
            parsed,
        });
    }

    Ok(artifacts)
}

fn write_scan_artifacts(repo_raw_root: &Path, lane_artifacts: &[LaneScanArtifact]) -> Result<(), String> {
    let aggregate_json = serde_json::to_string_pretty(&merge_lane_scan_envelope(lane_artifacts))
        .map_err(|error| format!("failed to serialize aggregated scan artifact: {error}"))?;
    let aggregate_text = render_aggregate_scan_text(lane_artifacts);
    fs::write(repo_raw_root.join("scan.txt"), aggregate_text)
        .map_err(|error| format!("failed to write text scan artifact: {error}"))?;
    fs::write(repo_raw_root.join("scan.json"), aggregate_json)
        .map_err(|error| format!("failed to write JSON scan artifact: {error}"))?;

    if lane_artifacts.len() > 1 {
        for artifact in lane_artifacts {
            let lane_root = repo_raw_root.join("lanes").join(&artifact.lane_id);
            fs::create_dir_all(&lane_root).map_err(|error| {
                format!(
                    "failed to create lane raw output dir {}: {error}",
                    lane_root.display()
                )
            })?;
            fs::write(lane_root.join("scan.txt"), &artifact.text)
                .map_err(|error| format!("failed to write lane text scan artifact: {error}"))?;
            let lane_json = serde_json::to_string_pretty(&artifact.parsed)
                .map_err(|error| format!("failed to serialize lane scan artifact: {error}"))?;
            fs::write(lane_root.join("scan.json"), lane_json)
                .map_err(|error| format!("failed to write lane JSON scan artifact: {error}"))?;
        }
    }

    Ok(())
}

fn render_aggregate_scan_text(lane_artifacts: &[LaneScanArtifact]) -> String {
    if let [artifact] = lane_artifacts {
        return artifact.text.clone();
    }

    let mut output = String::new();
    for artifact in lane_artifacts {
        output.push_str(&format!("== {} ==\n", artifact.lane_id));
        output.push_str(artifact.text.trim_end());
        output.push_str("\n\n");
    }
    output
}

fn merge_lane_scan_envelope(lane_artifacts: &[LaneScanArtifact]) -> JsonScanEnvelope {
    let mut findings = BTreeMap::new();
    let mut diagnostics = BTreeMap::new();
    let mut runtime_errors = BTreeMap::new();

    for artifact in lane_artifacts {
        for finding in &artifact.parsed.findings {
            findings
                .entry(stable_key_fingerprint(&finding.stable_key))
                .or_insert_with(|| finding.clone());
        }
        for diagnostic in &artifact.parsed.diagnostics {
            diagnostics
                .entry((
                    diagnostic.normalized_path.clone(),
                    diagnostic.severity.clone(),
                    diagnostic.code.clone(),
                    diagnostic.message.clone(),
                ))
                .or_insert_with(|| diagnostic.clone());
        }
        for error in &artifact.parsed.runtime_errors {
            runtime_errors
                .entry((error.normalized_path.clone(), error.kind.clone(), error.message.clone()))
                .or_insert_with(|| error.clone());
        }
    }

    JsonScanEnvelope {
        findings: findings.into_values().collect(),
        diagnostics: diagnostics.into_values().collect(),
        runtime_errors: runtime_errors.into_values().collect(),
    }
}

pub(crate) fn parse_package_flag(args: &[String]) -> Result<ValidationPackage, String> {
    let mut package = ValidationPackage::Canonical;
    for arg in args {
        let Some(value) = arg.strip_prefix("--package=") else {
            return Err(format!(
                "unexpected external validation argument `{arg}`; expected only --package=<name>"
            ));
        };
        package = ValidationPackage::parse(value)?;
    }
    Ok(package)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_without_arguments_reports_usage() {
        let error = run(std::iter::empty()).unwrap_err();
        assert_eq!(error, "expected one of: rerun, render-report");
    }

    #[test]
    fn run_with_unknown_command_reports_unknown_command() {
        let error = run(vec!["unknown".to_owned()].into_iter()).unwrap_err();
        assert_eq!(error, "unknown external validation command `unknown`");
    }

    #[test]
    fn parse_package_flag_ignores_missing_value_but_preserves_default() {
        assert_eq!(
            parse_package_flag(&[]).unwrap(),
            ValidationPackage::Canonical
        );
    }

    #[test]
    fn parse_package_flag_rejects_invalid_flag() {
        let error = parse_package_flag(&["--bad-flag".to_owned()]).unwrap_err();
        assert_eq!(
            error,
            "unexpected external validation argument `--bad-flag`; expected only --package=<name>"
        );
    }

    #[test]
    fn parse_package_flag_rejects_unknown_package_name() {
        let error = parse_package_flag(&["--package=bogus".to_owned()]).unwrap_err();
        assert_eq!(error, "unknown external validation package `bogus`");
    }

    #[test]
    fn parse_package_flag_uses_last_package_flag() {
        assert_eq!(
            parse_package_flag(&[
                "--package=tool-json-extension".to_owned(),
                "--package=github-actions-extension".to_owned(),
            ])
            .unwrap(),
            ValidationPackage::GithubActionsExtension
        );
    }

    #[test]
    fn run_renders_report_for_known_package() {
        run(["render-report".to_owned(), "--package=canonical".to_owned()].into_iter()).unwrap();
    }

    #[test]
    fn run_renders_reports_for_all_known_packages() {
        let packages = [
            "--package=canonical",
            "--package=tool-json-extension",
            "--package=server-json-extension",
            "--package=github-actions-extension",
            "--package=ai-native-discovery",
        ];

        for package in packages {
            run(["render-report".to_owned(), package.to_owned()].into_iter()).unwrap();
        }
    }

    #[test]
    fn parse_package_flag_accepts_the_last_flag() {
        assert_eq!(
            parse_package_flag(&[
                "--package=tool-json-extension".to_owned(),
                "--package=server-json-extension".to_owned(),
                "--package=canonical".to_owned(),
            ])
            .unwrap(),
            ValidationPackage::Canonical
        );
    }
}
