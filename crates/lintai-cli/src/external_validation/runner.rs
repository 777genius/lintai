use super::*;

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

        let text = run_scan(&lintai_bin, &local_dir, false)?;
        let json = run_scan(&lintai_bin, &local_dir, true)?;
        fs::write(repo_raw_root.join("scan.txt"), &text)
            .map_err(|error| format!("failed to write text scan artifact: {error}"))?;
        fs::write(repo_raw_root.join("scan.json"), &json)
            .map_err(|error| format!("failed to write JSON scan artifact: {error}"))?;
        let inventory_text = toml::to_string_pretty(&inventory)
            .map_err(|error| format!("failed to serialize inventory artifact: {error}"))?;
        fs::write(repo_raw_root.join("inventory.toml"), inventory_text)
            .map_err(|error| format!("failed to write inventory artifact: {error}"))?;

        let parsed: JsonScanEnvelope = serde_json::from_str(&json)
            .map_err(|error| format!("failed to parse scan JSON for {}: {error}", repo.repo))?;
        let mut entry = template_entries
            .get(&repo.repo)
            .cloned()
            .unwrap_or_else(|| default_entry_from_shortlist(repo));
        fill_auto_fields(
            &mut entry,
            repo,
            inventory.surfaces_present.clone(),
            &parsed,
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
            let baseline = load_ledger(&options.workspace_root.join(ARCHIVED_WAVE1_LEDGER_PATH))?;
            let current = load_ledger(&options.workspace_root.join(LEDGER_PATH))?;
            Ok(render_report_from_ledgers(&baseline, &current))
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
            Ok(render_ai_native_discovery_report(&shortlist, &current))
        }
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
