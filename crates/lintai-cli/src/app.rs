use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use lintai_api::{Applicability, Finding};
use lintai_engine::{
    Engine, FileSuppressions, OutputFormat, ResolvedFileConfig, explain_file_config,
    load_workspace_config,
};
use lintai_fix::{apply_planned_fixes, plan_fixes};

use crate::args::{parse_explain_config_args, parse_fix_args, parse_scan_args};
use crate::builtin_providers::{product_provider_set, run_provider_runner};
use crate::{output, path::validate_path_within_project};

pub fn run() -> Result<ExitCode, String> {
    let current_dir =
        std::env::current_dir().map_err(|error| format!("cwd resolution failed: {error}"))?;
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Ok(ExitCode::SUCCESS);
    };

    match command.as_str() {
        "scan" => run_scan(&current_dir, args),
        "fix" => run_fix(&current_dir, args),
        "explain-config" => run_explain_config(&current_dir, args),
        "__provider-runner" => run_provider_runner(args),
        "config-schema" => {
            println!("{}", lintai_engine::config_schema_pretty());
            Ok(ExitCode::SUCCESS)
        }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command: {other}")),
    }
}

fn run_scan(current_dir: &Path, args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    let parsed = parse_scan_args(args)?;
    let workspace = load_validated_workspace(current_dir, &parsed.target)?;
    let summary = build_engine(&workspace)?
        .scan_path(&parsed.target)
        .map_err(|error| format!("scan failed: {error}"))?;
    let report = output::build_envelope(
        &summary,
        workspace.source_path.as_deref(),
        workspace.engine_config.project_root.as_deref(),
    );

    let output_format = parsed
        .format_override
        .unwrap_or(workspace.engine_config.output_format);
    match output_format {
        OutputFormat::Text => {
            print!("{}", output::format_text(&report));
        }
        OutputFormat::Json => {
            println!(
                "{}",
                output::format_json(&report)
                    .map_err(|error| format!("json output failed: {error}"))?
            );
        }
        OutputFormat::Sarif => {
            println!(
                "{}",
                output::format_sarif(&report)
                    .map_err(|error| format!("sarif output failed: {error}"))?
            );
        }
    }

    if has_blocking_findings(&summary.findings, &workspace.engine_config.ci_policy) {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn run_fix(current_dir: &Path, args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    let parsed = parse_fix_args(args)?;
    let workspace = load_validated_workspace(current_dir, &parsed.target)?;
    let summary = build_engine(&workspace)?
        .scan_path(&parsed.target)
        .map_err(|error| format!("scan failed: {error}"))?;
    let rule_filters = parsed.rule_filters.into_iter().collect::<BTreeSet<_>>();
    let fix_root = fix_root(&workspace, current_dir);

    let mut selected_findings = 0usize;
    let mut suggestion_bearing_findings = 0usize;
    let mut grouped = BTreeMap::<String, Vec<&Finding>>::new();
    for finding in &summary.findings {
        if !rule_filters.is_empty() && !rule_filters.contains(finding.rule_code.as_str()) {
            continue;
        }
        if !finding.suggestions.is_empty() {
            suggestion_bearing_findings += 1;
        }
        let Some(fix) = finding.fix.as_ref() else {
            continue;
        };
        if !matches!(fix.applicability, Applicability::Safe) {
            continue;
        }

        selected_findings += 1;
        grouped
            .entry(finding.location.normalized_path.clone())
            .or_default()
            .push(finding);
    }

    let mut output = String::new();
    let mut applied_or_planned = 0usize;
    let mut skipped_conflicts = 0usize;
    let mut skipped_unapplied = 0usize;
    let mut files_changed = 0usize;
    let mut surfaced_suggestion_edits = 0usize;
    let mut surfaced_message_only_suggestions = 0usize;

    if selected_findings == 0 {
        output.push_str("no autofixable findings matched the current selection\n");
    }

    for (normalized_path, findings) in grouped {
        let fixes = findings
            .iter()
            .map(|finding| {
                finding
                    .fix
                    .clone()
                    .expect("fixable finding should carry a fix")
            })
            .collect::<Vec<_>>();
        let plan = plan_fixes(&fixes);
        skipped_conflicts += plan.conflicts.len();
        let file_path = fix_root.join(Path::new(&normalized_path));

        for index in &plan.conflicts {
            let finding = findings[*index];
            output.push_str(&format!(
                "skip-conflict {} {}:{}-{}\n",
                finding.rule_code,
                normalized_path,
                finding.location.span.start_byte,
                finding.location.span.end_byte
            ));
        }

        if plan.applicable.is_empty() {
            continue;
        }

        if parsed.apply {
            let content = fs::read_to_string(&file_path)
                .map_err(|error| format!("fix read failed for {}: {error}", file_path.display()))?;
            match apply_planned_fixes(&content, &fixes, &plan) {
                Ok(updated) => {
                    if updated != content {
                        fs::write(&file_path, updated).map_err(|error| {
                            format!("fix write failed for {}: {error}", file_path.display())
                        })?;
                        files_changed += 1;
                    }
                    applied_or_planned += plan.applicable.len();
                    for index in &plan.applicable {
                        let finding = findings[*index];
                        output.push_str(&format!(
                            "apply {} {}:{}-{}\n",
                            finding.rule_code,
                            normalized_path,
                            finding.location.span.start_byte,
                            finding.location.span.end_byte
                        ));
                    }
                }
                Err(error) => {
                    skipped_unapplied += plan.applicable.len();
                    output.push_str(&format!(
                        "skip-unapplied {} {}\n",
                        normalized_path,
                        fix_error_message(&error)
                    ));
                }
            }
        } else {
            applied_or_planned += plan.applicable.len();
            files_changed += 1;
            for index in &plan.applicable {
                let finding = findings[*index];
                output.push_str(&format!(
                    "plan {} {}:{}-{}\n",
                    finding.rule_code,
                    normalized_path,
                    finding.location.span.start_byte,
                    finding.location.span.end_byte
                ));
            }
        }
    }

    for finding in &summary.findings {
        if !rule_filters.is_empty() && !rule_filters.contains(finding.rule_code.as_str()) {
            continue;
        }
        for suggestion in &finding.suggestions {
            if let Some(fix) = &suggestion.fix {
                surfaced_suggestion_edits += 1;
                output.push_str(&format!(
                    "suggest-edit {} {}:{}-{} {}\n",
                    finding.rule_code,
                    finding.location.normalized_path,
                    fix.span.start_byte,
                    fix.span.end_byte,
                    suggestion.message
                ));
                output.push_str(&format!(
                    "  replacement: {}\n",
                    clipped_debug_string(&fix.replacement)
                ));
            } else {
                surfaced_message_only_suggestions += 1;
                output.push_str(&format!(
                    "suggest {} {}:{}-{} {}\n",
                    finding.rule_code,
                    finding.location.normalized_path,
                    finding.location.span.start_byte,
                    finding.location.span.end_byte,
                    suggestion.message
                ));
            }
        }
    }

    let action = if parsed.apply { "applied" } else { "planned" };
    output.push_str(&format!(
        "scanned {} finding(s); selected {} autofixable finding(s); {} {} fix(es); surfaced {} suggestion-bearing finding(s); surfaced {} suggestion edit(s); surfaced {} message-only suggestion(s); skipped {} conflict(s); skipped {} unapplied fix(es); files changed {}\n",
        summary.findings.len(),
        selected_findings,
        action,
        applied_or_planned,
        suggestion_bearing_findings,
        surfaced_suggestion_edits,
        surfaced_message_only_suggestions,
        skipped_conflicts,
        skipped_unapplied,
        files_changed
    ));
    print!("{output}");

    if parsed.apply && (skipped_conflicts > 0 || skipped_unapplied > 0) {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn run_explain_config(
    current_dir: &Path,
    args: impl Iterator<Item = String>,
) -> Result<ExitCode, String> {
    let target = parse_explain_config_args(args)?;
    let workspace = load_workspace_config(current_dir)
        .map_err(|error| format!("config resolution failed: {error}"))?;
    validate_path_within_project(&target, workspace.engine_config.project_root.as_deref())
        .map_err(|error| format!("target validation failed: {error}"))?;
    let resolved = explain_file_config(&workspace, &target);
    print!(
        "{}",
        format_explain_config(workspace.source_path.as_deref(), &resolved)
    );
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn format_explain_config(
    config_source: Option<&Path>,
    resolved: &ResolvedFileConfig,
) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "config_source={}\n",
        config_source.map_or("<none>".to_owned(), |p| p.display().to_string())
    ));
    output.push_str(&format!("normalized_path={}\n", resolved.normalized_path));
    output.push_str(&format!("included={}\n", resolved.included));
    output.push_str(&format!("detected_kind={:?}\n", resolved.detected_kind));
    output.push_str(&format!("detected_format={:?}\n", resolved.detected_format));
    output.push_str(&format!("output={:?}\n", resolved.output_format));
    output.push_str(&format!("ci_fail_on={:?}\n", resolved.ci_policy.fail_on));
    output.push_str(&format!(
        "ci_min_confidence={:?}\n",
        resolved.ci_policy.min_confidence
    ));
    output.push_str(&format!(
        "capability_conflict_mode={:?}\n",
        resolved.capability_conflict_mode
    ));
    output.push_str(&format!(
        "project_capabilities={:?}\n",
        resolved.project_capabilities
    ));
    output.push_str(&format!(
        "applied_overrides={:?}\n",
        resolved.applied_overrides
    ));
    output.push_str(&format!(
        "category_overrides={:?}\n",
        resolved.category_overrides
    ));
    output.push_str(&format!("rule_overrides={:?}\n", resolved.rule_overrides));
    output
}

fn print_usage() {
    println!("lintai scan [path] [--format=text|json]");
    println!("                    [--format=sarif]");
    println!("lintai fix [path] [--apply] [--rule CODE]");
    println!("lintai explain-config <file>");
    println!("lintai config-schema");
}

fn load_validated_workspace(
    current_dir: &Path,
    target: &Path,
) -> Result<lintai_engine::WorkspaceConfig, String> {
    let workspace = load_workspace_config(current_dir)
        .map_err(|error| format!("config resolution failed: {error}"))?;
    validate_path_within_project(target, workspace.engine_config.project_root.as_deref())
        .map_err(|error| format!("target validation failed: {error}"))?;
    Ok(workspace)
}

fn build_engine(workspace: &lintai_engine::WorkspaceConfig) -> Result<Engine, String> {
    let suppressions = FileSuppressions::load(&workspace.engine_config)
        .map_err(|error| format!("suppress loading failed: {error}"))?;
    let mut builder = Engine::builder()
        .with_config(workspace.engine_config.clone())
        .with_suppressions(std::sync::Arc::new(suppressions));
    for provider in product_provider_set() {
        builder = builder.with_provider(provider);
    }

    Ok(builder.build())
}

fn fix_root(workspace: &lintai_engine::WorkspaceConfig, current_dir: &Path) -> PathBuf {
    workspace
        .engine_config
        .project_root
        .clone()
        .unwrap_or_else(|| current_dir.to_path_buf())
}

fn fix_error_message(error: &lintai_fix::FixError) -> &'static str {
    match error {
        lintai_fix::FixError::OutOfBounds => "fix span fell outside current file contents",
        lintai_fix::FixError::InvalidRange => "fix span used an invalid byte range",
    }
}

fn clipped_debug_string(value: &str) -> String {
    const MAX_PREVIEW_CHARS: usize = 80;
    let clipped = if value.chars().count() > MAX_PREVIEW_CHARS {
        let mut preview = value.chars().take(MAX_PREVIEW_CHARS).collect::<String>();
        preview.push_str("...");
        preview
    } else {
        value.to_owned()
    };
    format!("{clipped:?}")
}

fn has_blocking_findings(
    findings: &[lintai_api::Finding],
    ci_policy: &lintai_engine::CiPolicy,
) -> bool {
    findings
        .iter()
        .filter(|finding| {
            confidence_rank(finding.confidence) >= confidence_rank(ci_policy.min_confidence)
        })
        .any(|finding| severity_rank(finding.severity) >= severity_rank(ci_policy.fail_on))
}

fn severity_rank(severity: lintai_api::Severity) -> usize {
    match severity {
        lintai_api::Severity::Allow => 0,
        lintai_api::Severity::Warn => 1,
        lintai_api::Severity::Deny => 2,
    }
}

fn confidence_rank(confidence: lintai_api::Confidence) -> usize {
    match confidence {
        lintai_api::Confidence::Low => 0,
        lintai_api::Confidence::Medium => 1,
        lintai_api::Confidence::High => 2,
    }
}
