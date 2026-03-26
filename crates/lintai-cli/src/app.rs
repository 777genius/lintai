use std::process::ExitCode;
use std::sync::Arc;

use lintai_ai_security::{AiSecurityProvider, PolicyMismatchProvider};
use lintai_engine::{
    Engine, FileSuppressions, OutputFormat, ResolvedFileConfig, explain_file_config,
    load_workspace_config,
};

use crate::args::{parse_explain_config_args, parse_scan_args};
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
        "explain-config" => run_explain_config(&current_dir, args),
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

fn run_scan(
    current_dir: &std::path::Path,
    args: impl Iterator<Item = String>,
) -> Result<ExitCode, String> {
    let parsed = parse_scan_args(args)?;
    let target = parsed.target;
    let format_override = parsed.format_override;

    let workspace = load_workspace_config(current_dir)
        .map_err(|error| format!("config resolution failed: {error}"))?;
    validate_path_within_project(&target, workspace.engine_config.project_root.as_deref())
        .map_err(|error| format!("target validation failed: {error}"))?;
    let suppressions = FileSuppressions::load(&workspace.engine_config)
        .map_err(|error| format!("suppress loading failed: {error}"))?;
    let engine = Engine::builder()
        .with_config(workspace.engine_config.clone())
        .with_suppressions(Arc::new(suppressions))
        .with_provider(Arc::new(AiSecurityProvider::default()))
        .with_provider(Arc::new(PolicyMismatchProvider))
        .build();

    let summary = engine
        .scan_path(&target)
        .map_err(|error| format!("scan failed: {error}"))?;
    let report = output::build_envelope(
        &summary,
        workspace.source_path.as_deref(),
        workspace.engine_config.project_root.as_deref(),
    );

    let output_format = format_override.unwrap_or(workspace.engine_config.output_format);
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

fn run_explain_config(
    current_dir: &std::path::Path,
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
    config_source: Option<&std::path::Path>,
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
    println!("lintai explain-config <file>");
    println!("lintai config-schema");
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
