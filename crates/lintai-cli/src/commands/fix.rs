use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use lintai_api::{Applicability, Finding};
use lintai_fix::{apply_planned_fixes, plan_fixes};

use crate::args::parse_fix_args;
use crate::execution::{build_engine, load_validated_workspace};

pub(crate) fn run(
    current_dir: &Path,
    args: impl Iterator<Item = String>,
) -> Result<ExitCode, String> {
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
