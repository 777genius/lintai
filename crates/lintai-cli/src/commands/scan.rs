use std::path::Path;
use std::process::ExitCode;

use crate::args::parse_scan_args;
use crate::execution::{
    build_engine, emit_report, exit_code_for_scan_summary, load_validated_workspace_for_scan,
};
use crate::output;

pub(crate) fn run(
    current_dir: &Path,
    args: impl Iterator<Item = String>,
) -> Result<ExitCode, String> {
    let parsed = parse_scan_args(args)?;
    let workspace =
        load_validated_workspace_for_scan(current_dir, &parsed.target, &parsed.preset_ids)?;
    let summary = build_engine(&workspace)?
        .scan_path(&parsed.target)
        .map_err(|error| format!("scan failed: {error}"))?;
    let report = output::build_envelope(
        &summary,
        workspace.source_path.as_deref(),
        workspace.engine_config.project_root.as_deref(),
    );

    emit_report(
        &report,
        parsed
            .format_override
            .unwrap_or(workspace.engine_config.output_format),
    )?;

    Ok(exit_code_for_scan_summary(
        &summary,
        &workspace.engine_config.ci_policy,
    ))
}
