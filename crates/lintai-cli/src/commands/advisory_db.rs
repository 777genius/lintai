use std::path::PathBuf;
use std::process::ExitCode;

use lintai_dep_vulns::{bundled_snapshot_json_pretty, normalize_snapshot_json};

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    let mut args = args;
    let Some(command) = args.next() else {
        return Err(usage());
    };

    match command.as_str() {
        "export-bundled" => {
            if let Some(output) = args.next() {
                write_file_atomic(PathBuf::from(output), &bundled_snapshot_json_pretty())?;
            } else {
                print!("{}", bundled_snapshot_json_pretty());
            }
            Ok(ExitCode::SUCCESS)
        }
        "update" => {
            let mut input = None;
            let mut output = None;
            let mut args = args.peekable();
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--input" => input = args.next().map(PathBuf::from),
                    "--output" => output = args.next().map(PathBuf::from),
                    other => {
                        return Err(format!(
                            "unknown advisory-db update arg: {other}\n{}",
                            usage()
                        ));
                    }
                }
            }
            let input = input.ok_or_else(|| format!("missing --input\n{}", usage()))?;
            let output = output.ok_or_else(|| format!("missing --output\n{}", usage()))?;
            let raw = std::fs::read_to_string(&input)
                .map_err(|error| format!("failed to read {}: {error}", input.display()))?;
            let normalized = normalize_snapshot_json(&raw).map_err(|error| {
                format!("invalid advisory snapshot {}: {error}", input.display())
            })?;
            write_file_atomic(output, &normalized)?;
            Ok(ExitCode::SUCCESS)
        }
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown advisory-db command: {other}\n{}", usage())),
    }
}

fn write_file_atomic(path: PathBuf, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    let tmp_path = path.with_extension(format!(
        "{}tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| format!("{ext}."))
            .unwrap_or_default()
    ));
    std::fs::write(&tmp_path, contents)
        .map_err(|error| format!("failed to write {}: {error}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, &path)
        .map_err(|error| format!("failed to replace {}: {error}", path.display()))?;
    Ok(())
}

fn usage() -> String {
    "lintai advisory-db export-bundled [output-file]\nlintai advisory-db update --input FILE --output FILE".to_owned()
}
