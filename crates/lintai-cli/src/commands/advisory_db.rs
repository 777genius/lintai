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
            let bundled = bundled_snapshot_json_pretty()?;
            if let Some(output) = args.next() {
                write_file_atomic(PathBuf::from(output), &bundled)?;
            } else {
                print!("{}", bundled);
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
    "lintai advisory-db export-bundled [output-file]\nlintai advisory-db update --input FILE --output FILE\n\nUse LINTAI_ADVISORY_SNAPSHOT=/path/to/advisories.normalized.json lintai scan . to scan with a normalized custom snapshot.".to_owned()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn run_without_arguments_reports_usage() {
        let error = run(std::iter::empty()).unwrap_err();
        assert!(
            error.starts_with("missing")
                || error.contains("usage")
                || error.contains("lintai advisory-db")
        );
    }

    #[test]
    fn run_help_command_is_success() {
        let exit_code = run(["help".to_string()].into_iter()).unwrap();
        assert_eq!(exit_code, std::process::ExitCode::SUCCESS);
    }

    #[test]
    fn run_export_bundled_is_success() {
        run(["export-bundled".to_string()].into_iter()).unwrap();
    }

    #[test]
    fn run_update_round_trips_normalized_snapshot() {
        let dir = std::env::temp_dir().join(format!("lintai-advisory-db-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let input = dir.join("input.json");
        let output = dir.join("output.json");
        let input_json = r#"{
  "schema_version": 1,
  "ecosystem": "npm",
  "generated_at": "2026-04-08T00:00:00Z",
  "source": "tests",
  "snapshot_revision": "x",
  "advisories": [
    {
      "id": "X-1",
      "package": "left-pad",
      "aliases": [],
      "summary": "demo",
      "references": ["https://example.test/X-1"],
      "ranges": [
        {
          "introduced": "0.0.0",
          "fixed": "1.0.0"
        }
      ]
    }
  ]
}"#;
        fs::write(&input, input_json).unwrap();
        run([
            "update".to_string(),
            "--input".to_string(),
            input.to_string_lossy().to_string(),
            "--output".to_string(),
            output.to_string_lossy().to_string(),
        ].into_iter()).unwrap();

        assert!(output.exists());
        let text = fs::read_to_string(output).unwrap();
        assert!(text.contains("\"generated_at\""));
        assert!(text.contains("\"advisories\""));
    }
}
