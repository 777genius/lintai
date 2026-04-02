use std::fs;
use std::process::ExitCode;

#[path = "normalize-case-manifests/legacy_manifest.rs"]
mod legacy_manifest;

use lintai_testing::{CaseManifest, checked_in_case_dirs};

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let check_only = match args
        .as_slice()
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["--write"] => false,
        ["--check"] => true,
        _ => {
            eprintln!("usage: normalize-case-manifests [--check|--write]");
            return ExitCode::from(2);
        }
    };

    let mut rewrites = Vec::new();
    let case_dirs = match checked_in_case_dirs() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed to discover checked-in case manifests: {error}");
            return ExitCode::FAILURE;
        }
    };

    for case_dir in case_dirs {
        let manifest_path = case_dir.join("case.toml");
        let raw = match fs::read_to_string(&manifest_path) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("failed to read {}: {error}", manifest_path.display());
                return ExitCode::FAILURE;
            }
        };
        if CaseManifest::from_toml(&raw).is_ok() {
            continue;
        }

        let manifest = match legacy_manifest::load_case_manifest_with_legacy_compat(&case_dir) {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "failed to load {} through compatibility path: {error}",
                    manifest_path.display()
                );
                return ExitCode::FAILURE;
            }
        };
        let canonical = match manifest.to_canonical_toml() {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "failed to serialize {} canonically: {error}",
                    manifest_path.display()
                );
                return ExitCode::FAILURE;
            }
        };
        rewrites.push((manifest_path, canonical));
    }

    if rewrites.is_empty() {
        println!("all checked-in case manifests are already canonical");
        return ExitCode::SUCCESS;
    }

    if check_only {
        for (path, _) in &rewrites {
            println!("{}", path.display());
        }
        eprintln!(
            "{} checked-in case manifests need canonicalization",
            rewrites.len()
        );
        return ExitCode::FAILURE;
    }

    for (path, canonical) in rewrites {
        if let Err(error) = fs::write(&path, canonical) {
            eprintln!("failed to write {}: {error}", path.display());
            return ExitCode::FAILURE;
        }
        println!("rewrote {}", path.display());
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use lintai_api::RuleTier;

    use super::legacy_manifest::load_case_manifest_with_legacy_compat;

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn legacy_compat_loader_preserves_expected_findings_for_bucket_scoped_manifests() {
        let bucket_root = unique_temp_dir("lintai-bucket-scoped-manifest");
        let case_dir = bucket_root
            .join("malicious")
            .join("skill-pip-http-git-install");
        std::fs::create_dir_all(case_dir.join("repo")).unwrap();
        std::fs::write(
            case_dir.join("case.toml"),
            r#"
id = "skill-pip-http-git-install"
kind = "Skill"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 1
expected_findings = [
  { rule_code = "SEC455", min_evidence_count = 1, tier = "stable" },
]
expected_absent_rules = []
snapshot = { kind = "none", name = "" }
"#,
        )
        .unwrap();

        let manifest = load_case_manifest_with_legacy_compat(&case_dir).unwrap();
        assert_eq!(manifest.kind, lintai_testing::CaseKind::Malicious);
        assert_eq!(manifest.expected_findings.len(), 1);
        assert_eq!(manifest.expected_findings[0].rule_code, "SEC455");
        assert_eq!(manifest.expected_findings[0].tier, Some(RuleTier::Stable));
        assert!(manifest.expected_absent_rules.is_empty());
    }
}
