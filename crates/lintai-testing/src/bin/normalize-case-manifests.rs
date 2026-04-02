use std::fs;
use std::process::ExitCode;

use lintai_testing::{CaseManifest, case_manifest_dialect_flags, checked_in_case_dirs};

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let check_only = match args.as_slice().iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
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
        let flags = case_manifest_dialect_flags(&raw);
        let is_canonical = CaseManifest::from_toml(&raw).is_ok() && flags.is_empty();
        if is_canonical {
            continue;
        }

        let manifest = match CaseManifest::load(&case_dir) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("failed to load {} through compatibility path: {error}", manifest_path.display());
                return ExitCode::FAILURE;
            }
        };
        let canonical = match manifest.to_canonical_toml() {
            Ok(value) => value,
            Err(error) => {
                eprintln!("failed to serialize {} canonically: {error}", manifest_path.display());
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
        eprintln!("{} checked-in case manifests need canonicalization", rewrites.len());
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
