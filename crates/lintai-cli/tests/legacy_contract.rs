use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should be discoverable from lintai-cli")
}

fn collect_source_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("source directory should be readable") {
        let entry = entry.expect("directory entry should be readable");
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|value| value.to_str()) == Some("target") {
                continue;
            }
            collect_source_files(&path, files);
            continue;
        }
        if matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("rs" | "md" | "toml")
        ) {
            files.push(path);
        }
    }
}

fn repo_text() -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    collect_source_files(&repo_root().join("crates"), &mut files);
    collect_source_files(&repo_root().join("docs"), &mut files);
    files
        .into_iter()
        .filter(|path| {
            path.file_name().and_then(|value| value.to_str()) != Some("legacy_contract.rs")
        })
        .map(|path| {
            let text = fs::read_to_string(&path).unwrap_or_default();
            (path, text)
        })
        .collect()
}

#[test]
fn legacy_provider_registration_strings_are_absent() {
    for (path, text) in repo_text() {
        assert!(
            !text.contains("with_provider(") && !text.contains("with_providers("),
            "legacy provider registration should be absent from {}",
            path.display()
        );
    }
}

#[test]
fn lifecycle_hooks_and_deprecated_rule_tier_are_absent() {
    for (path, text) in repo_text() {
        assert!(
            !text.contains("on_start(") && !text.contains("on_finish("),
            "lifecycle hook legacy should be absent from {}",
            path.display()
        );
        assert!(
            !text.contains("RuleTier::Deprecated")
                && !text.contains("stable | preview | deprecated"),
            "deprecated rule tier legacy should be absent from {}",
            path.display()
        );
    }
}

#[test]
fn provider_capabilities_and_ruleprovider_execution_knobs_are_absent() {
    let api_rule = fs::read_to_string(repo_root().join("crates/lintai-api/src/rule.rs"))
        .expect("lintai-api rule contract should be readable");
    let api_lib = fs::read_to_string(repo_root().join("crates/lintai-api/src/lib.rs"))
        .expect("lintai-api lib should be readable");
    let engine_provider =
        fs::read_to_string(repo_root().join("crates/lintai-engine/src/provider.rs"))
            .expect("engine provider backend should be readable");

    assert!(!api_rule.contains("ProviderCapabilities"));
    assert!(!api_lib.contains("ProviderCapabilities"));
    assert!(!api_rule.contains("fn timeout(&self)"));
    assert!(!api_rule.contains("fn capabilities(&self)"));
    assert!(!api_rule.contains("fn scan_scope(&self)"));
    assert!(!engine_provider.contains("provider.timeout()"));
    assert!(!engine_provider.contains("provider.capabilities()"));
    assert!(!engine_provider.contains("provider.scan_scope()"));
}

#[test]
fn internal_runner_schema_version_is_absent() {
    let text = fs::read_to_string(
        repo_root().join("crates/lintai-cli/src/builtin_providers.rs"),
    )
    .expect("builtin provider runtime source should be readable");
    assert!(
        !text.contains("schema_version"),
        "internal runner protocol should not carry compatibility schema_version fields"
    );
}

#[test]
fn root_engine_surface_does_not_export_internal_helpers() {
    let engine_lib = fs::read_to_string(repo_root().join("crates/lintai-engine/src/lib.rs"))
        .expect("engine lib should be readable");
    assert!(
        !engine_lib.contains("pub mod artifact_view;"),
        "artifact_view should not be part of engine surface"
    );
    assert!(
        !engine_lib.contains("pub use provider::{InProcessProviderBackend, ProviderBackend};"),
        "InProcessProviderBackend should not be re-exported from engine root"
    );
}
