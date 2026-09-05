use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;
use serde_json::Value;

use crate::execution::{
    build_engine, default_workspace_for_builtin_preset_names, exit_code_for_scan_summary,
};

const AGENT_PLUGINS_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
const MAX_MANIFEST_BYTES: u64 = 1 << 20;

pub(crate) const AGENT_PLUGIN_POLICY_ID: &str = "agent-plugin-install";
pub(crate) const AGENT_PLUGIN_POLICY_VERSION: u32 = 2;
pub(crate) const AGENT_PLUGIN_PRESETS: &[&str] = &[
    "recommended",
    "preview",
    "threat-review",
    "supply-chain",
    "advisory",
];

#[derive(Serialize)]
struct AgentPluginScanReport<'a> {
    schema_version: u32,
    tool: AgentPluginTool<'a>,
    policy: AgentPluginPolicy<'a>,
    stats: AgentPluginStats,
    findings: &'a [lintai_api::Finding],
    diagnostics: &'a [lintai_engine::ScanDiagnostic],
    runtime_errors: &'a [lintai_engine::ScanRuntimeError],
}

#[derive(Serialize)]
struct AgentPluginTool<'a> {
    name: &'a str,
    version: &'a str,
}

#[derive(Serialize)]
struct AgentPluginPolicy<'a> {
    id: &'a str,
    version: u32,
    presets: &'a [&'a str],
}

#[derive(Serialize)]
struct AgentPluginStats {
    scanned_files: usize,
    skipped_files: usize,
}

pub(crate) fn run(
    current_dir: &Path,
    mut args: impl Iterator<Item = String>,
) -> Result<ExitCode, String> {
    let raw_target = args
        .next()
        .ok_or_else(|| "missing package directory for scan-agent-plugin".to_owned())?;
    if let Some(extra) = args.next() {
        return Err(format!("unexpected extra argument: {extra}"));
    }
    let root = canonical_package_root(current_dir, &PathBuf::from(raw_target))?;
    validate_agent_plugin_root(&root)?;

    // This command deliberately ignores any lintai.toml controlled by the
    // untrusted package. Its fixed policy is the integration contract used by
    // installers and registries.
    let mut workspace = default_workspace_for_builtin_preset_names(AGENT_PLUGIN_PRESETS)?;
    workspace.engine_config.set_project_root(Some(root.clone()));
    let summary = build_engine(&workspace)?
        .scan_path(&root)
        .map_err(|error| format!("Agent Plugin scan failed: {error}"))?;
    let report = AgentPluginScanReport {
        schema_version: 1,
        tool: AgentPluginTool {
            name: "lintai",
            version: env!("CARGO_PKG_VERSION"),
        },
        policy: AgentPluginPolicy {
            id: AGENT_PLUGIN_POLICY_ID,
            version: AGENT_PLUGIN_POLICY_VERSION,
            presets: AGENT_PLUGIN_PRESETS,
        },
        stats: AgentPluginStats {
            scanned_files: summary.scanned_files,
            skipped_files: summary.skipped_files,
        },
        findings: &summary.findings,
        diagnostics: &summary.diagnostics,
        runtime_errors: &summary.runtime_errors,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("json output failed: {error}"))?
    );
    Ok(exit_code_for_scan_summary(
        &summary,
        &workspace.engine_config.ci_policy,
    ))
}

fn canonical_package_root(current_dir: &Path, target: &Path) -> Result<PathBuf, String> {
    let target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        current_dir.join(target)
    };
    fs::canonicalize(&target).map_err(|error| {
        format!(
            "package directory {} is unavailable: {error}",
            target.display()
        )
    })
}

fn validate_agent_plugin_root(root: &Path) -> Result<(), String> {
    if !root.is_dir() {
        return Err(format!(
            "package path {} is not a directory",
            root.display()
        ));
    }
    let manifest_path = root.join("plugin.json");
    let metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err("plugin.json must be a regular file no larger than 1 MiB".to_owned());
    }
    let manifest: Value = serde_json::from_slice(
        &fs::read(&manifest_path)
            .map_err(|error| format!("read {}: {error}", manifest_path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", manifest_path.display()))?;
    if manifest.get("$schema").and_then(Value::as_str) != Some(AGENT_PLUGINS_SCHEMA) {
        return Err(format!(
            "plugin.json must declare the published Agent Plugins 1.0 schema {AGENT_PLUGINS_SCHEMA}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "lintai-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn accepts_published_agent_plugins_manifest() {
        let root = temp_dir("agent-plugin-root");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("plugin.json"),
            format!(r#"{{"$schema":"{AGENT_PLUGINS_SCHEMA}","name":"demo"}}"#),
        )
        .unwrap();
        assert!(validate_agent_plugin_root(&root).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unrelated_plugin_manifest() {
        let root = temp_dir("unrelated-plugin-root");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("plugin.json"), r#"{"name":"demo"}"#).unwrap();
        let error = validate_agent_plugin_root(&root).unwrap_err();
        assert!(error.contains("published Agent Plugins 1.0 schema"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn installation_policy_is_fixed_and_unambiguous() {
        assert_eq!(AGENT_PLUGIN_POLICY_ID, "agent-plugin-install");
        assert_eq!(AGENT_PLUGIN_POLICY_VERSION, 2);
        assert_eq!(
            AGENT_PLUGIN_PRESETS,
            [
                "recommended",
                "preview",
                "threat-review",
                "supply-chain",
                "advisory"
            ]
        );
    }
}
