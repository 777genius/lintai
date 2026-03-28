use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{prefix}-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn stdout_string(output: &std::process::Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be valid UTF-8")
}

fn json_output(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_str(&stdout_string(output)).unwrap()
}

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn canonical_display(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn run_lintai(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lintai"))
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

fn baseline_snapshot(
    roots: serde_json::Value,
    findings: serde_json::Value,
    user_roots: usize,
    lintable_roots: usize,
    high_risk_roots: usize,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "generated_at": 1,
        "inventory_roots": roots,
        "inventory_stats": {
            "user_roots": user_roots,
            "system_roots": 0,
            "lintable_roots": lintable_roots,
            "discovered_only_roots": user_roots.saturating_sub(lintable_roots),
            "high_risk_roots": high_risk_roots,
            "medium_risk_roots": 0,
            "low_risk_roots": user_roots.saturating_sub(high_risk_roots),
            "supported_artifacts_scanned": lintable_roots,
            "non_target_files_in_lintable_roots": 0,
            "excluded_files": 0,
            "binary_files": 0,
            "unreadable_files": 0,
            "unrecognized_files": 0
        },
        "findings": findings
    })
}

#[test]
fn inventory_os_user_scope_reports_provenance_and_findings() {
    let temp_dir = unique_temp_dir("lintai-inventory-os-user");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    fs::create_dir_all(&cwd).unwrap();

    write(
        &root.join(".codeium/windsurf/mcp_config.json"),
        r#"{
  "mcpServers": {
    "wrapped-shell": { "command": "sh", "args": ["-c", "./run-wrapper.sh"] }
  }
}"#,
    );
    write(
        &root.join("Library/Application Support/Claude/claude_desktop_config.json"),
        r#"{
  "servers": {
    "remote-http": { "transport": "http", "url": "http://evil.test/mcp" }
  }
}"#,
    );

    let path_root = root.display().to_string();
    let output = run_lintai(
        &cwd,
        &[
            "inventory-os",
            "--scope=user",
            "--path-root",
            &path_root,
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(0));

    let value = json_output(&output);
    let roots = value["inventory_roots"].as_array().unwrap();
    assert_eq!(roots.len(), 2);
    assert!(roots
        .iter()
        .all(|root| root["provenance"]["origin_scope"] == "user"));
    assert!(roots.iter().all(|root| root["mode"] == "lintable"));
    assert!(roots.iter().all(|root| root["risk_level"] == "high"));
    assert!(roots
        .iter()
        .any(|root| { root["client"] == "windsurf" && root["surface"] == "mcp-config" }));
    assert!(roots
        .iter()
        .any(|root| { root["client"] == "claude-desktop" && root["surface"] == "desktop-config" }));

    let stats = &value["inventory_stats"];
    assert_eq!(stats["user_roots"], 2);
    assert_eq!(stats["system_roots"], 0);
    assert_eq!(stats["lintable_roots"], 2);
    assert_eq!(stats["high_risk_roots"], 2);
    assert_eq!(stats["supported_artifacts_scanned"], 2);

    let findings = value["findings"].as_array().unwrap();
    assert!(findings
        .iter()
        .any(|finding| finding["rule_code"] == "SEC301"));
    assert!(findings
        .iter()
        .any(|finding| finding["rule_code"] == "SEC302"));
    assert!(findings.iter().any(|finding| {
        finding["location"]["normalized_path"]
            == canonical_display(&root.join(".codeium/windsurf/mcp_config.json"))
    }));
}

#[test]
fn inventory_os_respects_client_filter() {
    let temp_dir = unique_temp_dir("lintai-inventory-os-client-filter");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    fs::create_dir_all(&cwd).unwrap();

    write(
        &root.join(".codeium/windsurf/mcp_config.json"),
        r#"{"mcpServers":{"wrapped-shell":{"command":"sh","args":["-c","./run-wrapper.sh"]}}}"#,
    );
    write(
        &root.join("Library/Application Support/Claude/claude_desktop_config.json"),
        r#"{"servers":{"remote-http":{"transport":"http","url":"http://evil.test/mcp"}}}"#,
    );

    let path_root = root.display().to_string();
    let output = run_lintai(
        &cwd,
        &[
            "inventory-os",
            "--scope=user",
            "--client=windsurf",
            "--path-root",
            &path_root,
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(0));

    let value = json_output(&output);
    let roots = value["inventory_roots"].as_array().unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0]["client"], "windsurf");
    assert_eq!(value["inventory_stats"]["user_roots"], 1);
}

#[test]
fn inventory_os_system_scope_is_truthful_when_no_system_roots_exist() {
    let temp_dir = unique_temp_dir("lintai-inventory-os-system");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    fs::create_dir_all(&cwd).unwrap();
    fs::create_dir_all(&root).unwrap();

    let path_root = root.display().to_string();
    let output = run_lintai(
        &cwd,
        &[
            "inventory-os",
            "--scope=system",
            "--path-root",
            &path_root,
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(0));

    let value = json_output(&output);
    assert!(value
        .get("inventory_roots")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|roots| roots.is_empty()));
    assert_eq!(value["inventory_stats"]["system_roots"], 0);
    assert_eq!(value["findings"].as_array().unwrap().len(), 0);
    assert_eq!(value["stats"]["scanned_files"], 0);
}

#[test]
fn inventory_os_write_baseline_persists_snapshot_contract() {
    let temp_dir = unique_temp_dir("lintai-inventory-os-baseline-write");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let baseline = temp_dir.join("baseline.json");
    fs::create_dir_all(&cwd).unwrap();

    write(
        &root.join(".codeium/windsurf/mcp_config.json"),
        r#"{"mcpServers":{"wrapped-shell":{"command":"sh","args":["-c","./run-wrapper.sh"]}}}"#,
    );

    let path_root = root.display().to_string();
    let output = run_lintai(
        &cwd,
        &[
            "inventory-os",
            "--scope=user",
            "--path-root",
            &path_root,
            "--write-baseline",
            baseline.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(0));

    let snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(&baseline).unwrap()).unwrap();
    assert_eq!(snapshot["schema_version"], 1);
    assert!(snapshot["generated_at"].as_u64().is_some());
    assert_eq!(snapshot["inventory_roots"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["inventory_stats"]["user_roots"], 1);
    assert_eq!(snapshot["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn inventory_os_diff_reports_new_roots() {
    let temp_dir = unique_temp_dir("lintai-inventory-os-diff-new-root");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let baseline = temp_dir.join("baseline.json");
    fs::create_dir_all(&cwd).unwrap();

    write(
        &root.join(".codeium/windsurf/mcp_config.json"),
        r#"{"mcpServers":{"wrapped-shell":{"command":"sh","args":["-c","./run-wrapper.sh"]}}}"#,
    );
    let path_root = root.display().to_string();
    let baseline_output = run_lintai(
        &cwd,
        &[
            "inventory-os",
            "--scope=user",
            "--path-root",
            &path_root,
            "--write-baseline",
            baseline.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(baseline_output.status.code(), Some(0));

    write(
        &root.join("Library/Application Support/Claude/claude_desktop_config.json"),
        r#"{"servers":{"remote-http":{"transport":"http","url":"http://evil.test/mcp"}}}"#,
    );
    let output = run_lintai(
        &cwd,
        &[
            "inventory-os",
            "--scope=user",
            "--path-root",
            &path_root,
            "--diff-against",
            baseline.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(0));

    let value = json_output(&output);
    assert_eq!(
        value["inventory_diff"]["new_roots"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        value["inventory_diff"]["removed_roots"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn inventory_os_diff_reports_removed_roots() {
    let temp_dir = unique_temp_dir("lintai-inventory-os-diff-removed-root");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let baseline = temp_dir.join("baseline.json");
    fs::create_dir_all(&cwd).unwrap();

    let windsurf = root.join(".codeium/windsurf/mcp_config.json");
    let claude = root.join("Library/Application Support/Claude/claude_desktop_config.json");
    write(
        &windsurf,
        r#"{"mcpServers":{"wrapped-shell":{"command":"sh","args":["-c","./run-wrapper.sh"]}}}"#,
    );
    write(
        &claude,
        r#"{"servers":{"remote-http":{"transport":"http","url":"http://evil.test/mcp"}}}"#,
    );
    let path_root = root.display().to_string();
    let baseline_output = run_lintai(
        &cwd,
        &[
            "inventory-os",
            "--scope=user",
            "--path-root",
            &path_root,
            "--write-baseline",
            baseline.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(baseline_output.status.code(), Some(0));

    fs::remove_file(&claude).unwrap();
    let output = run_lintai(
        &cwd,
        &[
            "inventory-os",
            "--scope=user",
            "--path-root",
            &path_root,
            "--diff-against",
            baseline.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(0));

    let value = json_output(&output);
    assert_eq!(
        value["inventory_diff"]["removed_roots"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn inventory_os_diff_reports_changed_roots_newly_lintable_risk_increase_and_new_findings() {
    let temp_dir = unique_temp_dir("lintai-inventory-os-diff-changed");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let baseline = temp_dir.join("baseline.json");
    fs::create_dir_all(&cwd).unwrap();

    let windsurf = root.join(".codeium/windsurf/mcp_config.json");
    write(
        &windsurf,
        r#"{"mcpServers":{"wrapped-shell":{"command":"sh","args":["-c","./run-wrapper.sh"]}}}"#,
    );
    let canonical = canonical_display(&windsurf);
    write_json(
        &baseline,
        &baseline_snapshot(
            serde_json::json!([{
                "client": "windsurf",
                "surface": "mcp-config",
                "path": canonical,
                "mode": "discovered_only",
                "risk_level": "low",
                "provenance": {
                    "origin_scope": "user",
                    "path_type": "file",
                    "mtime_epoch_s": 1
                }
            }]),
            serde_json::json!([]),
            1,
            0,
            0,
        ),
    );

    let path_root = root.display().to_string();
    let output = run_lintai(
        &cwd,
        &[
            "inventory-os",
            "--scope=user",
            "--path-root",
            &path_root,
            "--diff-against",
            baseline.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(0));

    let value = json_output(&output);
    assert_eq!(
        value["inventory_diff"]["changed_roots"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        value["inventory_diff"]["new_lintable_roots"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        value["inventory_diff"]["risk_increased_roots"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!value["inventory_diff"]["new_findings"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn inventory_os_diff_rejects_incompatible_schema_version() {
    let temp_dir = unique_temp_dir("lintai-inventory-os-diff-schema");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let baseline = temp_dir.join("baseline.json");
    fs::create_dir_all(&cwd).unwrap();
    fs::create_dir_all(&root).unwrap();
    write_json(
        &baseline,
        &serde_json::json!({
            "schema_version": 999,
            "generated_at": 1,
            "inventory_roots": [],
            "inventory_stats": {
                "user_roots": 0,
                "system_roots": 0,
                "lintable_roots": 0,
                "discovered_only_roots": 0,
                "high_risk_roots": 0,
                "medium_risk_roots": 0,
                "low_risk_roots": 0,
                "supported_artifacts_scanned": 0,
                "non_target_files_in_lintable_roots": 0,
                "excluded_files": 0,
                "binary_files": 0,
                "unreadable_files": 0,
                "unrecognized_files": 0
            },
            "findings": []
        }),
    );

    let path_root = root.display().to_string();
    let output = run_lintai(
        &cwd,
        &[
            "inventory-os",
            "--scope=user",
            "--path-root",
            &path_root,
            "--diff-against",
            baseline.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("unsupported baseline schema_version"));
}
