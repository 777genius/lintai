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

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
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

    let stdout = stdout_string(&output);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let roots = value["inventory_roots"].as_array().unwrap();
    assert_eq!(roots.len(), 2);
    assert!(roots.iter().all(|root| root["provenance"]["origin_scope"] == "user"));
    assert!(roots.iter().all(|root| root["mode"] == "lintable"));
    assert!(roots.iter().all(|root| root["risk_level"] == "high"));
    assert!(roots.iter().any(|root| {
        root["client"] == "windsurf" && root["surface"] == "mcp-config"
    }));
    assert!(roots.iter().any(|root| {
        root["client"] == "claude-desktop" && root["surface"] == "desktop-config"
    }));

    let stats = &value["inventory_stats"];
    assert_eq!(stats["user_roots"], 2);
    assert_eq!(stats["system_roots"], 0);
    assert_eq!(stats["lintable_roots"], 2);
    assert_eq!(stats["high_risk_roots"], 2);
    assert_eq!(stats["supported_artifacts_scanned"], 2);

    let findings = value["findings"].as_array().unwrap();
    assert!(findings.iter().any(|finding| finding["rule_code"] == "SEC301"));
    assert!(findings.iter().any(|finding| finding["rule_code"] == "SEC302"));
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

    let stdout = stdout_string(&output);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
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

    let stdout = stdout_string(&output);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        value
            .get("inventory_roots")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|roots| roots.is_empty())
    );
    assert_eq!(value["inventory_stats"]["system_roots"], 0);
    assert_eq!(value["findings"].as_array().unwrap().len(), 0);
    assert_eq!(value["stats"]["scanned_files"], 0);
}
