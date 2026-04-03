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

fn json_output(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

fn write_bytes(path: &Path, content: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

fn run_lintai(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lintai"))
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

fn write_policy(path: &Path, body: &str) {
    write(path, body);
}

#[test]
fn policy_os_allowlisted_client_and_base_dir_stays_clean() {
    let temp_dir = unique_temp_dir("lintai-policy-os-allowlisted");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let policy = temp_dir.join("policy.toml");
    fs::create_dir_all(&cwd).unwrap();

    write(&root.join(".cursor/mcp.json"), r#"{"mcpServers":{}}"#);
    write_policy(
        &policy,
        &format!(
            r#"
schema_version = 1
[rules]
unapproved_client = "deny"
unapproved_base_dir = "deny"
[allow]
clients = ["cursor"]
base_dirs = ["{}"]
"#,
            root.join(".cursor").display()
        ),
    );

    let output = run_lintai(
        &cwd,
        &[
            "policy-os",
            "--policy",
            policy.to_str().unwrap(),
            "--scope=user",
            "--path-root",
            root.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(0));

    let value = json_output(&output);
    assert!(
        value["policy_matches"]
            .as_array()
            .is_none_or(|matches| matches.is_empty())
    );
    assert_eq!(value["policy_stats"]["deny_matches"], 0);
    assert_eq!(value["policy_stats"]["warn_matches"], 0);
}

#[test]
fn policy_os_unapproved_client_emits_deny_match() {
    let temp_dir = unique_temp_dir("lintai-policy-os-unapproved-client");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let policy = temp_dir.join("policy.toml");
    fs::create_dir_all(&cwd).unwrap();

    write(&root.join(".cursor/mcp.json"), r#"{"mcpServers":{}}"#);
    write_policy(
        &policy,
        r#"
schema_version = 1
[rules]
unapproved_client = "deny"
[allow]
clients = ["windsurf"]
"#,
    );

    let output = run_lintai(
        &cwd,
        &[
            "policy-os",
            "--policy",
            policy.to_str().unwrap(),
            "--scope=user",
            "--path-root",
            root.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(1));

    let value = json_output(&output);
    let matches = value["policy_matches"].as_array().unwrap();
    assert!(matches.iter().any(|policy_match| {
        policy_match["policy_id"] == "unapproved-client"
            && policy_match["severity"] == "deny"
            && policy_match["client"] == "cursor"
    }));
}

#[test]
fn policy_os_unapproved_base_dir_emits_deny_match() {
    let temp_dir = unique_temp_dir("lintai-policy-os-unapproved-base-dir");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let policy = temp_dir.join("policy.toml");
    fs::create_dir_all(&cwd).unwrap();

    write(&root.join(".cursor/mcp.json"), r#"{"mcpServers":{}}"#);
    write_policy(
        &policy,
        &format!(
            r#"
schema_version = 1
[rules]
unapproved_base_dir = "deny"
[allow]
base_dirs = ["{}"]
"#,
            temp_dir.join("other").display()
        ),
    );

    let output = run_lintai(
        &cwd,
        &[
            "policy-os",
            "--policy",
            policy.to_str().unwrap(),
            "--scope=user",
            "--path-root",
            root.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(1));

    let value = json_output(&output);
    let matches = value["policy_matches"].as_array().unwrap();
    assert!(matches.iter().any(|policy_match| {
        policy_match["policy_id"] == "unapproved-base-dir" && policy_match["severity"] == "deny"
    }));
}

#[test]
fn policy_os_global_shell_wrapper_mcp_uses_machine_policy_default_scan_profile() {
    let temp_dir = unique_temp_dir("lintai-policy-os-shell-wrapper");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let policy = temp_dir.join("policy.toml");
    fs::create_dir_all(&cwd).unwrap();

    write(
        &root.join(".codeium/windsurf/mcp_config.json"),
        r#"{"mcpServers":{"wrapped-shell":{"command":"sh","args":["-c","./run-wrapper.sh"]}}}"#,
    );
    write_policy(
        &policy,
        &format!(
            r#"
schema_version = 1
[rules]
global_shell_wrapper_mcp = "deny"
unapproved_client = "off"
unapproved_base_dir = "off"
[allow]
clients = ["windsurf"]
base_dirs = ["{}"]
"#,
            root.join(".codeium").display()
        ),
    );

    let output = run_lintai(
        &cwd,
        &[
            "policy-os",
            "--policy",
            policy.to_str().unwrap(),
            "--scope=user",
            "--path-root",
            root.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(1));

    let value = json_output(&output);
    let matches = value["policy_matches"].as_array().unwrap();
    assert!(matches.iter().any(|policy_match| {
        policy_match["policy_id"] == "global-shell-wrapper-mcp"
            && policy_match["severity"] == "deny"
            && policy_match["matched_findings"]
                .as_array()
                .is_some_and(|findings| findings.iter().any(|finding| finding == "SEC301"))
    }));
}

#[test]
fn policy_os_plaintext_auth_uses_machine_policy_default_scan_profile() {
    let temp_dir = unique_temp_dir("lintai-policy-os-plaintext-auth");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let policy = temp_dir.join("policy.toml");
    fs::create_dir_all(&cwd).unwrap();

    write(
        &root.join(".cursor/mcp.json"),
        r#"{"env":{"OPENAI_API_KEY":"sk-test-secret"}}"#,
    );
    write_policy(
        &policy,
        &format!(
            r#"
schema_version = 1
[rules]
plaintext_auth = "deny"
[allow]
clients = ["cursor"]
base_dirs = ["{}"]
"#,
            root.join(".cursor").display()
        ),
    );

    let output = run_lintai(
        &cwd,
        &[
            "policy-os",
            "--policy",
            policy.to_str().unwrap(),
            "--scope=user",
            "--path-root",
            root.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(1));

    let value = json_output(&output);
    let matches = value["policy_matches"].as_array().unwrap();
    assert!(matches.iter().any(|policy_match| {
        policy_match["policy_id"] == "plaintext-auth"
            && policy_match["severity"] == "deny"
            && policy_match["matched_findings"]
                .as_array()
                .is_some_and(|findings| findings.iter().any(|finding| finding == "SEC309"))
    }));
}

#[test]
fn policy_os_trust_disable_warn_does_not_fail_exit_code() {
    let temp_dir = unique_temp_dir("lintai-policy-os-trust-disable");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let policy = temp_dir.join("policy.toml");
    fs::create_dir_all(&cwd).unwrap();

    write(
        &root.join(".cursor/mcp.json"),
        r#"{"client":{"url":"https://internal.test","verifyTLS":false}}"#,
    );
    write_policy(
        &policy,
        &format!(
            r#"
schema_version = 1
[rules]
trust_disable = "warn"
[allow]
clients = ["cursor"]
base_dirs = ["{}"]
"#,
            root.join(".cursor").display()
        ),
    );

    let output = run_lintai(
        &cwd,
        &[
            "policy-os",
            "--policy",
            policy.to_str().unwrap(),
            "--scope=user",
            "--path-root",
            root.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(0));

    let value = json_output(&output);
    let matches = value["policy_matches"].as_array().unwrap();
    assert!(matches.iter().any(|policy_match| {
        policy_match["policy_id"] == "trust-disable"
            && policy_match["severity"] == "warn"
            && policy_match["matched_findings"]
                .as_array()
                .is_some_and(|findings| findings.iter().any(|finding| finding == "SEC304"))
    }));
}

#[test]
fn policy_os_explicit_recommended_preset_can_keep_output_quiet() {
    let temp_dir = unique_temp_dir("lintai-policy-os-explicit-recommended");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let policy = temp_dir.join("policy.toml");
    fs::create_dir_all(&cwd).unwrap();

    write(
        &root.join(".cursor/mcp.json"),
        r#"{"env":{"OPENAI_API_KEY":"sk-test-secret"}}"#,
    );
    write_policy(
        &policy,
        &format!(
            r#"
schema_version = 1
[rules]
plaintext_auth = "deny"
[allow]
clients = ["cursor"]
base_dirs = ["{}"]
"#,
            root.join(".cursor").display()
        ),
    );

    let output = run_lintai(
        &cwd,
        &[
            "policy-os",
            "--policy",
            policy.to_str().unwrap(),
            "--preset",
            "recommended",
            "--scope=user",
            "--path-root",
            root.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(0));

    let value = json_output(&output);
    assert!(
        value["policy_matches"]
            .as_array()
            .is_none_or(|matches| matches.is_empty())
    );
}

#[test]
fn policy_os_high_risk_discovered_only_emits_warn_match() {
    let temp_dir = unique_temp_dir("lintai-policy-os-high-risk-discovered-only");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let policy = temp_dir.join("policy.toml");
    fs::create_dir_all(&cwd).unwrap();

    fs::create_dir_all(root.join(".kiro/agents/reviewer")).unwrap();
    write_policy(
        &policy,
        r#"
schema_version = 1
[rules]
high_risk_discovered_only = "warn"
"#,
    );

    let output = run_lintai(
        &cwd,
        &[
            "policy-os",
            "--policy",
            policy.to_str().unwrap(),
            "--scope=user",
            "--path-root",
            root.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(0));

    let value = json_output(&output);
    let matches = value["policy_matches"].as_array().unwrap();
    assert!(matches.iter().any(|policy_match| {
        policy_match["policy_id"] == "high-risk-discovered-only"
            && policy_match["client"] == "kiro"
            && policy_match["severity"] == "warn"
            && policy_match["risk_level"] == "high"
    }));
}

#[test]
fn policy_os_rejects_unsupported_schema_version() {
    let temp_dir = unique_temp_dir("lintai-policy-os-schema-version");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let policy = temp_dir.join("policy.toml");
    fs::create_dir_all(&cwd).unwrap();
    fs::create_dir_all(&root).unwrap();

    write_policy(
        &policy,
        r#"
schema_version = 999
[rules]
unapproved_client = "deny"
[allow]
clients = ["cursor"]
"#,
    );

    let output = run_lintai(
        &cwd,
        &[
            "policy-os",
            "--policy",
            policy.to_str().unwrap(),
            "--scope=user",
            "--path-root",
            root.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("unsupported policy schema_version"));
}

#[test]
fn policy_os_sarif_contains_policy_rule_ids() {
    let temp_dir = unique_temp_dir("lintai-policy-os-sarif");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let policy = temp_dir.join("policy.toml");
    fs::create_dir_all(&cwd).unwrap();

    write(&root.join(".cursor/mcp.json"), r#"{"mcpServers":{}}"#);
    write_policy(
        &policy,
        r#"
schema_version = 1
[rules]
unapproved_client = "deny"
[allow]
clients = ["windsurf"]
"#,
    );

    let output = run_lintai(
        &cwd,
        &[
            "policy-os",
            "--policy",
            policy.to_str().unwrap(),
            "--scope=user",
            "--path-root",
            root.to_str().unwrap(),
            "--format=sarif",
        ],
    );
    assert_eq!(output.status.code(), Some(1));

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let results = value["runs"][0]["results"].as_array().unwrap();
    assert!(
        results
            .iter()
            .any(|result| result["ruleId"] == "policy:unapproved-client")
    );
}

#[test]
fn policy_os_exits_two_on_runtime_errors() {
    let temp_dir = unique_temp_dir("lintai-policy-os-runtime-errors");
    let cwd = temp_dir.join("cwd");
    let root = temp_dir.join("machine");
    let policy = temp_dir.join("policy.toml");
    fs::create_dir_all(&cwd).unwrap();

    write_bytes(&root.join(".cursor/mcp.json"), b"{\n\xff\n}");
    write_policy(
        &policy,
        r#"
schema_version = 1
[rules]
unapproved_client = "off"
unapproved_base_dir = "off"
"#,
    );

    let output = run_lintai(
        &cwd,
        &[
            "policy-os",
            "--policy",
            policy.to_str().unwrap(),
            "--scope=user",
            "--path-root",
            root.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(2));

    let value = json_output(&output);
    assert_eq!(value["findings"].as_array().unwrap().len(), 0);
    assert_eq!(value["runtime_errors"].as_array().unwrap().len(), 1);
}
