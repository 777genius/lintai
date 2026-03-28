use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Copy)]
enum OutputKind {
    Text,
    Json,
    Sarif,
    FixPreview,
    ExplainConfig,
    Help,
    ConfigSchema,
}

struct CommandCase {
    name: &'static str,
    cwd: PathBuf,
    args: &'static [&'static str],
    expected_exit: i32,
    output_kind: OutputKind,
    expected_rules: &'static [&'static str],
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should be discoverable from lintai-cli tests")
}

fn sample_repo_dir(name: &str) -> PathBuf {
    repo_root().join("sample-repos").join(name).join("repo")
}

fn docs_cases() -> Vec<CommandCase> {
    vec![
        CommandCase {
            name: "root-help",
            cwd: repo_root(),
            args: &["help"],
            expected_exit: 0,
            output_kind: OutputKind::Help,
            expected_rules: &[],
        },
        CommandCase {
            name: "root-config-schema",
            cwd: repo_root(),
            args: &["config-schema"],
            expected_exit: 0,
            output_kind: OutputKind::ConfigSchema,
            expected_rules: &[],
        },
        CommandCase {
            name: "fixable-comments-fix-preview",
            cwd: sample_repo_dir("fixable-comments"),
            args: &["fix", "."],
            expected_exit: 0,
            output_kind: OutputKind::FixPreview,
            expected_rules: &["SEC101", "SEC103"],
        },
        CommandCase {
            name: "clean-scan-text",
            cwd: sample_repo_dir("clean"),
            args: &["scan", "."],
            expected_exit: 0,
            output_kind: OutputKind::Text,
            expected_rules: &[],
        },
        CommandCase {
            name: "clean-scan-json",
            cwd: sample_repo_dir("clean"),
            args: &["scan", ".", "--format=json"],
            expected_exit: 0,
            output_kind: OutputKind::Json,
            expected_rules: &[],
        },
        CommandCase {
            name: "clean-scan-sarif",
            cwd: sample_repo_dir("clean"),
            args: &["scan", ".", "--format=sarif"],
            expected_exit: 0,
            output_kind: OutputKind::Sarif,
            expected_rules: &[],
        },
        CommandCase {
            name: "mcp-heavy-scan-text",
            cwd: sample_repo_dir("mcp-heavy"),
            args: &["scan", "."],
            expected_exit: 0,
            output_kind: OutputKind::Text,
            expected_rules: &["SEC301", "SEC302", "SEC303"],
        },
        CommandCase {
            name: "mcp-heavy-scan-json",
            cwd: sample_repo_dir("mcp-heavy"),
            args: &["scan", ".", "--format=json"],
            expected_exit: 0,
            output_kind: OutputKind::Json,
            expected_rules: &["SEC301", "SEC302", "SEC303"],
        },
        CommandCase {
            name: "mcp-heavy-scan-sarif",
            cwd: sample_repo_dir("mcp-heavy"),
            args: &["scan", ".", "--format=sarif"],
            expected_exit: 0,
            output_kind: OutputKind::Sarif,
            expected_rules: &["SEC301", "SEC302", "SEC303"],
        },
        CommandCase {
            name: "cursor-plugin-scan-text",
            cwd: sample_repo_dir("cursor-plugin"),
            args: &["scan", "."],
            expected_exit: 1,
            output_kind: OutputKind::Text,
            expected_rules: &["SEC201", "SEC202", "SEC203", "SEC205"],
        },
        CommandCase {
            name: "cursor-plugin-scan-json",
            cwd: sample_repo_dir("cursor-plugin"),
            args: &["scan", ".", "--format=json"],
            expected_exit: 1,
            output_kind: OutputKind::Json,
            expected_rules: &["SEC201", "SEC202", "SEC203", "SEC205"],
        },
        CommandCase {
            name: "cursor-plugin-scan-sarif",
            cwd: sample_repo_dir("cursor-plugin"),
            args: &["scan", ".", "--format=sarif"],
            expected_exit: 1,
            output_kind: OutputKind::Sarif,
            expected_rules: &["SEC201", "SEC202", "SEC203", "SEC205"],
        },
        CommandCase {
            name: "policy-mismatch-scan-text",
            cwd: sample_repo_dir("policy-mismatch"),
            args: &["scan", "."],
            expected_exit: 0,
            output_kind: OutputKind::Text,
            expected_rules: &["SEC201", "SEC401", "SEC402", "SEC403"],
        },
        CommandCase {
            name: "policy-mismatch-scan-json",
            cwd: sample_repo_dir("policy-mismatch"),
            args: &["scan", ".", "--format=json"],
            expected_exit: 0,
            output_kind: OutputKind::Json,
            expected_rules: &["SEC201", "SEC401", "SEC402", "SEC403"],
        },
        CommandCase {
            name: "policy-mismatch-scan-sarif",
            cwd: sample_repo_dir("policy-mismatch"),
            args: &["scan", ".", "--format=sarif"],
            expected_exit: 0,
            output_kind: OutputKind::Sarif,
            expected_rules: &["SEC201", "SEC401", "SEC402", "SEC403"],
        },
        CommandCase {
            name: "policy-mismatch-explain-config",
            cwd: sample_repo_dir("policy-mismatch"),
            args: &["explain-config", "custom/agent.md"],
            expected_exit: 0,
            output_kind: OutputKind::ExplainConfig,
            expected_rules: &[],
        },
    ]
}

fn run_case(case: &CommandCase) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lintai"))
        .current_dir(&case.cwd)
        .args(case.args)
        .output()
        .unwrap_or_else(|error| panic!("{} failed to spawn: {error}", case.name))
}

fn stdout_string(output: &std::process::Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be valid UTF-8")
}

fn assert_text_output(case: &CommandCase, stdout: &str) {
    assert!(
        stdout.starts_with("scanned "),
        "{} text output missing summary line: {stdout}",
        case.name
    );

    if case.expected_rules.is_empty() {
        assert!(
            stdout.contains("found 0 finding(s)"),
            "{} expected clean summary: {stdout}",
            case.name
        );
    } else {
        for rule in case.expected_rules {
            assert!(
                stdout.contains(rule),
                "{} text output missing rule {}: {stdout}",
                case.name,
                rule
            );
        }
    }
}

fn assert_json_output(case: &CommandCase, stdout: &str) {
    let value: serde_json::Value = serde_json::from_str(stdout)
        .unwrap_or_else(|error| panic!("{} invalid JSON: {error}", case.name));
    assert_eq!(
        value["schema_version"], 1,
        "{} schema_version drifted",
        case.name
    );
    assert!(
        value["findings"].is_array(),
        "{} JSON findings shape missing: {stdout}",
        case.name
    );
    if case.expected_rules.is_empty() {
        assert_eq!(
            value["findings"].as_array().unwrap().len(),
            0,
            "{} expected no findings",
            case.name
        );
    } else {
        let findings = value["findings"].as_array().unwrap();
        for rule in case.expected_rules {
            assert!(
                findings.iter().any(|finding| finding["rule_code"] == *rule),
                "{} JSON output missing rule {}: {stdout}",
                case.name,
                rule
            );
        }
    }
}

fn assert_sarif_output(case: &CommandCase, stdout: &str) {
    let value: serde_json::Value = serde_json::from_str(stdout)
        .unwrap_or_else(|error| panic!("{} invalid SARIF JSON: {error}", case.name));
    let results = value["runs"][0]["results"]
        .as_array()
        .unwrap_or_else(|| panic!("{} SARIF results missing: {stdout}", case.name));
    if case.expected_rules.is_empty() {
        assert_eq!(
            results.len(),
            0,
            "{} expected zero SARIF results",
            case.name
        );
    } else {
        assert!(
            !results.is_empty(),
            "{} expected SARIF results: {stdout}",
            case.name
        );
        for result in results {
            assert!(
                result.get("ruleId").is_some(),
                "{} missing SARIF ruleId",
                case.name
            );
            assert!(
                result["partialFingerprints"].get("stableKey").is_some(),
                "{} missing SARIF stableKey fingerprint",
                case.name
            );
        }
        for rule in case.expected_rules {
            assert!(
                results.iter().any(|result| result["ruleId"] == *rule),
                "{} SARIF output missing rule {}: {stdout}",
                case.name,
                rule
            );
        }
    }
}

fn assert_explain_config_output(case: &CommandCase, stdout: &str) {
    for expected in [
        "detected_kind=",
        "detected_format=",
        "capability_conflict_mode=",
        "project_capabilities=",
    ] {
        assert!(
            stdout.contains(expected),
            "{} explain-config output missing {}: {stdout}",
            case.name,
            expected
        );
    }
}

fn assert_fix_preview_output(case: &CommandCase, stdout: &str) {
    for rule in case.expected_rules {
        assert!(
            stdout.contains(rule),
            "{} fix preview missing rule {}: {stdout}",
            case.name,
            rule
        );
    }
    for expected in [
        "selected 2 autofixable finding(s)",
        "planned 2 fix(es)",
        "files changed 1",
    ] {
        assert!(
            stdout.contains(expected),
            "{} fix preview missing {}: {stdout}",
            case.name,
            expected
        );
    }
}

fn assert_help_output(case: &CommandCase, stdout: &str) {
    for expected in [
        "lintai scan [path]",
        "lintai scan-known [--scope=project|global|both] [--client NAME]",
        "lintai inventory-os [--scope=user|system|both] [--client NAME]",
        "lintai fix [path] [--apply] [--rule CODE]",
        "lintai explain-config <file>",
        "lintai config-schema",
    ] {
        assert!(
            stdout.contains(expected),
            "{} help output missing {}: {stdout}",
            case.name,
            expected
        );
    }
}

fn assert_config_schema_output(case: &CommandCase, stdout: &str) {
    let value: serde_json::Value = serde_json::from_str(stdout)
        .unwrap_or_else(|error| panic!("{} invalid schema JSON: {error}", case.name));
    assert!(
        value.get("$defs").is_some(),
        "{} schema missing $defs",
        case.name
    );
}

fn assert_case(case: &CommandCase) {
    let output = run_case(case);
    let exit = output
        .status
        .code()
        .unwrap_or_else(|| panic!("{} terminated without an exit code", case.name));
    let stdout = stdout_string(&output);
    let stderr = String::from_utf8(output.stderr.clone()).expect("stderr should be valid UTF-8");

    assert_eq!(
        exit, case.expected_exit,
        "{} exit code mismatch\nstdout:\n{}\nstderr:\n{}",
        case.name, stdout, stderr
    );

    match case.output_kind {
        OutputKind::Text => assert_text_output(case, &stdout),
        OutputKind::Json => assert_json_output(case, &stdout),
        OutputKind::Sarif => assert_sarif_output(case, &stdout),
        OutputKind::FixPreview => assert_fix_preview_output(case, &stdout),
        OutputKind::ExplainConfig => assert_explain_config_output(case, &stdout),
        OutputKind::Help => assert_help_output(case, &stdout),
        OutputKind::ConfigSchema => assert_config_schema_output(case, &stdout),
    }
}

#[test]
fn documented_commands_match_the_release_contract() {
    for case in docs_cases() {
        assert!(
            Path::new(&case.cwd).exists(),
            "{} cwd does not exist: {}",
            case.name,
            case.cwd.display()
        );
        assert_case(&case);
    }
}
