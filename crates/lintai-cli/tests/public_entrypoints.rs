use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should be discoverable from lintai-cli tests")
}

fn run_root_cargo(args: &[&str]) -> std::process::Output {
    run_cargo(repo_root(), args, &[])
}

fn run_cargo(cwd: PathBuf, args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new("cargo");
    command.current_dir(cwd).args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn cargo {:?}: {error}", args))
}

fn temp_path(prefix: &str, suffix: &str) -> PathBuf {
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{nanos}-{sequence}{suffix}",
        std::process::id()
    ))
}

fn advisory_snapshot_fixture_path() -> PathBuf {
    let path = temp_path("lintai-cli-advisory-snapshot", ".json");
    fs::write(
        &path,
        r#"{
          "schema_version": 1,
          "ecosystem": "npm",
          "generated_at": "2026-04-02T00:00:00Z",
          "source": "custom-e2e-snapshot",
          "snapshot_revision": "custom-e2e-1",
          "advisories": [
            {
              "id": "CUSTOM-E2E-1",
              "package": "left-pad",
              "aliases": [],
              "summary": "demo",
              "references": ["https://example.test/CUSTOM-E2E-1"],
              "ranges": [{"introduced": "0.0.0", "fixed": "1.3.0"}]
            }
          ]
        }"#,
    )
    .unwrap();
    path
}

fn write_repo_file(repo: &Path, relative_path: &str, contents: &str) {
    let path = repo.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn stderr_string(output: &std::process::Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be valid UTF-8")
}

#[test]
fn readme_root_cargo_help_command_is_truthful() {
    let output = run_root_cargo(&["run", "--", "help"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "README cargo help command failed:\n{}",
        stderr_string(&output)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    assert!(
        stdout.contains("lintai scan [path] [--preset NAME]")
            && stdout.contains("--color=auto|always|never")
            && stdout.contains("lintai config-schema")
            && stdout.contains("lintai advisory-db export-bundled"),
        "help output missing expected commands: {stdout}"
    );
}

#[test]
fn subcommand_help_flag_prints_specific_usage() {
    let output = run_root_cargo(&["run", "--", "inventory-os", "--help"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "inventory-os --help failed:\n{}",
        stderr_string(&output)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    assert!(stdout.contains("lintai inventory-os [--scope=user|system|both]"));
    assert!(stdout.contains("--color=auto|always|never"));
    assert!(!stdout.contains("lintai scan [path]"));
}

#[test]
fn help_subcommand_prints_specific_usage() {
    let output = run_root_cargo(&["run", "--", "help", "inventory-os"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "help inventory-os failed:\n{}",
        stderr_string(&output)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    assert!(stdout.contains("lintai inventory-os [--scope=user|system|both]"));
    assert!(stdout.contains("--diff-against FILE"));
    assert!(!stdout.contains("lintai scan [path]"));
}

#[test]
fn scan_color_always_emits_ansi_for_text_output() {
    let output = run_root_cargo(&[
        "run",
        "--quiet",
        "--",
        "scan",
        "./sample-repos/mcp-heavy/repo",
        "--preset=supply-chain",
        "--color=always",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "colorized text scan failed:\n{}",
        stderr_string(&output)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    assert!(stdout.contains("\u{1b}["));
    assert!(stdout.contains("SEC302"));
    assert!(stdout.contains("supply-chain (1)"));
}

#[test]
fn scan_color_always_keeps_json_uncolored() {
    let output = run_root_cargo(&[
        "run",
        "--quiet",
        "--",
        "scan",
        "./sample-repos/mcp-heavy/repo",
        "--preset=supply-chain",
        "--format=json",
        "--color=always",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "json scan with --color failed:\n{}",
        stderr_string(&output)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    assert!(!stdout.contains("\u{1b}["));
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("scan output JSON");
    assert_eq!(value["findings"].as_array().unwrap().len(), 1);
    assert_eq!(value["findings"][0]["rule_code"], "SEC302");
}

#[test]
fn scan_explicit_presets_ignore_repo_local_preset_activation() {
    let repo = temp_path("lintai-cli-scan-preset-bypass", "");
    fs::create_dir_all(&repo).unwrap();
    write_repo_file(&repo, "lintai.toml", "[presets]\nenable = [\"advisory\"]\n");
    write_repo_file(
        &repo,
        "package-lock.json",
        r#"{
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/left-pad": { "version": "1.1.3" }
          }
        }"#,
    );
    let snapshot = advisory_snapshot_fixture_path();
    let snapshot_arg = snapshot.to_string_lossy().into_owned();
    let envs = [("LINTAI_ADVISORY_SNAPSHOT", snapshot_arg.as_str())];

    let manifest_path = repo_root().join("Cargo.toml");
    let manifest_arg = manifest_path.to_string_lossy().into_owned();

    let default_output = run_cargo(
        repo.clone(),
        &[
            "run",
            "--quiet",
            "--manifest-path",
            &manifest_arg,
            "--",
            "scan",
            ".",
            "--format",
            "json",
        ],
        &envs,
    );
    assert_eq!(
        default_output.status.code(),
        Some(0),
        "default scan should honor repo-local preset activation:\n{}",
        stderr_string(&default_output)
    );
    let default_json: serde_json::Value =
        serde_json::from_slice(&default_output.stdout).expect("default scan output JSON");
    assert_eq!(default_json["findings"].as_array().unwrap().len(), 1);
    assert_eq!(default_json["findings"][0]["rule_code"], "SEC756");

    let explicit_output = run_cargo(
        repo,
        &[
            "run",
            "--quiet",
            "--manifest-path",
            &manifest_arg,
            "--",
            "scan",
            ".",
            "--preset",
            " base ",
            "--format",
            "json",
        ],
        &envs,
    );
    assert_eq!(
        explicit_output.status.code(),
        Some(0),
        "explicit scan presets should bypass repo-local preset activation:\n{}",
        stderr_string(&explicit_output)
    );
    let explicit_json: serde_json::Value =
        serde_json::from_slice(&explicit_output.stdout).expect("explicit scan output JSON");
    assert!(
        explicit_json["findings"].as_array().unwrap().is_empty(),
        "base preset should not inherit repo-local advisory activation: {}",
        String::from_utf8_lossy(&explicit_output.stdout)
    );
}

#[test]
fn readme_root_cargo_config_schema_command_is_truthful() {
    let output = run_root_cargo(&["run", "--", "config-schema"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "README cargo config-schema command failed:\n{}",
        stderr_string(&output)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("config-schema output should be valid JSON");
    assert_eq!(
        value["$schema"], "https://json-schema.org/draft/2020-12/schema",
        "config-schema output should remain a draft 2020-12 schema"
    );
}

#[test]
fn advisory_db_export_bundled_command_outputs_snapshot_json() {
    let output = run_root_cargo(&["run", "--", "advisory-db", "export-bundled"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "advisory-db export-bundled command failed:\n{}",
        stderr_string(&output)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("advisory-db export-bundled should be valid JSON");
    assert_eq!(value["ecosystem"], "npm");
    assert!(value["generated_at"].is_string());
    assert!(value["source"].is_string());
    assert!(value["snapshot_revision"].is_string());
}

#[test]
fn advisory_scan_can_use_custom_snapshot_override() {
    let repo = temp_path("lintai-cli-advisory-repo", "");
    fs::create_dir_all(&repo).unwrap();
    write_repo_file(&repo, "lintai.toml", "[presets]\nenable = [\"advisory\"]\n");
    write_repo_file(
        &repo,
        "package-lock.json",
        r#"{
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/left-pad": { "version": "1.1.3" }
          }
        }"#,
    );

    let snapshot = advisory_snapshot_fixture_path();
    let manifest_path = repo_root().join("Cargo.toml");
    let manifest_arg = manifest_path.to_string_lossy().into_owned();
    let snapshot_arg = snapshot.to_string_lossy().into_owned();
    let output = run_cargo(
        repo.clone(),
        &[
            "run",
            "--quiet",
            "--manifest-path",
            &manifest_arg,
            "--",
            "scan",
            ".",
            "--format",
            "json",
        ],
        &[("LINTAI_ADVISORY_SNAPSHOT", &snapshot_arg)],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "custom advisory snapshot scan failed:\n{}",
        stderr_string(&output)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("scan output JSON");
    let findings = value["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["rule_code"], "SEC756");
    assert_eq!(
        findings[0]["metadata"]["snapshot_source"],
        "custom-e2e-snapshot"
    );
    assert_eq!(
        findings[0]["evidence"][1]["message"],
        "advisory `CUSTOM-E2E-1` from snapshot `custom-e2e-1` marks this version as affected"
    );
}

#[test]
fn advisory_db_update_rejects_wrong_ecosystem_snapshot() {
    let input = temp_path("lintai-cli-advisory-invalid-input", ".json");
    let output = temp_path("lintai-cli-advisory-invalid-output", ".json");
    fs::write(
        &input,
        r#"{
          "schema_version": 1,
          "ecosystem": "pypi",
          "generated_at": "2026-04-02T00:00:00Z",
          "source": "bad",
          "snapshot_revision": "bad-1",
          "advisories": []
        }"#,
    )
    .unwrap();

    let input_arg = input.to_string_lossy().into_owned();
    let output_arg = output.to_string_lossy().into_owned();
    let output = run_root_cargo(&[
        "run",
        "--quiet",
        "--",
        "advisory-db",
        "update",
        "--input",
        &input_arg,
        "--output",
        &output_arg,
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr_string(&output);
    assert!(stderr.contains("unsupported ecosystem"));
}

#[test]
fn advisory_db_update_rejects_invalid_semver_bounds() {
    let input = temp_path("lintai-cli-advisory-invalid-bounds-input", ".json");
    let output = temp_path("lintai-cli-advisory-invalid-bounds-output", ".json");
    fs::write(
        &input,
        r#"{
          "schema_version": 1,
          "ecosystem": "npm",
          "generated_at": "2026-04-02T00:00:00Z",
          "source": "bad",
          "snapshot_revision": "bad-1",
          "advisories": [
            {
              "id": "BAD-1",
              "package": "demo",
              "aliases": [],
              "summary": "demo",
              "references": [],
              "ranges": [{"introduced": "not-a-version", "fixed": "1.0.0"}]
            }
          ]
        }"#,
    )
    .unwrap();

    let input_arg = input.to_string_lossy().into_owned();
    let output_arg = output.to_string_lossy().into_owned();
    let output = run_root_cargo(&[
        "run",
        "--quiet",
        "--",
        "advisory-db",
        "update",
        "--input",
        &input_arg,
        "--output",
        &output_arg,
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr_string(&output);
    assert!(stderr.contains("invalid `introduced` semver bound"));
}

#[test]
fn advisory_db_update_rejects_invalid_generated_at_timestamp() {
    let input = temp_path("lintai-cli-advisory-invalid-generated-at-input", ".json");
    let output = temp_path("lintai-cli-advisory-invalid-generated-at-output", ".json");
    fs::write(
        &input,
        r#"{
          "schema_version": 1,
          "ecosystem": "npm",
          "generated_at": "2026-99-99T25:61:61Z",
          "source": "bad",
          "snapshot_revision": "bad-1",
          "advisories": []
        }"#,
    )
    .unwrap();

    let input_arg = input.to_string_lossy().into_owned();
    let output_arg = output.to_string_lossy().into_owned();
    let output = run_root_cargo(&[
        "run",
        "--quiet",
        "--",
        "advisory-db",
        "update",
        "--input",
        &input_arg,
        "--output",
        &output_arg,
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr_string(&output);
    assert!(stderr.contains("RFC3339 `generated_at` timestamp"));
}

#[test]
fn advisory_scan_invalid_custom_snapshot_exits_with_execution_error() {
    let repo = temp_path("lintai-cli-advisory-invalid-repo", "");
    fs::create_dir_all(&repo).unwrap();
    write_repo_file(&repo, "lintai.toml", "[presets]\nenable = [\"advisory\"]\n");
    write_repo_file(
        &repo,
        "package-lock.json",
        r#"{
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/lodash": { "version": "4.17.20" }
          }
        }"#,
    );

    let bad_snapshot = temp_path("lintai-cli-advisory-bad-snapshot", ".json");
    fs::write(&bad_snapshot, "{ definitely not json").unwrap();
    let manifest_path = repo_root().join("Cargo.toml");
    let manifest_arg = manifest_path.to_string_lossy().into_owned();
    let snapshot_arg = bad_snapshot.to_string_lossy().into_owned();
    let output = run_cargo(
        repo,
        &[
            "run",
            "--quiet",
            "--manifest-path",
            &manifest_arg,
            "--",
            "scan",
            ".",
            "--format",
            "json",
        ],
        &[("LINTAI_ADVISORY_SNAPSHOT", &snapshot_arg)],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid custom advisory snapshot should fail scan:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr_string(&output)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("scan output JSON");
    assert_eq!(value["findings"].as_array().unwrap().len(), 0);
    assert_eq!(value["runtime_errors"].as_array().unwrap().len(), 1);
}

#[test]
fn advisory_scan_invalid_tracked_package_version_exits_with_runtime_error() {
    let repo = temp_path("lintai-cli-advisory-invalid-version-repo", "");
    fs::create_dir_all(&repo).unwrap();
    write_repo_file(&repo, "lintai.toml", "[presets]\nenable = [\"advisory\"]\n");
    write_repo_file(
        &repo,
        "package-lock.json",
        r#"{
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/lodash": { "version": "workspace:*" }
          }
        }"#,
    );

    let manifest_path = repo_root().join("Cargo.toml");
    let manifest_arg = manifest_path.to_string_lossy().into_owned();
    let output = run_cargo(
        repo,
        &[
            "run",
            "--quiet",
            "--manifest-path",
            &manifest_arg,
            "--",
            "scan",
            ".",
            "--format",
            "json",
        ],
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid advisory-tracked package version should fail scan:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr_string(&output)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("scan output JSON");
    assert_eq!(value["findings"].as_array().unwrap().len(), 0);
    assert_eq!(value["runtime_errors"].as_array().unwrap().len(), 1);
    assert!(
        value["runtime_errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("not valid semver")
    );
}

#[test]
fn advisory_scan_missing_tracked_package_version_exits_with_runtime_error() {
    let repo = temp_path("lintai-cli-advisory-missing-version-repo", "");
    fs::create_dir_all(&repo).unwrap();
    write_repo_file(&repo, "lintai.toml", "[presets]\nenable = [\"advisory\"]\n");
    write_repo_file(
        &repo,
        "package-lock.json",
        r#"{
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/lodash": { "version": "" }
          }
        }"#,
    );

    let manifest_path = repo_root().join("Cargo.toml");
    let manifest_arg = manifest_path.to_string_lossy().into_owned();
    let output = run_cargo(
        repo,
        &[
            "run",
            "--quiet",
            "--manifest-path",
            &manifest_arg,
            "--",
            "scan",
            ".",
            "--format",
            "json",
        ],
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "missing advisory-tracked package version should fail scan:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr_string(&output)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("scan output JSON");
    assert_eq!(value["findings"].as_array().unwrap().len(), 0);
    assert_eq!(value["runtime_errors"].as_array().unwrap().len(), 1);
    assert!(
        value["runtime_errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("missing a valid installed version")
    );
}

#[test]
fn advisory_scan_malformed_pnpm_key_exits_with_runtime_error() {
    let repo = temp_path("lintai-cli-advisory-bad-pnpm-repo", "");
    fs::create_dir_all(&repo).unwrap();
    write_repo_file(&repo, "lintai.toml", "[presets]\nenable = [\"advisory\"]\n");
    write_repo_file(
        &repo,
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\npackages:\n  lodash@:\n    resolution: {integrity: sha512-demo}\n",
    );

    let manifest_path = repo_root().join("Cargo.toml");
    let manifest_arg = manifest_path.to_string_lossy().into_owned();
    let output = run_cargo(
        repo,
        &[
            "run",
            "--quiet",
            "--manifest-path",
            &manifest_arg,
            "--",
            "scan",
            ".",
            "--format",
            "json",
        ],
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "malformed pnpm advisory-tracked key should fail scan:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr_string(&output)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("scan output JSON");
    assert_eq!(value["findings"].as_array().unwrap().len(), 0);
    assert_eq!(value["runtime_errors"].as_array().unwrap().len(), 1);
    assert!(
        value["runtime_errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("missing a valid installed version")
    );
}
