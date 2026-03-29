use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should be discoverable from lintai-cli tests")
}

fn run_root_cargo(args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .current_dir(repo_root())
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn cargo {:?}: {error}", args))
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
        stdout.contains("lintai scan [path]") && stdout.contains("lintai config-schema"),
        "help output missing expected commands: {stdout}"
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
        value["$schema"],
        "https://json-schema.org/draft/2020-12/schema",
        "config-schema output should remain a draft 2020-12 schema"
    );
}
