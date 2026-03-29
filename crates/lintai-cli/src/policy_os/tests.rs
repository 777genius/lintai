use super::{
    evaluate_machine_policy, load_machine_policy, PolicyAction, MACHINE_POLICY_SCHEMA_VERSION,
};
use crate::known_scan::{InventoryProvenance, InventoryRoot};
use lintai_api::Severity;
use std::fs;
use std::path::PathBuf;
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

#[test]
fn policy_loader_rejects_relative_allow_base_dir() {
    let temp_dir = unique_temp_dir("lintai-policy-os-relative");
    let policy = temp_dir.join("policy.toml");
    fs::write(
        &policy,
        r#"
schema_version = 1
[rules]
unapproved_base_dir = "deny"
[allow]
base_dirs = ["relative/path"]
"#,
    )
    .unwrap();

    let error = load_machine_policy(&policy).unwrap_err();
    assert!(error.contains("allow.base_dirs"));
}

#[test]
fn policy_loader_requires_allowlist_for_allowlist_rules() {
    let temp_dir = unique_temp_dir("lintai-policy-os-missing-allow");
    let policy = temp_dir.join("policy.toml");
    fs::write(
        &policy,
        r#"
schema_version = 1
[rules]
unapproved_client = "deny"
"#,
    )
    .unwrap();

    let error = load_machine_policy(&policy).unwrap_err();
    assert!(error.contains("allow.clients"));
}

#[test]
fn evaluate_machine_policy_emits_root_and_finding_based_matches() {
    let temp_dir = unique_temp_dir("lintai-policy-os-evaluate");
    let policy = temp_dir.join("policy.toml");
    fs::write(
        &policy,
        format!(
            r#"
schema_version = {MACHINE_POLICY_SCHEMA_VERSION}
[rules]
global_shell_wrapper_mcp = "deny"
unapproved_client = "warn"
[allow]
clients = ["cursor"]
"#
        ),
    )
    .unwrap();
    let policy = load_machine_policy(&policy).unwrap();
    let root = InventoryRoot {
        client: "windsurf".to_owned(),
        surface: "mcp-config".to_owned(),
        path: "/tmp/.codeium/windsurf/mcp_config.json".to_owned(),
        mode: "lintable".to_owned(),
        risk_level: "high".to_owned(),
        provenance: InventoryProvenance {
            origin_scope: "user".to_owned(),
            path_type: "file".to_owned(),
            target_path: None,
            owner: None,
            mtime_epoch_s: None,
        },
    };
    let finding = lintai_api::Finding::new(
        &lintai_api::RuleMetadata::new(
            "SEC301",
            "demo",
            lintai_api::Category::Security,
            lintai_api::Severity::Warn,
            lintai_api::Confidence::High,
            lintai_api::RuleTier::Stable,
        ),
        lintai_api::Location::new(
            "/tmp/.codeium/windsurf/mcp_config.json",
            lintai_api::Span::new(0, 7),
        ),
        "demo finding",
    );

    let (matches, stats) = evaluate_machine_policy(&policy, &[root], &[finding]);
    assert_eq!(matches.len(), 2);
    assert!(matches.iter().any(|policy_match| {
        policy_match.policy_id == "global-shell-wrapper-mcp"
            && policy_match.severity == "deny"
            && policy_match.matched_findings == vec!["SEC301"]
    }));
    assert!(matches.iter().any(|policy_match| {
        policy_match.policy_id == "unapproved-client" && policy_match.severity == "warn"
    }));
    assert_eq!(stats.deny_matches, 1);
    assert_eq!(stats.warn_matches, 1);
    assert_eq!(stats.matched_roots, 1);
    assert_eq!(stats.matched_findings, 1);
}

#[test]
fn policy_action_warn_and_deny_convert_to_severity() {
    assert_eq!(PolicyAction::Warn.as_severity(), Some(Severity::Warn));
    assert_eq!(PolicyAction::Deny.as_severity(), Some(Severity::Deny));
    assert_eq!(PolicyAction::Off.as_severity(), None);
}
