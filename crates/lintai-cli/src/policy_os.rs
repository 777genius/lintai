use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use lintai_api::{Finding, Severity};
use lintai_engine::normalize_path_string;
use serde::{Deserialize, Serialize};

use crate::known_scan::InventoryRoot;

pub const MACHINE_POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Off,
    Warn,
    Deny,
}

impl PolicyAction {
    fn as_severity(self) -> Option<Severity> {
        match self {
            Self::Off => None,
            Self::Warn => Some(Severity::Warn),
            Self::Deny => Some(Severity::Deny),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PolicyOsArgs {
    pub format_override: Option<lintai_engine::OutputFormat>,
    pub scope: crate::known_scan::InventoryOsScope,
    pub client_filters: BTreeSet<String>,
    pub path_root: Option<PathBuf>,
    pub policy_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachinePolicyFile {
    pub schema_version: u32,
    #[serde(default)]
    pub rules: MachinePolicyRules,
    #[serde(default)]
    pub allow: MachinePolicyAllow,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachinePolicyRules {
    #[serde(default)]
    pub global_shell_wrapper_mcp: Option<PolicyAction>,
    #[serde(default)]
    pub plaintext_auth: Option<PolicyAction>,
    #[serde(default)]
    pub trust_disable: Option<PolicyAction>,
    #[serde(default)]
    pub high_risk_discovered_only: Option<PolicyAction>,
    #[serde(default)]
    pub unapproved_client: Option<PolicyAction>,
    #[serde(default)]
    pub unapproved_base_dir: Option<PolicyAction>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachinePolicyAllow {
    #[serde(default)]
    pub clients: Vec<String>,
    #[serde(default)]
    pub base_dirs: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct MachinePolicy {
    pub rules: EvaluatedPolicyRules,
    pub allow_clients: BTreeSet<String>,
    pub allow_base_dirs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct EvaluatedPolicyRules {
    pub global_shell_wrapper_mcp: PolicyAction,
    pub plaintext_auth: PolicyAction,
    pub trust_disable: PolicyAction,
    pub high_risk_discovered_only: PolicyAction,
    pub unapproved_client: PolicyAction,
    pub unapproved_base_dir: PolicyAction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyMatch {
    pub policy_id: String,
    pub severity: String,
    pub client: String,
    pub surface: String,
    pub path: String,
    pub message: String,
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub matched_findings: Vec<String>,
    pub mode: String,
    pub risk_level: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PolicyStats {
    pub deny_matches: usize,
    pub warn_matches: usize,
    pub matched_roots: usize,
    pub matched_findings: usize,
}

pub fn load_machine_policy(path: &Path) -> Result<MachinePolicy, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("failed to read policy {}: {error}", path.display()))?;
    let parsed: MachinePolicyFile = toml::from_str(&text)
        .map_err(|error| format!("failed to parse policy {}: {error}", path.display()))?;
    if parsed.schema_version != MACHINE_POLICY_SCHEMA_VERSION {
        return Err(format!(
            "unsupported policy schema_version {} in {} (expected {})",
            parsed.schema_version,
            path.display(),
            MACHINE_POLICY_SCHEMA_VERSION
        ));
    }

    let allow_clients = parsed
        .allow
        .clients
        .into_iter()
        .map(|client| client.trim().to_ascii_lowercase())
        .filter(|client| !client.is_empty())
        .collect::<BTreeSet<_>>();
    let allow_base_dirs = parsed
        .allow
        .base_dirs
        .into_iter()
        .map(|path| {
            if !path.is_absolute() {
                return Err(format!(
                    "policy allow.base_dirs must use absolute paths: {}",
                    path.display()
                ));
            }
            let normalized = fs::canonicalize(&path)
                .map(|canonical| normalize_path_string(&canonical))
                .unwrap_or_else(|_| normalize_path_string(&path));
            Ok(normalized)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let rules = EvaluatedPolicyRules {
        global_shell_wrapper_mcp: parsed
            .rules
            .global_shell_wrapper_mcp
            .unwrap_or(PolicyAction::Off),
        plaintext_auth: parsed.rules.plaintext_auth.unwrap_or(PolicyAction::Off),
        trust_disable: parsed.rules.trust_disable.unwrap_or(PolicyAction::Off),
        high_risk_discovered_only: parsed
            .rules
            .high_risk_discovered_only
            .unwrap_or(PolicyAction::Off),
        unapproved_client: parsed.rules.unapproved_client.unwrap_or(PolicyAction::Off),
        unapproved_base_dir: parsed
            .rules
            .unapproved_base_dir
            .unwrap_or(PolicyAction::Off),
    };

    if !matches!(rules.unapproved_client, PolicyAction::Off) && allow_clients.is_empty() {
        return Err("policy rule unapproved_client requires allow.clients".to_owned());
    }
    if !matches!(rules.unapproved_base_dir, PolicyAction::Off) && allow_base_dirs.is_empty() {
        return Err("policy rule unapproved_base_dir requires allow.base_dirs".to_owned());
    }

    Ok(MachinePolicy {
        rules,
        allow_clients,
        allow_base_dirs,
    })
}

pub fn evaluate_machine_policy(
    policy: &MachinePolicy,
    inventory_roots: &[InventoryRoot],
    findings: &[Finding],
) -> (Vec<PolicyMatch>, PolicyStats) {
    let mut matches = Vec::new();

    for root in inventory_roots {
        let root_findings = findings_for_root(root, findings);

        push_root_rule_match(
            &mut matches,
            "unapproved-client",
            policy.rules.unapproved_client,
            root,
            !policy.allow_clients.contains(&root.client),
            "client is not allowlisted",
            Vec::new(),
        );
        push_root_rule_match(
            &mut matches,
            "unapproved-base-dir",
            policy.rules.unapproved_base_dir,
            root,
            !path_allowed(&root.path, &policy.allow_base_dirs),
            "path is outside allow.base_dirs",
            Vec::new(),
        );
        push_root_rule_match(
            &mut matches,
            "high-risk-discovered-only",
            policy.rules.high_risk_discovered_only,
            root,
            root.mode == "discovered_only" && root.risk_level == "high",
            "discovered-only high-risk root",
            Vec::new(),
        );

        push_finding_rule_match(
            &mut matches,
            "global-shell-wrapper-mcp",
            policy.rules.global_shell_wrapper_mcp,
            root,
            &root_findings,
            |code| code == "SEC301",
            "matched shell-wrapper MCP finding",
        );
        push_finding_rule_match(
            &mut matches,
            "plaintext-auth",
            policy.rules.plaintext_auth,
            root,
            &root_findings,
            |code| matches!(code, "SEC305" | "SEC309" | "SEC321" | "SEC323"),
            "matched literal auth or secret-material finding",
        );
        push_finding_rule_match(
            &mut matches,
            "trust-disable",
            policy.rules.trust_disable,
            root,
            &root_findings,
            |code| matches!(code, "SEC302" | "SEC304" | "SEC319"),
            "matched insecure transport or trust-disable finding",
        );
    }

    sort_policy_matches(&mut matches);
    let stats = policy_stats(&matches);
    (matches, stats)
}

fn findings_for_root<'a>(root: &InventoryRoot, findings: &'a [Finding]) -> Vec<&'a Finding> {
    let root_path = Path::new(&root.path);
    findings
        .iter()
        .filter(|finding| {
            let finding_path = Path::new(&finding.location.normalized_path);
            match root.provenance.path_type.as_str() {
                "directory" => finding_path == root_path || finding_path.starts_with(root_path),
                _ => normalize_path_string(finding_path) == root.path,
            }
        })
        .collect()
}

fn path_allowed(path: &str, allowed_dirs: &[String]) -> bool {
    let path = Path::new(path);
    allowed_dirs.iter().any(|base_dir| {
        let base_dir = Path::new(base_dir);
        path == base_dir || path.starts_with(base_dir)
    })
}

fn push_root_rule_match(
    matches: &mut Vec<PolicyMatch>,
    policy_id: &str,
    action: PolicyAction,
    root: &InventoryRoot,
    predicate: bool,
    message: &str,
    matched_findings: Vec<String>,
) {
    let Some(severity) = action.as_severity() else {
        return;
    };
    if !predicate {
        return;
    }
    matches.push(PolicyMatch {
        policy_id: policy_id.to_owned(),
        severity: severity_label(severity).to_owned(),
        client: root.client.clone(),
        surface: root.surface.clone(),
        path: root.path.clone(),
        message: message.to_owned(),
        evidence: vec![
            format!("origin_scope={}", root.provenance.origin_scope),
            format!("mode={}", root.mode),
            format!("risk_level={}", root.risk_level),
        ],
        matched_findings,
        mode: root.mode.clone(),
        risk_level: root.risk_level.clone(),
    });
}

fn push_finding_rule_match(
    matches: &mut Vec<PolicyMatch>,
    policy_id: &str,
    action: PolicyAction,
    root: &InventoryRoot,
    findings: &[&Finding],
    predicate: impl Fn(&str) -> bool,
    message: &str,
) {
    let Some(severity) = action.as_severity() else {
        return;
    };
    let matched_findings = findings
        .iter()
        .filter(|finding| predicate(&finding.rule_code))
        .map(|finding| finding.rule_code.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if matched_findings.is_empty() {
        return;
    }
    matches.push(PolicyMatch {
        policy_id: policy_id.to_owned(),
        severity: severity_label(severity).to_owned(),
        client: root.client.clone(),
        surface: root.surface.clone(),
        path: root.path.clone(),
        message: message.to_owned(),
        evidence: matched_findings
            .iter()
            .map(|rule_code| format!("matched finding {rule_code}"))
            .collect(),
        matched_findings,
        mode: root.mode.clone(),
        risk_level: root.risk_level.clone(),
    });
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Deny => "deny",
        Severity::Warn => "warn",
        Severity::Allow => "allow",
    }
}

fn sort_policy_matches(matches: &mut [PolicyMatch]) {
    matches.sort_by(|left, right| {
        (
            left.path.as_str(),
            left.policy_id.as_str(),
            left.client.as_str(),
            left.surface.as_str(),
        )
            .cmp(&(
                right.path.as_str(),
                right.policy_id.as_str(),
                right.client.as_str(),
                right.surface.as_str(),
            ))
    });
}

fn policy_stats(matches: &[PolicyMatch]) -> PolicyStats {
    let mut stats = PolicyStats::default();
    let mut matched_roots = BTreeSet::new();
    let mut matched_findings = BTreeSet::new();

    for policy_match in matches {
        match policy_match.severity.as_str() {
            "deny" => stats.deny_matches += 1,
            "warn" => stats.warn_matches += 1,
            _ => {}
        }
        matched_roots.insert(format!(
            "{}|{}|{}",
            policy_match.client, policy_match.surface, policy_match.path
        ));
        for rule_code in &policy_match.matched_findings {
            matched_findings.insert(format!(
                "{}|{}|{}|{}",
                policy_match.client, policy_match.surface, policy_match.path, rule_code
            ));
        }
    }

    stats.matched_roots = matched_roots.len();
    stats.matched_findings = matched_findings.len();
    stats
}

#[cfg(test)]
mod tests {
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
}
