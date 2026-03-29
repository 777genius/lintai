use std::collections::BTreeSet;
use std::path::Path;

use lintai_api::{Finding, Severity};
use lintai_engine::normalize_path_string;

use crate::known_scan::InventoryRoot;
use crate::policy_os::model::{MachinePolicy, PolicyAction, PolicyMatch, PolicyStats};

pub(crate) fn evaluate_machine_policy(
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
