use std::path::Path;

use lintai_api::Severity;
use lintai_engine::{DiagnosticSeverity, ProviderExecutionPhase, RuntimeErrorKind};

use super::model::ReportEnvelope;
use crate::known_scan::InventoryChangedRoot;

pub(crate) fn format_text(report: &ReportEnvelope<'_>) -> String {
    let mut output = String::new();
    if let Some(policy_stats) = &report.policy_stats {
        output.push_str(&format!(
            "policy matched {} root(s), deny {}, warn {}, inventory roots {}, findings {}\n",
            policy_stats.matched_roots,
            policy_stats.deny_matches,
            policy_stats.warn_matches,
            report.inventory_roots.len(),
            report.findings.len()
        ));
        if let Some(inventory_stats) = &report.inventory_stats {
            output.push_str(&format!(
                "inventory counters: user={} system={} lintable={} discovered_only={} high={} medium={} low={} scanned={} non_target={} excluded={} binary={} unreadable={} unrecognized={}\n",
                inventory_stats.user_roots,
                inventory_stats.system_roots,
                inventory_stats.lintable_roots,
                inventory_stats.discovered_only_roots,
                inventory_stats.high_risk_roots,
                inventory_stats.medium_risk_roots,
                inventory_stats.low_risk_roots,
                inventory_stats.supported_artifacts_scanned,
                inventory_stats.non_target_files_in_lintable_roots,
                inventory_stats.excluded_files,
                inventory_stats.binary_files,
                inventory_stats.unreadable_files,
                inventory_stats.unrecognized_files,
            ));
        }
    } else if let Some(inventory_diff) = &report.inventory_diff {
        let inventory_stats = report
            .inventory_stats
            .as_ref()
            .expect("inventory_diff requires inventory_stats");
        output.push_str(&format!(
            "inventory diff discovered {} root(s), new {} root(s), removed {} root(s), changed {} root(s), new lintable {} root(s), risk increased {} root(s), new findings {}\n",
            report.inventory_roots.len(),
            inventory_diff.new_roots.len(),
            inventory_diff.removed_roots.len(),
            inventory_diff.changed_roots.len(),
            inventory_diff.new_lintable_roots.len(),
            inventory_diff.risk_increased_roots.len(),
            inventory_diff.new_findings.len()
        ));
        output.push_str(&format!(
            "inventory counters: user={} system={} lintable={} discovered_only={} high={} medium={} low={} scanned={} non_target={} excluded={} binary={} unreadable={} unrecognized={}\n",
            inventory_stats.user_roots,
            inventory_stats.system_roots,
            inventory_stats.lintable_roots,
            inventory_stats.discovered_only_roots,
            inventory_stats.high_risk_roots,
            inventory_stats.medium_risk_roots,
            inventory_stats.low_risk_roots,
            inventory_stats.supported_artifacts_scanned,
            inventory_stats.non_target_files_in_lintable_roots,
            inventory_stats.excluded_files,
            inventory_stats.binary_files,
            inventory_stats.unreadable_files,
            inventory_stats.unrecognized_files,
        ));
    } else if let Some(inventory_stats) = &report.inventory_stats {
        output.push_str(&format!(
            "inventory discovered {} root(s), user {} root(s), system {} root(s), lintable {} root(s), discovered-only {} root(s), high risk {} root(s), medium risk {} root(s), low risk {} root(s), scanned {} supported artifact(s), non-target {} file(s), found {} finding(s), {} diagnostic(s), {} runtime error(s)\n",
            report.inventory_roots.len(),
            inventory_stats.user_roots,
            inventory_stats.system_roots,
            inventory_stats.lintable_roots,
            inventory_stats.discovered_only_roots,
            inventory_stats.high_risk_roots,
            inventory_stats.medium_risk_roots,
            inventory_stats.low_risk_roots,
            inventory_stats.supported_artifacts_scanned,
            inventory_stats.non_target_total(),
            report.findings.len(),
            report.diagnostics.len(),
            report.runtime_errors.len()
        ));
        output.push_str(&format!(
            "inventory counters: non_target={} excluded={} binary={} unreadable={} unrecognized={}\n",
            inventory_stats.non_target_files_in_lintable_roots,
            inventory_stats.excluded_files,
            inventory_stats.binary_files,
            inventory_stats.unreadable_files,
            inventory_stats.unrecognized_files,
        ));
    } else if let Some(discovery_stats) = &report.discovery_stats {
        output.push_str(&format!(
            "discovered {} root(s), lintable {} root(s), discovered-only {} root(s), scanned {} supported artifact(s), non-target {} file(s), found {} finding(s), {} diagnostic(s), {} runtime error(s)\n",
            report.discovered_roots.len(),
            discovery_stats.lintable_roots,
            discovery_stats.discovered_only_roots,
            discovery_stats.supported_artifacts_scanned,
            discovery_stats.non_target_total(),
            report.findings.len(),
            report.diagnostics.len(),
            report.runtime_errors.len()
        ));
        output.push_str(&format!(
            "discovery counters: non_target={} excluded={} binary={} unreadable={} unrecognized={}\n",
            discovery_stats.non_target_files_in_lintable_roots,
            discovery_stats.excluded_files,
            discovery_stats.binary_files,
            discovery_stats.unreadable_files,
            discovery_stats.unrecognized_files,
        ));
    } else {
        output.push_str(&format!(
            "scanned {} file(s), skipped {} file(s), found {} finding(s), {} diagnostic(s), {} runtime error(s)\n",
            report.stats.scanned_files,
            report.stats.skipped_files,
            report.findings.len(),
            report.diagnostics.len(),
            report.runtime_errors.len()
        ));
    }

    for root in &report.discovered_roots {
        output.push_str(&format!(
            "root [{} {}] {} {} {}\n",
            root.scope, root.mode, root.client, root.surface, root.path
        ));
    }

    for root in &report.inventory_roots {
        output.push_str(&format!(
            "inventory-root [{} {} {}] {} {} {}\n",
            root.provenance.origin_scope,
            root.risk_level,
            root.mode,
            root.client,
            root.surface,
            root.path
        ));
    }

    for policy_match in &report.policy_matches {
        output.push_str(&format!(
            "policy [{}] {} {} {} {} {}\n",
            policy_match.severity,
            policy_match.policy_id,
            policy_match.client,
            policy_match.surface,
            policy_match.path,
            policy_match.message
        ));
        for rule_code in &policy_match.matched_findings {
            output.push_str(&format!("  matched: {rule_code}\n"));
        }
    }

    if let Some(inventory_diff) = &report.inventory_diff {
        for root in &inventory_diff.new_roots {
            output.push_str(&format!(
                "new-root [{} {}] {} {} {}\n",
                root.risk_level, root.mode, root.client, root.surface, root.path
            ));
        }
        for root in &inventory_diff.removed_roots {
            output.push_str(&format!(
                "removed-root [{} {}] {} {} {}\n",
                root.risk_level, root.mode, root.client, root.surface, root.path
            ));
        }
        for root in &inventory_diff.changed_roots {
            output.push_str(&format!(
                "changed-root [{}] {} {} {}\n",
                changed_root_fragment(root),
                root.client,
                root.surface,
                root.path
            ));
        }
        for root in &inventory_diff.new_lintable_roots {
            output.push_str(&format!(
                "new-lintable-root [{}] {} {} {}\n",
                root.risk_level, root.client, root.surface, root.path
            ));
        }
        for root in &inventory_diff.risk_increased_roots {
            output.push_str(&format!(
                "risk-increased-root [{}->{}] {} {} {}\n",
                root.old_risk_level, root.new_risk_level, root.client, root.surface, root.path
            ));
        }
        for finding in &inventory_diff.new_findings {
            output.push_str(&format!(
                "new-finding {} {} {}\n",
                finding.rule_code,
                client_for_inventory_finding(
                    &report.inventory_roots,
                    finding.location.normalized_path.as_str()
                ),
                finding.location.normalized_path
            ));
        }
    }

    for finding in report.findings {
        output.push_str(&format!(
            "{} [{}] {}:{}-{} {}\n",
            finding.rule_code,
            severity_label(finding.severity),
            finding.location.normalized_path,
            finding.location.span.start_byte,
            finding.location.span.end_byte,
            finding.message
        ));
        for suggestion in &finding.suggestions {
            output.push_str(&format!("  suggest: {}\n", suggestion.message));
        }
    }

    for diagnostic in report.diagnostics {
        output.push_str(&format!(
            "diagnostic [{}] {} {}\n",
            diagnostic_label(diagnostic.severity),
            diagnostic.normalized_path,
            diagnostic.message
        ));
    }

    for error in report.runtime_errors {
        let provider_fragment = error
            .provider_id
            .as_deref()
            .map(|provider_id| format!(" provider={provider_id}"))
            .unwrap_or_default();
        let phase_fragment = error
            .phase
            .map(|phase| format!(" phase={}", provider_execution_phase_label(phase)))
            .unwrap_or_default();
        output.push_str(&format!(
            "error [{}] {}{}{} {}\n",
            error_kind_label(error.kind),
            error.normalized_path,
            provider_fragment,
            phase_fragment,
            error.message
        ));
    }

    output
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Deny => "deny",
        Severity::Warn => "warn",
        Severity::Allow => "allow",
    }
}

fn diagnostic_label(kind: DiagnosticSeverity) -> &'static str {
    match kind {
        DiagnosticSeverity::Info => "info",
        DiagnosticSeverity::Warn => "warn",
    }
}

fn error_kind_label(kind: RuntimeErrorKind) -> &'static str {
    match kind {
        RuntimeErrorKind::Read => "read",
        RuntimeErrorKind::InvalidUtf8 => "invalid_utf8",
        RuntimeErrorKind::Parse => "parse",
        RuntimeErrorKind::ProviderExecution => "provider_execution",
        RuntimeErrorKind::ProviderTimeout => "provider_timeout",
    }
}

fn provider_execution_phase_label(phase: ProviderExecutionPhase) -> &'static str {
    match phase {
        ProviderExecutionPhase::File => "file",
        ProviderExecutionPhase::Workspace => "workspace",
    }
}

fn changed_root_fragment(root: &InventoryChangedRoot) -> String {
    let mut parts = Vec::new();
    if root.old_risk_level != root.new_risk_level {
        parts.push(format!(
            "risk {}->{}",
            root.old_risk_level, root.new_risk_level
        ));
    }
    if root.old_mode != root.new_mode {
        parts.push(format!("mode {}->{}", root.old_mode, root.new_mode));
    }
    if root.old_path_type != root.new_path_type {
        parts.push(format!(
            "path_type {}->{}",
            root.old_path_type, root.new_path_type
        ));
    }
    if root.old_mtime_epoch_s != root.new_mtime_epoch_s {
        parts.push(format!(
            "mtime {}->{}",
            option_u64_label(root.old_mtime_epoch_s),
            option_u64_label(root.new_mtime_epoch_s)
        ));
    }
    parts.join(" ")
}

fn option_u64_label(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned())
}

fn client_for_inventory_finding<'a>(
    roots: &'a [crate::known_scan::InventoryRoot],
    normalized_path: &str,
) -> &'a str {
    let finding_path = Path::new(normalized_path);
    roots
        .iter()
        .find(|root| match root.provenance.path_type.as_str() {
            "directory" => {
                let root_path = Path::new(&root.path);
                finding_path == root_path || finding_path.starts_with(root_path)
            }
            _ => root.path == normalized_path,
        })
        .map(|root| root.client.as_str())
        .unwrap_or("unknown")
}
