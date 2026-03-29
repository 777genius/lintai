use std::path::Path;

use lintai_api::Severity;
use lintai_engine::{DiagnosticSeverity, ProviderExecutionPhase, RuntimeErrorKind};

use crate::known_scan::{InventoryChangedRoot, InventoryRoot};

pub(super) fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Deny => "deny",
        Severity::Warn => "warn",
        Severity::Allow => "allow",
    }
}

pub(super) fn diagnostic_label(kind: DiagnosticSeverity) -> &'static str {
    match kind {
        DiagnosticSeverity::Info => "info",
        DiagnosticSeverity::Warn => "warn",
    }
}

pub(super) fn error_kind_label(kind: RuntimeErrorKind) -> &'static str {
    match kind {
        RuntimeErrorKind::Read => "read",
        RuntimeErrorKind::InvalidUtf8 => "invalid_utf8",
        RuntimeErrorKind::Parse => "parse",
        RuntimeErrorKind::ProviderExecution => "provider_execution",
        RuntimeErrorKind::ProviderTimeout => "provider_timeout",
    }
}

pub(super) fn provider_execution_phase_label(phase: ProviderExecutionPhase) -> &'static str {
    match phase {
        ProviderExecutionPhase::File => "file",
        ProviderExecutionPhase::Workspace => "workspace",
    }
}

pub(super) fn changed_root_fragment(root: &InventoryChangedRoot) -> String {
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

pub(super) fn client_for_inventory_finding<'a>(
    roots: &'a [InventoryRoot],
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

fn option_u64_label(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned())
}
