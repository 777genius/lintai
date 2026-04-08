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

#[cfg(test)]
mod tests {
    use crate::known_scan::{InventoryChangedRoot, InventoryRoot};
    use super::changed_root_fragment;

    #[test]
    fn maps_severity_labels() {
        assert_eq!(super::severity_label(lintai_api::Severity::Deny), "deny");
        assert_eq!(super::severity_label(lintai_api::Severity::Warn), "warn");
        assert_eq!(super::severity_label(lintai_api::Severity::Allow), "allow");
    }

    #[test]
    fn maps_diagnostic_and_runtime_error_labels() {
        assert_eq!(super::diagnostic_label(lintai_engine::DiagnosticSeverity::Info), "info");
        assert_eq!(
            super::diagnostic_label(lintai_engine::DiagnosticSeverity::Warn),
            "warn"
        );
        assert_eq!(
            super::error_kind_label(lintai_engine::RuntimeErrorKind::Read),
            "read"
        );
        assert_eq!(
            super::error_kind_label(lintai_engine::RuntimeErrorKind::InvalidUtf8),
            "invalid_utf8"
        );
        assert_eq!(
            super::error_kind_label(lintai_engine::RuntimeErrorKind::Parse),
            "parse"
        );
        assert_eq!(
            super::error_kind_label(lintai_engine::RuntimeErrorKind::ProviderExecution),
            "provider_execution"
        );
        assert_eq!(
            super::error_kind_label(lintai_engine::RuntimeErrorKind::ProviderTimeout),
            "provider_timeout"
        );
        assert_eq!(
            super::provider_execution_phase_label(lintai_engine::ProviderExecutionPhase::File),
            "file"
        );
        assert_eq!(
            super::provider_execution_phase_label(lintai_engine::ProviderExecutionPhase::Workspace),
            "workspace"
        );
    }

    #[test]
    fn changed_root_fragment_includes_only_changed_fields() {
        let changed = InventoryChangedRoot {
            client: "client".into(),
            surface: "surface".into(),
            path: "/tmp".into(),
            old_mode: "discovered_only".into(),
            new_mode: "lintable".into(),
            old_risk_level: "medium".into(),
            new_risk_level: "medium".into(),
            old_path_type: "file".into(),
            new_path_type: "directory".into(),
            old_mtime_epoch_s: None,
            new_mtime_epoch_s: Some(1730),
        };

        let fragment = changed_root_fragment(&changed);
        assert!(fragment.contains("mode discovered_only->lintable"));
        assert!(fragment.contains("path_type file->directory"));
        assert!(fragment.contains("mtime none->1730"));
        assert!(!fragment.contains("risk"));
    }

    #[test]
    fn client_for_inventory_finding_matches_directory_scope() {
        let root = InventoryRoot {
            client: "client".into(),
            surface: "surface".into(),
            path: "/tmp/project".into(),
            mode: "lintable".into(),
            risk_level: "low".into(),
            provenance: crate::known_scan::InventoryProvenance {
                origin_scope: "project".into(),
                path_type: "directory".into(),
                target_path: None,
                owner: None,
                mtime_epoch_s: None,
            },
        };
        let file = InventoryRoot {
            client: "other".into(),
            surface: "surface".into(),
            path: "/tmp/other/README.md".into(),
            mode: "lintable".into(),
            risk_level: "low".into(),
            provenance: crate::known_scan::InventoryProvenance {
                origin_scope: "project".into(),
                path_type: "file".into(),
                target_path: None,
                owner: None,
                mtime_epoch_s: None,
            },
        };

        let roots = vec![root, file];
        assert_eq!(super::client_for_inventory_finding(&roots, "/tmp/project"), "client");
        assert_eq!(
            super::client_for_inventory_finding(&roots, "/tmp/project/src/lib.rs"),
            "client"
        );
        assert_eq!(
            super::client_for_inventory_finding(&roots, "/tmp/other/README.md"),
            "other"
        );
        assert_eq!(super::client_for_inventory_finding(&roots, "/tmp/other"), "unknown");
    }
}
