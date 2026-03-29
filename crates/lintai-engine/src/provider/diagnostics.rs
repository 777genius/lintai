use crate::{DiagnosticSeverity, ScanDiagnostic};

pub(super) fn provider_diagnostic(normalized_path: &str, message: String) -> ScanDiagnostic {
    ScanDiagnostic {
        normalized_path: normalized_path.to_owned(),
        severity: DiagnosticSeverity::Warn,
        code: Some("provider_contract".to_owned()),
        message,
    }
}
