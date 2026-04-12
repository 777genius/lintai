use lintai_api::Location;
use lintai_engine::ProviderExecutionPhase;

use crate::known_scan::InventoryChangedRoot;

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
        parts.push(format!(
            "mode {}->{}",
            inventory_mode_label(&root.old_mode),
            inventory_mode_label(&root.new_mode)
        ));
    }
    if root.old_path_type != root.new_path_type {
        parts.push(format!(
            "path type {}->{}",
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

pub(super) fn location_label(location: &Location) -> String {
    if let Some(start) = &location.start {
        return format!(
            "{}:{}:{}",
            location.normalized_path, start.line, start.column
        );
    }

    format!(
        "{}:{}-{}",
        location.normalized_path, location.span.start_byte, location.span.end_byte
    )
}

pub(super) fn location_detail_label(location: &Location) -> String {
    if let Some(start) = &location.start {
        return format!("{}:{}", start.line, start.column);
    }

    format!("{}-{}", location.span.start_byte, location.span.end_byte)
}

pub(super) fn append_section_gap(output: &mut String) {
    if output.is_empty() {
        return;
    }
    if !output.ends_with('\n') {
        output.push('\n');
    }
    if !output.ends_with("\n\n") {
        output.push('\n');
    }
}

pub(super) fn count_label(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

pub(super) fn diagnostic_code_label(code: &str) -> String {
    code.replace('_', "-")
}

fn option_u64_label(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned())
}

fn inventory_mode_label(mode: &str) -> &str {
    match mode {
        "discovered_only" => "discovered-only",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::changed_root_fragment;
    use crate::known_scan::InventoryChangedRoot;
    use lintai_api::{LineColumn, Location, Span};

    #[test]
    fn maps_provider_execution_phase_labels() {
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
        assert!(fragment.contains("mode discovered-only->lintable"));
        assert!(fragment.contains("path type file->directory"));
        assert!(fragment.contains("mtime none->1730"));
        assert!(!fragment.contains("risk"));
    }

    #[test]
    fn location_label_prefers_line_column_when_present() {
        let mut location = Location::new("repo/file.md", Span::new(4, 9));
        location.start = Some(LineColumn::new(3, 7));

        assert_eq!(super::location_label(&location), "repo/file.md:3:7");
    }

    #[test]
    fn location_label_falls_back_to_byte_span() {
        let location = Location::new("repo/file.md", Span::new(4, 9));

        assert_eq!(super::location_label(&location), "repo/file.md:4-9");
    }

    #[test]
    fn location_detail_label_prefers_line_column_when_present() {
        let mut location = Location::new("repo/file.md", Span::new(4, 9));
        location.start = Some(LineColumn::new(3, 7));

        assert_eq!(super::location_detail_label(&location), "3:7");
    }

    #[test]
    fn location_detail_label_falls_back_to_byte_span() {
        let location = Location::new("repo/file.md", Span::new(4, 9));

        assert_eq!(super::location_detail_label(&location), "4-9");
    }

    #[test]
    fn count_label_handles_singular_and_plural() {
        assert_eq!(super::count_label(1, "file", "files"), "1 file");
        assert_eq!(super::count_label(2, "file", "files"), "2 files");
    }

    #[test]
    fn diagnostic_code_label_humanizes_snake_case() {
        assert_eq!(
            super::diagnostic_code_label("parse_recovery"),
            "parse-recovery"
        );
        assert_eq!(super::diagnostic_code_label("yaml"), "yaml");
    }
}
