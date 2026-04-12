#[path = "text/common.rs"]
mod common;
#[path = "text/discovery.rs"]
mod discovery;
#[path = "text/inventory.rs"]
mod inventory;
#[path = "text/policy.rs"]
mod policy;
#[path = "text/scan.rs"]
mod scan;
#[path = "text/style.rs"]
mod style;

use super::model::ReportEnvelope;

pub(crate) use style::{ColorMode, ResolvedTextStyle, TextColorEnvironment, TextRenderOptions};

#[cfg(test)]
pub(crate) fn format_text(report: &ReportEnvelope<'_>) -> String {
    format_text_with_style(report, ResolvedTextStyle::plain_for_tests())
}

pub(crate) fn format_text_with_style(
    report: &ReportEnvelope<'_>,
    style: ResolvedTextStyle,
) -> String {
    let mut output = String::new();

    if report.policy_stats.is_some() || !report.policy_matches.is_empty() {
        policy::append_policy_sections(&mut output, report, style);
    } else if report.inventory_diff.is_some() || report.inventory_stats.is_some() {
        inventory::append_inventory_summary(&mut output, report, style);
    } else if report.discovery_stats.is_some() {
        discovery::append_discovery_summary(&mut output, report, style);
    } else {
        scan::append_default_summary(&mut output, report, style);
    }

    discovery::append_discovered_roots(&mut output, report, style);
    inventory::append_inventory_sections(&mut output, report, style);
    if let Some(inventory_diff) = &report.inventory_diff {
        if !inventory_diff.new_findings.is_empty() {
            common::append_section_gap(&mut output);
            output.push_str(
                &style.section_heading("new findings", inventory_diff.new_findings.len()),
            );
            output.push_str("\n\n");
        }
        scan::append_finding_sections(&mut output, &inventory_diff.new_findings, style);
        scan::append_diagnostics_section(&mut output, report.diagnostics, style);
        scan::append_runtime_errors_section(&mut output, report.runtime_errors, style);
    } else {
        scan::append_scan_results(&mut output, report, style);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::format_text_with_style;
    use crate::known_scan::{InventoryDiff, InventoryStats};
    use crate::output::model::{ReportEnvelope, ReportStats, ToolMetadata};
    use lintai_api::{Finding, Location, RuleMetadata, RuleTier, Severity, Span};

    #[test]
    fn inventory_diff_renders_explicit_new_findings_section() {
        let finding = Finding::new(
            &RuleMetadata::new(
                "SEC302",
                "demo",
                lintai_api::Category::Hardening,
                Severity::Warn,
                lintai_api::Confidence::High,
                RuleTier::Stable,
            ),
            Location::new("repo/mcp.json", Span::new(0, 4)),
            "demo finding",
        );
        let report = ReportEnvelope {
            schema_version: 1,
            tool: ToolMetadata { name: "lintai" },
            config_source: None,
            project_root: None,
            discovered_roots: Vec::new(),
            discovery_stats: None,
            inventory_roots: Vec::new(),
            inventory_stats: Some(InventoryStats::default()),
            inventory_diff: Some(InventoryDiff {
                new_roots: Vec::new(),
                removed_roots: Vec::new(),
                changed_roots: Vec::new(),
                new_lintable_roots: Vec::new(),
                risk_increased_roots: Vec::new(),
                new_findings: vec![finding],
            }),
            policy_matches: Vec::new(),
            policy_stats: None,
            stats: ReportStats {
                scanned_files: 1,
                skipped_files: 0,
            },
            findings: &[],
            diagnostics: &[],
            runtime_errors: &[],
        };

        let text =
            format_text_with_style(&report, crate::output::ResolvedTextStyle::plain_for_tests());
        assert!(text.contains("new findings (1)"));
        assert!(text.contains("supply-chain (1)"));
    }
}
