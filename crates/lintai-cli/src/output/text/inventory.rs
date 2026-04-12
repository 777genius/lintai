use crate::output::model::ReportEnvelope;

use super::common::{append_section_gap, changed_root_fragment, count_label};
use super::scan::append_lane_summary;
use super::style::ResolvedTextStyle;

pub(super) fn append_inventory_summary(
    output: &mut String,
    report: &ReportEnvelope<'_>,
    style: ResolvedTextStyle,
) -> bool {
    if let Some(inventory_diff) = &report.inventory_diff {
        let inventory_stats = report
            .inventory_stats
            .as_ref()
            .expect("inventory_diff requires inventory_stats");
        output.push_str(&format!(
            "inventory diff discovered {}, {}, {}, {}, {}, {}, {}\n",
            count_label(report.inventory_roots.len(), "root", "roots"),
            count_label(inventory_diff.new_roots.len(), "new root", "new roots"),
            count_label(
                inventory_diff.removed_roots.len(),
                "removed root",
                "removed roots",
            ),
            count_label(
                inventory_diff.changed_roots.len(),
                "changed root",
                "changed roots",
            ),
            count_label(
                inventory_diff.new_lintable_roots.len(),
                "new lintable root",
                "new lintable roots",
            ),
            count_label(
                inventory_diff.risk_increased_roots.len(),
                "root with increased risk",
                "roots with increased risk",
            ),
            count_label(
                inventory_diff.new_findings.len(),
                "new finding",
                "new findings",
            ),
        ));
        output.push_str(&format!(
            "inventory counters: user={}, system={}, lintable={}, discovered-only={}, high={}, medium={}, low={}, scanned={}, non-target={}, excluded={}, binary={}, unreadable={}, unrecognized={}\n",
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
        append_lane_summary(output, &inventory_diff.new_findings, style);
        return true;
    }

    let Some(inventory_stats) = &report.inventory_stats else {
        return false;
    };
    output.push_str(&format!(
        "inventory discovered {}, user {}, system {}, lintable {}, discovered-only {}, high risk {}, medium risk {}, low risk {}, scanned {}, non-target {}, found {}, {}, {}\n",
        count_label(report.inventory_roots.len(), "root", "roots"),
        count_label(inventory_stats.user_roots, "root", "roots"),
        count_label(inventory_stats.system_roots, "root", "roots"),
        count_label(inventory_stats.lintable_roots, "root", "roots"),
        count_label(inventory_stats.discovered_only_roots, "root", "roots"),
        count_label(inventory_stats.high_risk_roots, "root", "roots"),
        count_label(inventory_stats.medium_risk_roots, "root", "roots"),
        count_label(inventory_stats.low_risk_roots, "root", "roots"),
        count_label(
            inventory_stats.supported_artifacts_scanned,
            "supported artifact",
            "supported artifacts",
        ),
        count_label(inventory_stats.non_target_total(), "file", "files"),
        count_label(report.findings.len(), "finding", "findings"),
        count_label(report.diagnostics.len(), "diagnostic", "diagnostics"),
        count_label(report.runtime_errors.len(), "runtime error", "runtime errors"),
    ));
    output.push_str(&format!(
        "inventory counters: non-target={}, excluded={}, binary={}, unreadable={}, unrecognized={}\n",
        inventory_stats.non_target_files_in_lintable_roots,
        inventory_stats.excluded_files,
        inventory_stats.binary_files,
        inventory_stats.unreadable_files,
        inventory_stats.unrecognized_files,
    ));
    append_lane_summary(output, report.findings, style);
    true
}

pub(super) fn append_inventory_sections(
    output: &mut String,
    report: &ReportEnvelope<'_>,
    style: ResolvedTextStyle,
) {
    append_inventory_root_section(output, &report.inventory_roots, style);

    let Some(inventory_diff) = &report.inventory_diff else {
        return;
    };

    append_inventory_root_section_with_title(output, "new roots", &inventory_diff.new_roots, style);
    append_inventory_root_section_with_title(
        output,
        "removed roots",
        &inventory_diff.removed_roots,
        style,
    );

    if !inventory_diff.changed_roots.is_empty() {
        append_section_gap(output);
        output
            .push_str(&style.section_heading("changed roots", inventory_diff.changed_roots.len()));
        output.push_str("\n\n");
        let mut changed_roots = inventory_diff.changed_roots.iter().collect::<Vec<_>>();
        changed_roots.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.client.cmp(&right.client))
                .then_with(|| left.surface.cmp(&right.surface))
        });
        for (index, root) in changed_roots.iter().enumerate() {
            let detail = changed_root_fragment(root);
            output.push_str("  ");
            output.push_str(&format!("{} {} {}", root.client, root.surface, root.path));
            output.push('\n');
            output.push_str("  ");
            if detail.is_empty() {
                output.push_str(&style.secondary("content changed"));
            } else {
                output.push_str(&style.secondary(&detail));
            }
            output.push('\n');
            if index + 1 < changed_roots.len() {
                output.push('\n');
            }
        }
    }

    append_inventory_root_section_with_title(
        output,
        "new lintable roots",
        &inventory_diff.new_lintable_roots,
        style,
    );

    if !inventory_diff.risk_increased_roots.is_empty() {
        append_section_gap(output);
        output.push_str(
            &style.section_heading("risk increased", inventory_diff.risk_increased_roots.len()),
        );
        output.push_str("\n\n");
        let mut risk_increased_roots = inventory_diff
            .risk_increased_roots
            .iter()
            .collect::<Vec<_>>();
        risk_increased_roots.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.client.cmp(&right.client))
                .then_with(|| left.surface.cmp(&right.surface))
        });
        for (index, root) in risk_increased_roots.iter().enumerate() {
            output.push_str("  ");
            output.push_str(&format!("{} {} {}", root.client, root.surface, root.path));
            output.push('\n');
            output.push_str("  ");
            output.push_str(&style.secondary(&format!(
                "risk {} -> {}",
                root.old_risk_level, root.new_risk_level
            )));
            output.push('\n');
            if index + 1 < risk_increased_roots.len() {
                output.push('\n');
            }
        }
    }
}

fn append_inventory_root_section(
    output: &mut String,
    roots: &[crate::known_scan::InventoryRoot],
    style: ResolvedTextStyle,
) {
    append_inventory_root_section_with_title(output, "inventory roots", roots, style);
}

fn append_inventory_root_section_with_title(
    output: &mut String,
    title: &str,
    roots: &[crate::known_scan::InventoryRoot],
    style: ResolvedTextStyle,
) {
    if roots.is_empty() {
        return;
    }

    append_section_gap(output);
    output.push_str(&style.section_heading(title, roots.len()));
    output.push_str("\n\n");

    let mut sorted_roots = roots.iter().collect::<Vec<_>>();
    sorted_roots.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.client.cmp(&right.client))
            .then_with(|| left.surface.cmp(&right.surface))
            .then_with(|| left.mode.cmp(&right.mode))
            .then_with(|| left.risk_level.cmp(&right.risk_level))
    });

    for (index, root) in sorted_roots.iter().enumerate() {
        output.push_str("  ");
        output.push_str(&format!(
            "[{}] [{}] [{}] {} {} {}",
            root.provenance.origin_scope,
            root.risk_level,
            root.mode,
            root.client,
            root.surface,
            root.path
        ));
        output.push('\n');
        if index + 1 < sorted_roots.len() {
            output.push('\n');
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::known_scan::{
        InventoryChangedRoot, InventoryDiff, InventoryOriginScope, InventoryProvenance,
        InventoryRiskIncrease, InventoryRoot, InventoryStats,
    };
    use crate::output::model::{ReportEnvelope, ReportStats, ToolMetadata};
    use lintai_api::{Finding, Location, RuleMetadata, RuleTier, Severity, Span};

    fn base_envelope<'a>(findings: &'a [Finding]) -> ReportEnvelope<'a> {
        ReportEnvelope {
            schema_version: 1,
            tool: ToolMetadata { name: "lintai" },
            config_source: None,
            project_root: None,
            discovered_roots: Vec::new(),
            discovery_stats: None,
            inventory_roots: Vec::new(),
            inventory_stats: None,
            inventory_diff: None,
            policy_matches: Vec::new(),
            policy_stats: None,
            stats: ReportStats {
                scanned_files: 0,
                skipped_files: 0,
            },
            findings,
            diagnostics: &[],
            runtime_errors: &[],
        }
    }

    fn inventory_root(
        path: &str,
        client: &str,
        path_type: &str,
        risk_level: &str,
        mode: &str,
    ) -> InventoryRoot {
        InventoryRoot {
            client: client.into(),
            surface: "surface".into(),
            path: path.into(),
            mode: mode.into(),
            risk_level: risk_level.into(),
            provenance: InventoryProvenance {
                origin_scope: InventoryOriginScope::Project.as_str().to_string(),
                path_type: path_type.into(),
                target_path: None,
                owner: None,
                mtime_epoch_s: None,
            },
        }
    }

    #[test]
    fn appends_inventory_summary_when_diff_present() {
        let finding = Finding::new(
            &RuleMetadata::new(
                "SEC417",
                "test",
                lintai_api::Category::Hardening,
                Severity::Warn,
                lintai_api::Confidence::High,
                RuleTier::Stable,
            ),
            Location::new("service/config.json", Span::new(0, 12)),
            "details",
        );
        let finding_for_diff = finding.clone();
        let mut envelope = base_envelope(std::slice::from_ref(&finding));
        let inventory_roots = vec![inventory_root(
            "service",
            "client-a",
            "directory",
            "low",
            "discovered_only",
        )];
        envelope.inventory_stats = Some(InventoryStats {
            user_roots: 1,
            discovered_only_roots: 1,
            high_risk_roots: 2,
            medium_risk_roots: 1,
            low_risk_roots: 3,
            supported_artifacts_scanned: 4,
            non_target_files_in_lintable_roots: 5,
            excluded_files: 6,
            binary_files: 7,
            unreadable_files: 8,
            unrecognized_files: 9,
            system_roots: 2,
            lintable_roots: 0,
        });
        envelope.inventory_roots = inventory_roots;
        envelope.inventory_diff = Some(InventoryDiff {
            new_roots: vec![inventory_root(
                "service/new",
                "client-a",
                "file",
                "low",
                "lintable",
            )],
            removed_roots: Vec::new(),
            changed_roots: vec![InventoryChangedRoot {
                client: "client-a".into(),
                surface: "surface".into(),
                path: "service/config.json".into(),
                old_mode: "discovered_only".into(),
                new_mode: "lintable".into(),
                old_risk_level: "low".into(),
                new_risk_level: "low".into(),
                old_path_type: "file".into(),
                new_path_type: "file".into(),
                old_mtime_epoch_s: Some(101),
                new_mtime_epoch_s: None,
            }],
            new_lintable_roots: vec![inventory_root(
                "service/lintable",
                "client-a",
                "directory",
                "medium",
                "lintable",
            )],
            risk_increased_roots: vec![InventoryRiskIncrease {
                client: "client-a".into(),
                surface: "surface".into(),
                path: "service/config.json".into(),
                old_risk_level: "low".into(),
                new_risk_level: "medium".into(),
            }],
            new_findings: vec![finding_for_diff],
        });

        let mut output = String::new();
        super::append_inventory_summary(
            &mut output,
            &envelope,
            super::ResolvedTextStyle::plain_for_tests(),
        );
        super::append_inventory_sections(
            &mut output,
            &envelope,
            super::ResolvedTextStyle::plain_for_tests(),
        );

        assert!(output.contains(
            "inventory diff discovered 1 root, 1 new root, 0 removed roots, 1 changed root, 1 new lintable root, 1 root with increased risk, 1 new finding"
        ));
        assert!(output.contains("lanes: supply-chain 1"));
        assert!(output.contains("new roots (1)"));
        assert!(output.contains("changed roots (1)"));
        assert!(output.contains("risk increased (1)"));
    }

    #[test]
    fn changed_root_without_metadata_delta_marks_content_change() {
        let mut envelope = base_envelope(&[]);
        envelope.inventory_stats = Some(InventoryStats::default());
        envelope.inventory_diff = Some(InventoryDiff {
            new_roots: Vec::new(),
            removed_roots: Vec::new(),
            changed_roots: vec![InventoryChangedRoot {
                client: "client-a".into(),
                surface: "surface".into(),
                path: "service/config.json".into(),
                old_mode: "lintable".into(),
                new_mode: "lintable".into(),
                old_risk_level: "low".into(),
                new_risk_level: "low".into(),
                old_path_type: "file".into(),
                new_path_type: "file".into(),
                old_mtime_epoch_s: None,
                new_mtime_epoch_s: None,
            }],
            new_lintable_roots: Vec::new(),
            risk_increased_roots: Vec::new(),
            new_findings: Vec::new(),
        });
        let mut output = String::new();

        super::append_inventory_sections(
            &mut output,
            &envelope,
            super::ResolvedTextStyle::plain_for_tests(),
        );

        assert!(output.contains("content changed"));
    }

    #[test]
    fn appends_inventory_summary_without_diff() {
        let mut envelope = base_envelope(&[]);
        envelope.inventory_roots = vec![inventory_root(
            "service",
            "client-a",
            "directory",
            "low",
            "lintable",
        )];
        envelope.inventory_stats = Some(InventoryStats {
            user_roots: 1,
            system_roots: 1,
            lintable_roots: 1,
            discovered_only_roots: 2,
            high_risk_roots: 3,
            medium_risk_roots: 4,
            low_risk_roots: 5,
            supported_artifacts_scanned: 6,
            non_target_files_in_lintable_roots: 7,
            excluded_files: 8,
            binary_files: 9,
            unreadable_files: 10,
            unrecognized_files: 11,
        });
        let mut output = String::new();

        let did_render = super::append_inventory_summary(
            &mut output,
            &envelope,
            super::ResolvedTextStyle::plain_for_tests(),
        );
        super::append_inventory_sections(
            &mut output,
            &envelope,
            super::ResolvedTextStyle::plain_for_tests(),
        );

        assert!(did_render);
        assert!(output.contains("inventory discovered 1 root, user 1 root, system 1 root"));
        assert!(output.contains("inventory counters: non-target=7"));
        assert!(output.contains("inventory roots (1)"));
    }
}
