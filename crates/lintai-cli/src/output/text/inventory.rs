use crate::output::model::ReportEnvelope;
use crate::shipped_rules::shipped_rule_docs_url;

use super::common::{changed_root_fragment, client_for_inventory_finding};

pub(super) fn append_inventory_summary(output: &mut String, report: &ReportEnvelope<'_>) -> bool {
    if let Some(inventory_diff) = &report.inventory_diff {
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
        return true;
    }

    let Some(inventory_stats) = &report.inventory_stats else {
        return false;
    };
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
    true
}

pub(super) fn append_inventory_sections(output: &mut String, report: &ReportEnvelope<'_>) {
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
            if let Some(url) = shipped_rule_docs_url(&finding.rule_code) {
                output.push_str(&format!("  docs: {url}\n"));
            }
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
                lintai_api::Category::Security,
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
        super::append_inventory_summary(&mut output, &envelope);
        super::append_inventory_sections(&mut output, &envelope);

        assert!(output.contains("inventory diff discovered 1 root(s), new 1 root(s), removed 0 root(s), changed 1 root(s), new lintable 1 root(s), risk increased 1 root(s), new findings 1"));
        assert!(output.contains("inventory counters: user=1"));
        assert!(output.contains("new-root [low lintable] client-a surface service/new"));
        assert!(output.contains("changed-root [mode discovered_only->lintable mtime 101->none] client-a surface service/config.json"));
        assert!(
            output
                .contains("risk-increased-root [low->medium] client-a surface service/config.json")
        );
        assert!(output.contains("new-finding SEC417 client-a service/config.json"));
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

        let did_render = super::append_inventory_summary(&mut output, &envelope);
        super::append_inventory_sections(&mut output, &envelope);

        assert!(did_render);
        assert!(
            output.contains("inventory discovered 1 root(s), user 1 root(s), system 1 root(s)")
        );
        assert!(output.contains("inventory counters: non_target=7"));
        assert!(output.contains("excluded=8"));
        assert!(output.contains("binary=9"));
        assert!(output.contains("unreadable=10"));
        assert!(output.contains("unrecognized=11"));
        assert!(output.contains("inventory-root [project low lintable] client-a surface service"));
    }
}
