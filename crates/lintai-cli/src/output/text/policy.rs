use crate::output::model::ReportEnvelope;

pub(super) fn append_policy_sections(output: &mut String, report: &ReportEnvelope<'_>) {
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
}

#[cfg(test)]
mod tests {
    use crate::known_scan::{InventoryProvenance, InventoryRoot, InventoryStats};
    use crate::output::model::{ReportEnvelope, ReportStats, ToolMetadata};
    use crate::policy_os::PolicyMatch;
    use crate::policy_os::PolicyStats;
    use lintai_api::{Finding, Location, RuleMetadata, RuleTier, Severity, Span};

    fn empty_envelope<'a>() -> ReportEnvelope<'a> {
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
            findings: &[],
            diagnostics: &[],
            runtime_errors: &[],
        }
    }

    #[test]
    fn appends_policy_sections_with_stats_and_matches() {
        let mut envelope = empty_envelope();
        let findings = [Finding::new(
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
        )];
        envelope.findings = &findings;
        envelope.inventory_roots = vec![InventoryRoot {
            client: "client-a".into(),
            surface: "surface".into(),
            path: "/project".into(),
            mode: "lintable".into(),
            risk_level: "low".into(),
            provenance: InventoryProvenance {
                origin_scope: "project".into(),
                path_type: "directory".into(),
                target_path: None,
                owner: None,
                mtime_epoch_s: None,
            },
        }];
        envelope.inventory_stats = Some(InventoryStats {
            user_roots: 1,
            system_roots: 0,
            lintable_roots: 1,
            discovered_only_roots: 0,
            high_risk_roots: 0,
            medium_risk_roots: 0,
            low_risk_roots: 0,
            supported_artifacts_scanned: 0,
            non_target_files_in_lintable_roots: 0,
            excluded_files: 0,
            binary_files: 0,
            unreadable_files: 0,
            unrecognized_files: 0,
        });
        envelope.policy_matches = vec![PolicyMatch {
            policy_id: "policy_1".into(),
            severity: "warn".into(),
            client: "client-a".into(),
            surface: "surface".into(),
            path: "service/config.json".into(),
            message: "policy message".into(),
            evidence: vec!["some evidence".into()],
            matched_findings: vec!["SEC417".into()],
            mode: "lintable".into(),
            risk_level: "low".into(),
        }];
        envelope.policy_stats = Some(PolicyStats {
            deny_matches: 1,
            warn_matches: 2,
            matched_roots: 1,
            matched_findings: 1,
        });

        let mut output = String::new();
        super::append_policy_sections(&mut output, &envelope);

        assert!(
            output.contains(
                "policy matched 1 root(s), deny 1, warn 2, inventory roots 1, findings 1"
            )
        );
        assert!(output.contains("inventory counters: user=1 system=0 lintable=1 discovered_only=0 high=0 medium=0 low=0 scanned=0 non_target=0 excluded=0 binary=0 unreadable=0 unrecognized=0"));
        assert!(output.contains(
            "policy [warn] policy_1 client-a surface service/config.json policy message"
        ));
        assert!(output.contains("  matched: SEC417"));
    }

    #[test]
    fn appends_no_policy_summary_when_stats_absent() {
        let mut envelope = empty_envelope();
        let mut output = String::new();
        envelope.policy_matches = vec![PolicyMatch {
            policy_id: "policy_1".into(),
            severity: "warn".into(),
            client: "client-a".into(),
            surface: "surface".into(),
            path: "service/config.json".into(),
            message: "policy message".into(),
            evidence: vec!["some evidence".into()],
            matched_findings: vec![],
            mode: "lintable".into(),
            risk_level: "low".into(),
        }];

        super::append_policy_sections(&mut output, &envelope);

        assert!(output.contains(
            "policy [warn] policy_1 client-a surface service/config.json policy message"
        ));
    }
}
