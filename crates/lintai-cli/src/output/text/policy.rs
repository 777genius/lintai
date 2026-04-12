use std::collections::BTreeSet;

use crate::output::model::ReportEnvelope;

use super::common::{append_section_gap, count_label};
use super::scan::append_lane_summary;
use super::style::ResolvedTextStyle;

pub(super) fn append_policy_sections(
    output: &mut String,
    report: &ReportEnvelope<'_>,
    style: ResolvedTextStyle,
) {
    if report.policy_stats.is_some() || !report.policy_matches.is_empty() {
        let matched_roots = report
            .policy_stats
            .as_ref()
            .map(|policy_stats| policy_stats.matched_roots)
            .unwrap_or_else(|| {
                report
                    .policy_matches
                    .iter()
                    .map(|policy_match| {
                        (
                            policy_match.client.as_str(),
                            policy_match.surface.as_str(),
                            policy_match.path.as_str(),
                        )
                    })
                    .collect::<BTreeSet<_>>()
                    .len()
            });
        let deny_matches = report
            .policy_stats
            .as_ref()
            .map(|policy_stats| policy_stats.deny_matches)
            .unwrap_or_else(|| {
                report
                    .policy_matches
                    .iter()
                    .filter(|policy_match| policy_match.severity == "deny")
                    .count()
            });
        let warn_matches = report
            .policy_stats
            .as_ref()
            .map(|policy_stats| policy_stats.warn_matches)
            .unwrap_or_else(|| {
                report
                    .policy_matches
                    .iter()
                    .filter(|policy_match| policy_match.severity == "warn")
                    .count()
            });
        output.push_str(&format!(
            "policy matched {}, deny {}, warn {}, inventory {}, {}\n",
            count_label(matched_roots, "root", "roots"),
            deny_matches,
            warn_matches,
            count_label(report.inventory_roots.len(), "root", "roots"),
            count_label(report.findings.len(), "finding", "findings"),
        ));
        if let Some(inventory_stats) = &report.inventory_stats {
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
        }
        append_lane_summary(output, report.findings, style);
    }

    if report.policy_matches.is_empty() {
        return;
    }

    append_section_gap(output);
    output.push_str(&style.section_heading("policy matches", report.policy_matches.len()));
    output.push_str("\n\n");

    let mut policy_matches = report.policy_matches.iter().collect::<Vec<_>>();
    policy_matches.sort_by(|left, right| {
        policy_severity_rank(&right.severity)
            .cmp(&policy_severity_rank(&left.severity))
            .then_with(|| left.policy_id.cmp(&right.policy_id))
            .then_with(|| left.client.cmp(&right.client))
            .then_with(|| left.surface.cmp(&right.surface))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.message.cmp(&right.message))
    });

    for (index, policy_match) in policy_matches.iter().enumerate() {
        output.push_str("  ");
        output.push_str(&format!(
            "[{}] {} {} {} {}",
            policy_match.severity,
            policy_match.policy_id,
            policy_match.client,
            policy_match.surface,
            policy_match.path
        ));
        output.push('\n');

        output.push_str("  ");
        output.push_str(&policy_match.message);
        output.push('\n');

        if !policy_match.evidence.is_empty() {
            output.push_str("  ");
            output.push_str(&style.secondary("evidence:"));
            output.push('\n');
            for evidence in &policy_match.evidence {
                output.push_str("    ");
                output.push_str(evidence);
                output.push('\n');
            }
        }

        if !policy_match.matched_findings.is_empty() {
            output.push_str("  ");
            output.push_str(&style.secondary("matched findings:"));
            output.push('\n');
            for rule_code in &policy_match.matched_findings {
                output.push_str("    ");
                output.push_str(rule_code);
                output.push('\n');
            }
        }

        if index + 1 < policy_matches.len() {
            output.push('\n');
        }
    }
}

fn policy_severity_rank(severity: &str) -> usize {
    match severity {
        "deny" => 2,
        "warn" => 1,
        _ => 0,
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
                lintai_api::Category::Hardening,
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
        super::append_policy_sections(
            &mut output,
            &envelope,
            super::ResolvedTextStyle::plain_for_tests(),
        );

        assert!(
            output.contains("policy matched 1 root, deny 1, warn 2, inventory 1 root, 1 finding")
        );
        assert!(output.contains("inventory counters: user=1"));
        assert!(output.contains("policy matches (1)"));
        assert!(output.contains("[warn] policy_1 client-a surface service/config.json"));
        assert!(output.contains("matched findings:"));
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

        super::append_policy_sections(
            &mut output,
            &envelope,
            super::ResolvedTextStyle::plain_for_tests(),
        );

        assert!(
            output.contains("policy matched 1 root, deny 0, warn 1, inventory 0 roots, 0 findings")
        );
        assert!(output.contains("policy matches (1)"));
        assert!(output.contains("policy message"));
    }
}
