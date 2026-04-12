use lintai_api::{Finding, Severity};
use lintai_engine::{ScanDiagnostic, ScanRuntimeError};

use crate::output::model::ReportEnvelope;
use crate::shipped_rules::{
    PublicLane, shipped_rule_display_label, shipped_rule_docs_url, shipped_rule_public_lane,
};

use super::common::{
    append_section_gap, count_label, diagnostic_code_label, location_detail_label, location_label,
    provider_execution_phase_label,
};
use super::style::ResolvedTextStyle;

const LANE_ORDER: [PublicLane; 8] = [
    PublicLane::Recommended,
    PublicLane::ThreatReview,
    PublicLane::SupplyChain,
    PublicLane::Compat,
    PublicLane::Governance,
    PublicLane::Guidance,
    PublicLane::Advisory,
    PublicLane::Preview,
];

pub(super) fn append_default_summary(
    output: &mut String,
    report: &ReportEnvelope<'_>,
    style: ResolvedTextStyle,
) {
    output.push_str(&format!(
        "scanned {}, skipped {}, found {}, {}, {}\n",
        count_label(report.stats.scanned_files, "file", "files"),
        count_label(report.stats.skipped_files, "file", "files"),
        count_label(report.findings.len(), "finding", "findings"),
        count_label(report.diagnostics.len(), "diagnostic", "diagnostics"),
        count_label(
            report.runtime_errors.len(),
            "runtime error",
            "runtime errors"
        ),
    ));
    append_lane_summary(output, report.findings, style);
}

pub(super) fn append_lane_summary(
    output: &mut String,
    findings: &[Finding],
    style: ResolvedTextStyle,
) {
    let mut parts = Vec::new();
    for lane in LANE_ORDER {
        let count = findings
            .iter()
            .filter(|finding| finding_lane(finding) == lane)
            .count();
        if count > 0 {
            parts.push(style.lane_summary_label(lane, count));
        }
    }
    if !parts.is_empty() {
        output.push('\n');
        output.push_str("lanes: ");
        output.push_str(&parts.join(", "));
        output.push('\n');
    }
}

pub(super) fn append_scan_results(
    output: &mut String,
    report: &ReportEnvelope<'_>,
    style: ResolvedTextStyle,
) {
    append_finding_sections(output, report.findings, style);
    append_diagnostics_section(output, report.diagnostics, style);
    append_runtime_errors_section(output, report.runtime_errors, style);
}

pub(super) fn append_finding_sections(
    output: &mut String,
    findings: &[Finding],
    style: ResolvedTextStyle,
) {
    if findings.is_empty() {
        return;
    }

    let mut sorted = findings.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        left.location
            .normalized_path
            .cmp(&right.location.normalized_path)
            .then_with(|| severity_rank(right.severity).cmp(&severity_rank(left.severity)))
            .then_with(|| left.rule_code.cmp(&right.rule_code))
            .then_with(|| left.stable_key.subject_id.cmp(&right.stable_key.subject_id))
            .then_with(|| {
                left.location
                    .span
                    .start_byte
                    .cmp(&right.location.span.start_byte)
            })
            .then_with(|| {
                left.location
                    .span
                    .end_byte
                    .cmp(&right.location.span.end_byte)
            })
    });

    for lane in LANE_ORDER {
        let lane_findings = sorted
            .iter()
            .copied()
            .filter(|finding| finding_lane(finding) == lane)
            .collect::<Vec<_>>();
        if lane_findings.is_empty() {
            continue;
        }

        append_section_gap(output);
        output.push_str(&style.lane_heading(lane, lane_findings.len()));
        output.push('\n');
        output.push_str(&style.lane_explainer(lane));
        output.push_str("\n\n");

        let mut group_start = 0usize;
        while group_start < lane_findings.len() {
            let group_path = &lane_findings[group_start].location.normalized_path;
            let mut group_end = group_start + 1;
            while group_end < lane_findings.len()
                && lane_findings[group_end].location.normalized_path == *group_path
            {
                group_end += 1;
            }

            let path_group = &lane_findings[group_start..group_end];
            if path_group.len() == 1 {
                append_finding_card(
                    output,
                    path_group[0],
                    style,
                    "  ",
                    &location_label(&path_group[0].location),
                );
            } else if path_group.len() >= 3 {
                append_compact_path_group(output, path_group, style);
            } else {
                append_path_group(output, path_group, style);
            }

            if group_end < lane_findings.len() {
                output.push('\n');
            }
            group_start = group_end;
        }
    }
}

pub(super) fn append_diagnostics_section(
    output: &mut String,
    diagnostics: &[ScanDiagnostic],
    style: ResolvedTextStyle,
) {
    if diagnostics.is_empty() {
        return;
    }

    let mut sorted = diagnostics.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        left.normalized_path
            .cmp(&right.normalized_path)
            .then_with(|| left.message.cmp(&right.message))
            .then_with(|| left.code.cmp(&right.code))
    });

    append_section_gap(output);
    output.push_str(&style.section_heading("diagnostics", sorted.len()));
    output.push_str("\n\n");

    for (index, diagnostic) in sorted.iter().enumerate() {
        output.push_str("  ");
        output.push_str(&style.diagnostic_badge(diagnostic.severity));
        output.push(' ');
        output.push_str(&diagnostic.normalized_path);
        if let Some(code) = diagnostic.code.as_deref() {
            output.push(' ');
            output.push_str(&style.secondary(&format!("code={}", diagnostic_code_label(code))));
        }
        output.push('\n');
        output.push_str("  ");
        output.push_str(&diagnostic.message);
        output.push('\n');

        if index + 1 < sorted.len() {
            output.push('\n');
        }
    }
}

pub(super) fn append_runtime_errors_section(
    output: &mut String,
    runtime_errors: &[ScanRuntimeError],
    style: ResolvedTextStyle,
) {
    if runtime_errors.is_empty() {
        return;
    }

    let mut sorted = runtime_errors.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.normalized_path.cmp(&right.normalized_path))
            .then_with(|| left.provider_id.cmp(&right.provider_id))
            .then_with(|| left.phase.cmp(&right.phase))
            .then_with(|| left.message.cmp(&right.message))
    });

    append_section_gap(output);
    output.push_str(&style.section_heading("runtime errors", sorted.len()));
    output.push_str("\n\n");

    for (index, error) in sorted.iter().enumerate() {
        output.push_str("  ");
        output.push_str(&style.runtime_error_badge(error.kind));
        output.push(' ');
        output.push_str(&error.normalized_path);
        output.push('\n');

        if error.provider_id.is_some() || error.phase.is_some() {
            let mut detail_parts = Vec::new();
            if let Some(provider_id) = error.provider_id.as_deref() {
                detail_parts.push(format!("provider={provider_id}"));
            }
            if let Some(phase) = error.phase {
                detail_parts.push(format!("phase={}", provider_execution_phase_label(phase)));
            }
            output.push_str("  ");
            output.push_str(&style.secondary(&detail_parts.join(", ")));
            output.push('\n');
        }

        output.push_str("  ");
        output.push_str(&error.message);
        output.push('\n');

        if index + 1 < sorted.len() {
            output.push('\n');
        }
    }
}

fn append_path_group(output: &mut String, findings: &[&Finding], style: ResolvedTextStyle) {
    let path = &findings[0].location.normalized_path;
    output.push_str("  ");
    output.push_str(path);
    output.push_str(&style.secondary(&format!(" ({} findings)", findings.len())));
    output.push_str("\n\n");

    for (index, finding) in findings.iter().enumerate() {
        append_finding_card(
            output,
            finding,
            style,
            "    ",
            &location_detail_label(&finding.location),
        );
        if index + 1 < findings.len() {
            output.push('\n');
        }
    }
}

fn append_compact_path_group(
    output: &mut String,
    findings: &[&Finding],
    style: ResolvedTextStyle,
) {
    let path = &findings[0].location.normalized_path;
    output.push_str("  ");
    output.push_str(path);
    output.push_str(&style.secondary(&format!(" ({} findings)", findings.len())));
    output.push_str("\n\n");

    for (index, finding) in findings.iter().enumerate() {
        output.push_str("    ");
        output.push_str(&style.severity_badge(finding.severity));
        output.push(' ');
        output.push_str(&style.category_badge(finding.category));
        output.push(' ');
        output.push_str(&shipped_rule_display_label(&finding.rule_code));
        output.push(' ');
        output.push_str(&style.secondary(&format!(
            "at {}",
            location_detail_label(&finding.location)
        )));
        output.push('\n');

        output.push_str("    ");
        output.push_str(&finding.message);
        output.push('\n');

        if let Some(url) = shipped_rule_docs_url(&finding.rule_code) {
            output.push_str("    ");
            output.push_str(&style.secondary(&format!("docs: {url}")));
            output.push('\n');
        }

        if index + 1 < findings.len() {
            output.push('\n');
        }
    }
}

fn append_finding_card(
    output: &mut String,
    finding: &Finding,
    style: ResolvedTextStyle,
    indent: &str,
    location_display: &str,
) {
    output.push_str(indent);
    output.push_str(&style.severity_badge(finding.severity));
    output.push(' ');
    output.push_str(&style.category_badge(finding.category));
    output.push(' ');
    output.push_str(&shipped_rule_display_label(&finding.rule_code));
    output.push('\n');

    output.push_str(indent);
    output.push_str(&style.secondary(&format!("at {location_display}")));
    output.push('\n');

    output.push_str(indent);
    output.push_str(&finding.message);
    output.push('\n');

    if let Some(url) = shipped_rule_docs_url(&finding.rule_code) {
        output.push_str(indent);
        output.push_str(&style.secondary(&format!("docs: {url}")));
        output.push('\n');
    }

    for suggestion in &finding.suggestions {
        output.push_str(indent);
        output.push_str(&style.secondary(&format!("suggest: {}", suggestion.message)));
        output.push('\n');
    }
}

fn finding_lane(finding: &Finding) -> PublicLane {
    shipped_rule_public_lane(&finding.rule_code).unwrap_or(PublicLane::Preview)
}

fn severity_rank(severity: Severity) -> usize {
    match severity {
        Severity::Deny => 2,
        Severity::Warn => 1,
        Severity::Allow => 0,
    }
}

#[cfg(test)]
mod tests {
    use crate::output::model::{ReportEnvelope, ReportStats, ToolMetadata};
    use lintai_api::Finding;

    fn empty_report<'a>(findings: &'a [Finding]) -> ReportEnvelope<'a> {
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

    #[test]
    fn summary_renders_lane_badges() {
        let findings = [Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC329",
                "demo",
                lintai_api::Category::Hardening,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            lintai_api::Location::new(".mcp.json", lintai_api::Span::new(0, 4)),
            "demo finding",
        )];
        let report = ReportEnvelope {
            stats: ReportStats {
                scanned_files: 3,
                skipped_files: 1,
            },
            ..empty_report(&findings)
        };
        let mut output = String::new();

        super::append_default_summary(
            &mut output,
            &report,
            super::ResolvedTextStyle::plain_for_tests(),
        );

        assert!(output.contains(
            "scanned 3 files, skipped 1 file, found 1 finding, 0 diagnostics, 0 runtime errors"
        ));
        assert!(output.contains("lanes: recommended 1"));
    }

    #[test]
    fn finding_sections_render_grouped_cards() {
        let mut location = lintai_api::Location::new(".mcp.json", lintai_api::Span::new(0, 4));
        location.start = Some(lintai_api::LineColumn::new(4, 18));
        let finding = Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC329",
                "demo",
                lintai_api::Category::Hardening,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            location,
            "demo finding",
        )
        .with_suggestion(lintai_api::Suggestion::new("pin it", None));
        let mut output = String::new();

        super::append_finding_sections(
            &mut output,
            &[finding],
            super::ResolvedTextStyle::plain_for_tests(),
        );

        assert!(output.contains("recommended (1)"));
        assert!(output.contains("quiet practical default findings"));
        assert!(output.contains("[warn] [hardening] SEC329 / MCP-MUTABLE-LAUNCHER"));
        assert!(output.contains("at .mcp.json:4:18"));
        assert!(output.contains("demo finding"));
        assert!(output.contains("suggest: pin it"));
    }

    #[test]
    fn finding_sections_group_multiple_findings_by_path() {
        let mut read_location =
            lintai_api::Location::new("docs/SKILL.md", lintai_api::Span::new(0, 4));
        read_location.start = Some(lintai_api::LineColumn::new(4, 1));
        let mut bash_location =
            lintai_api::Location::new("docs/SKILL.md", lintai_api::Span::new(10, 14));
        bash_location.start = Some(lintai_api::LineColumn::new(5, 1));

        let read_finding = Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC423",
                "demo",
                lintai_api::Category::Hardening,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            read_location,
            "frontmatter grants bare Read tool access",
        );
        let bash_finding = Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC352",
                "demo",
                lintai_api::Category::Hardening,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            bash_location,
            "frontmatter grants unscoped Bash tool access",
        );

        let mut output = String::new();
        super::append_finding_sections(
            &mut output,
            &[read_finding, bash_finding],
            super::ResolvedTextStyle::plain_for_tests(),
        );

        assert!(output.contains("governance (2)"));
        assert!(output.contains("docs/SKILL.md (2 findings)"));
        assert!(output.contains("at 4:1"));
        assert!(output.contains("at 5:1"));
        assert!(output.contains("SEC423 / MD-READ-UNSCOPED"));
        assert!(output.contains("SEC352 / MD-UNSCOPED-BASH"));
    }

    #[test]
    fn finding_sections_compact_large_path_groups() {
        let mut read_location =
            lintai_api::Location::new("docs/SKILL.md", lintai_api::Span::new(0, 4));
        read_location.start = Some(lintai_api::LineColumn::new(4, 1));
        let mut bash_location =
            lintai_api::Location::new("docs/SKILL.md", lintai_api::Span::new(10, 14));
        bash_location.start = Some(lintai_api::LineColumn::new(5, 1));
        let mut grep_location =
            lintai_api::Location::new("docs/SKILL.md", lintai_api::Span::new(15, 19));
        grep_location.start = Some(lintai_api::LineColumn::new(6, 1));

        let read_finding = Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC423",
                "demo",
                lintai_api::Category::Hardening,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            read_location,
            "frontmatter grants bare Read tool access",
        )
        .with_suggestion(lintai_api::Suggestion::new("scope Read", None));
        let bash_finding = Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC352",
                "demo",
                lintai_api::Category::Hardening,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            bash_location,
            "frontmatter grants unscoped Bash tool access",
        );
        let grep_finding = Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC427",
                "demo",
                lintai_api::Category::Hardening,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            grep_location,
            "frontmatter grants bare Grep tool access",
        );

        let mut output = String::new();
        super::append_finding_sections(
            &mut output,
            &[read_finding, bash_finding, grep_finding],
            super::ResolvedTextStyle::plain_for_tests(),
        );

        assert!(output.contains("docs/SKILL.md (3 findings)"));
        assert!(output.contains("SEC423 / MD-READ-UNSCOPED at 4:1"));
        assert!(output.contains("SEC352 / MD-UNSCOPED-BASH at 5:1"));
        assert!(output.contains("SEC427 / MD-GREP-UNSCOPED at 6:1"));
        assert!(output.contains("docs: https://777genius.github.io/lintai/rules/lintai-ai-security/sec423"));
        assert!(!output.contains("suggest: scope Read"));
    }

    #[test]
    fn diagnostics_section_humanizes_internal_codes() {
        let diagnostic = lintai_engine::ScanDiagnostic {
            normalized_path: "SKILL.md".into(),
            severity: lintai_engine::DiagnosticSeverity::Warn,
            code: Some("parse_recovery".into()),
            message: "diagnostic message".into(),
        };
        let mut output = String::new();

        super::append_diagnostics_section(
            &mut output,
            &[diagnostic],
            super::ResolvedTextStyle::plain_for_tests(),
        );

        assert!(output.contains("diagnostics (1)"));
        assert!(output.contains("[warn] SKILL.md code=parse-recovery"));
        assert!(output.contains("diagnostic message"));
    }
}
