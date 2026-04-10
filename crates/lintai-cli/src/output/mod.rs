mod build;
mod json;
mod model;
mod sarif;
mod text;

pub(crate) use build::{
    InventoryEnvelopeArgs, build_envelope, build_envelope_with_discovery,
    build_envelope_with_inventory,
};
pub(crate) use json::format_json;
pub(crate) use model::ReportEnvelope;
pub(crate) use sarif::format_sarif;
pub(crate) use text::format_text;

#[cfg(test)]
mod tests {
    use super::{format_json, format_sarif, format_text};
    use crate::output::model::{ReportEnvelope, ReportStats, ToolMetadata};

    #[test]
    fn sarif_output_contains_stable_fingerprint() {
        let finding = lintai_api::Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC900",
                "demo",
                lintai_api::Category::Security,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            lintai_api::Location::new("SKILL.md", lintai_api::Span::new(0, 4)),
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
            inventory_stats: None,
            inventory_diff: None,
            policy_matches: Vec::new(),
            policy_stats: None,
            stats: ReportStats {
                scanned_files: 1,
                skipped_files: 0,
            },
            findings: std::slice::from_ref(&finding),
            diagnostics: &[],
            runtime_errors: &[],
        };

        let sarif = format_sarif(&report).unwrap();
        assert!(sarif.contains("\"stableKey\": \"SEC900:SKILL.md:0:4:\""));
    }

    #[test]
    fn json_output_omits_empty_optional_sections() {
        let report = ReportEnvelope {
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
        };

        let json = format_json(&report).unwrap();
        assert!(!json.contains("discovered_roots"));
        assert!(!json.contains("inventory_roots"));
        assert!(!json.contains("policy_matches"));
    }

    #[test]
    fn text_output_groups_findings_by_public_lane() {
        let recommended = lintai_api::Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC329",
                "demo recommended",
                lintai_api::Category::Hardening,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            lintai_api::Location::new(".github/workflows/ci.yml", lintai_api::Span::new(0, 4)),
            "demo recommended finding",
        );
        let preview = lintai_api::Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC335",
                "demo preview",
                lintai_api::Category::Security,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            lintai_api::Location::new("SKILL.md", lintai_api::Span::new(0, 4)),
            "demo preview finding",
        );
        let governance = lintai_api::Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC423",
                "demo governance",
                lintai_api::Category::Hardening,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            lintai_api::Location::new("SKILL.md", lintai_api::Span::new(5, 9)),
            "demo governance finding",
        );
        let supply_chain = lintai_api::Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC324",
                "demo supply-chain finding",
                lintai_api::Category::Security,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            lintai_api::Location::new(".github/workflows/ci.yml", lintai_api::Span::new(5, 9)),
            "demo supply-chain finding",
        );
        let findings = [recommended, preview, governance, supply_chain];
        let report = ReportEnvelope {
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
                scanned_files: 3,
                skipped_files: 0,
            },
            findings: &findings,
            diagnostics: &[],
            runtime_errors: &[],
        };

        let text = format_text(&report);
        assert!(text.starts_with("scanned 3 file(s), skipped 0 file(s), found 4 finding(s)"));
        assert!(text.contains("recommended findings: 1"));
        assert!(text.contains("preview findings: 1"));
        assert!(text.contains("governance review findings: 1"));
        assert!(text.contains("supply-chain findings: 1"));
    }
}
