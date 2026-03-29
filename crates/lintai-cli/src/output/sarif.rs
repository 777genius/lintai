use std::collections::BTreeSet;

use lintai_api::Severity;

use super::model::ReportEnvelope;

pub(crate) fn format_sarif(report: &ReportEnvelope<'_>) -> Result<String, serde_json::Error> {
    let mut results = report
        .findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "ruleId": finding.rule_code,
                "level": sarif_level(finding.severity),
                "message": { "text": finding.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": finding.location.normalized_path },
                        "region": {
                            "startLine": finding.location.start.as_ref().map(|v| v.line),
                            "startColumn": finding.location.start.as_ref().map(|v| v.column),
                            "endLine": finding.location.end.as_ref().map(|v| v.line),
                            "endColumn": finding.location.end.as_ref().map(|v| v.column),
                            "charOffset": finding.location.span.start_byte,
                            "charLength": finding.location.span.end_byte.saturating_sub(finding.location.span.start_byte),
                        }
                    }
                }],
                "partialFingerprints": {
                    "stableKey": format!(
                        "{}:{}:{}:{}:{}",
                        finding.stable_key.rule_code,
                        finding.stable_key.normalized_path,
                        finding.stable_key.span.start_byte,
                        finding.stable_key.span.end_byte,
                        finding.stable_key.subject_id.as_deref().unwrap_or("")
                    )
                },
                "properties": {
                    "confidence": format!("{:?}", finding.confidence).to_lowercase(),
                    "category": format!("{:?}", finding.category).to_lowercase(),
                    "evidenceCount": finding.evidence.len(),
                }
            })
        })
        .collect::<Vec<_>>();
    results.extend(report.policy_matches.iter().map(|policy_match| {
        serde_json::json!({
            "ruleId": format!("policy:{}", policy_match.policy_id),
            "level": sarif_policy_level(policy_match.severity.as_str()),
            "message": { "text": policy_match.message },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": policy_match.path },
                }
            }],
            "partialFingerprints": {
                "stableKey": format!(
                    "policy:{}:{}:{}:{}",
                    policy_match.policy_id,
                    policy_match.client,
                    policy_match.surface,
                    policy_match.path
                )
            },
            "properties": {
                "client": policy_match.client,
                "surface": policy_match.surface,
                "mode": policy_match.mode,
                "riskLevel": policy_match.risk_level,
                "matchedFindings": policy_match.matched_findings,
            }
        })
    }));
    let mut rules = report
        .findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "id": finding.rule_code,
                "shortDescription": { "text": finding.rule_code },
                "properties": {
                    "tags": finding.tags,
                    "cwe": finding.cwe,
                }
            })
        })
        .collect::<Vec<_>>();
    let mut seen_policy_rules = BTreeSet::new();
    for policy_match in &report.policy_matches {
        if !seen_policy_rules.insert(policy_match.policy_id.clone()) {
            continue;
        }
        rules.push(serde_json::json!({
            "id": format!("policy:{}", policy_match.policy_id),
            "shortDescription": { "text": policy_match.policy_id },
            "properties": {
                "policy": true,
            }
        }));
    }

    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": report.tool.name,
                    "rules": rules,
                }
            },
            "results": results,
        }]
    }))
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Deny => "error",
        Severity::Warn => "warning",
        Severity::Allow => "note",
    }
}

fn sarif_policy_level(severity: &str) -> &'static str {
    match severity {
        "deny" => "error",
        "warn" => "warning",
        _ => "note",
    }
}
