use lintai_api::{Finding, RuleTier, Span, StableKey};

use crate::ScanDiagnostic;

use super::ProviderEntry;
use super::diagnostics::provider_diagnostic;

impl ProviderEntry<'_> {
    pub(super) fn prepare_finding_internal(
        &self,
        artifact_path: &str,
        content: &str,
        finding: &mut Finding,
        diagnostics: &mut Vec<ScanDiagnostic>,
    ) -> Option<Finding> {
        let Some(rule) = self.rules.get(&finding.rule_code) else {
            diagnostics.push(provider_diagnostic(
                artifact_path,
                format!(
                    "provider `{}` emitted undeclared rule code `{}`",
                    self.id, finding.rule_code
                ),
            ));
            return None;
        };

        if finding.location.normalized_path != artifact_path {
            diagnostics.push(provider_diagnostic(
                artifact_path,
                format!(
                    "provider `{}` emitted finding for `{}` while scanning `{}`",
                    self.id, finding.location.normalized_path, artifact_path
                ),
            ));
            return None;
        }

        if !span_is_valid(content, &finding.location.span) {
            diagnostics.push(provider_diagnostic(
                artifact_path,
                format!(
                    "provider `{}` emitted invalid span {}..{} for rule `{}`",
                    self.id,
                    finding.location.span.start_byte,
                    finding.location.span.end_byte,
                    finding.rule_code
                ),
            ));
            return None;
        }

        if finding.category != rule.category {
            diagnostics.push(provider_diagnostic(
                artifact_path,
                format!(
                    "provider `{}` emitted rule `{}` with category {:?}, expected {:?}",
                    self.id, finding.rule_code, finding.category, rule.category
                ),
            ));
            finding.category = rule.category;
        }

        let normalized_key = StableKey::new(
            finding.rule_code.clone(),
            finding.location.normalized_path.clone(),
            finding.location.span.clone(),
            finding.stable_key.subject_id.clone(),
        );
        if finding.stable_key != normalized_key {
            diagnostics.push(provider_diagnostic(
                artifact_path,
                format!(
                    "provider `{}` emitted non-canonical stable_key for rule `{}`; engine normalized it",
                    self.id, finding.rule_code
                ),
            ));
            finding.stable_key = normalized_key;
        }

        normalize_evidence(finding, content, artifact_path, &self.id, diagnostics);
        if matches!(rule.tier, RuleTier::Stable) && finding.evidence.is_empty() {
            diagnostics.push(provider_diagnostic(
                artifact_path,
                format!(
                    "provider `{}` emitted stable rule `{}` without structured evidence",
                    self.id, finding.rule_code
                ),
            ));
            return None;
        }

        normalize_fix(finding, content, &self.id, diagnostics);
        normalize_suggestion_fixes(finding, content, &self.id, diagnostics);

        Some(finding.clone())
    }
}

fn span_is_valid(content: &str, span: &Span) -> bool {
    span.start_byte <= span.end_byte
        && span.end_byte <= content.len()
        && content.is_char_boundary(span.start_byte)
        && content.is_char_boundary(span.end_byte)
}

fn normalize_fix(
    finding: &mut Finding,
    content: &str,
    provider_id: &str,
    diagnostics: &mut Vec<ScanDiagnostic>,
) {
    let Some(fix) = finding.fix.as_ref() else {
        return;
    };

    if span_is_valid(content, &fix.span) {
        return;
    }

    let invalid_fix = fix.clone();
    diagnostics.push(provider_diagnostic(
        &finding.location.normalized_path,
        format!(
            "provider `{provider_id}` emitted invalid fix span {}..{} for rule `{}`; engine dropped the fix",
            invalid_fix.span.start_byte, invalid_fix.span.end_byte, finding.rule_code
        ),
    ));
    finding.fix = None;
}

fn normalize_evidence(
    finding: &mut Finding,
    content: &str,
    artifact_path: &str,
    provider_id: &str,
    diagnostics: &mut Vec<ScanDiagnostic>,
) {
    for evidence in &mut finding.evidence {
        let Some(location) = evidence.location.as_mut() else {
            continue;
        };
        if location.normalized_path != artifact_path {
            diagnostics.push(provider_diagnostic(
                artifact_path,
                format!(
                    "provider `{provider_id}` emitted evidence for `{}` while scanning `{artifact_path}`; engine dropped the evidence location",
                    location.normalized_path
                ),
            ));
            evidence.location = None;
            continue;
        }

        if !span_is_valid(content, &location.span) {
            diagnostics.push(provider_diagnostic(
                artifact_path,
                format!(
                    "provider `{provider_id}` emitted invalid evidence span {}..{} for rule `{}`; engine dropped the evidence location",
                    location.span.start_byte, location.span.end_byte, finding.rule_code
                ),
            ));
            evidence.location = None;
        }
    }
}

fn normalize_suggestion_fixes(
    finding: &mut Finding,
    content: &str,
    provider_id: &str,
    diagnostics: &mut Vec<ScanDiagnostic>,
) {
    for suggestion in &mut finding.suggestions {
        let Some(fix) = suggestion.fix.as_ref() else {
            continue;
        };
        if span_is_valid(content, &fix.span) {
            continue;
        }

        diagnostics.push(provider_diagnostic(
            &finding.location.normalized_path,
            format!(
                "provider `{provider_id}` emitted invalid suggestion fix span {}..{} for rule `{}`; engine dropped the suggestion fix",
                fix.span.start_byte, fix.span.end_byte, finding.rule_code
            ),
        ));
        suggestion.fix = None;
    }
}
