use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use lintai_api::{
    Finding, RuleMetadata, RuleProvider, RuleTier, ScanContext, ScanScope, Span, StableKey,
};

use crate::{EngineError, ScanDiagnostic};

pub(crate) struct ProviderCatalog<'a> {
    entries: Vec<ProviderEntry<'a>>,
}

pub(crate) struct ProviderEntry<'a> {
    provider: &'a dyn RuleProvider,
    id: String,
    rules: BTreeMap<String, RuleMetadata>,
    supports_fix: bool,
    scope: ScanScope,
    timeout: Duration,
}

impl<'a> ProviderCatalog<'a> {
    pub(crate) fn new(providers: &'a [Arc<dyn RuleProvider>]) -> Result<Self, EngineError> {
        let mut provider_ids = BTreeSet::new();
        let mut global_rule_codes = BTreeMap::new();
        let mut entries = Vec::with_capacity(providers.len());

        for provider in providers {
            let provider = provider.as_ref();
            let provider_id = provider.id().to_owned();
            if !provider_ids.insert(provider_id.clone()) {
                return Err(EngineError::ProviderContract(format!(
                    "duplicate provider id `{provider_id}`"
                )));
            }

            let timeout = provider.timeout();
            validate_timeout(provider_id.as_str(), timeout)?;
            validate_capabilities(provider)?;

            let mut rules = BTreeMap::new();
            for rule in provider.rules() {
                if rules.insert(rule.code.to_owned(), *rule).is_some() {
                    return Err(EngineError::ProviderContract(format!(
                        "provider `{provider_id}` declares duplicate rule code `{}`",
                        rule.code
                    )));
                }

                if let Some(other_provider) =
                    global_rule_codes.insert(rule.code.to_owned(), provider_id.clone())
                {
                    return Err(EngineError::ProviderContract(format!(
                        "rule code `{}` is declared by both `{other_provider}` and `{provider_id}`",
                        rule.code
                    )));
                }
            }

            entries.push(ProviderEntry {
                provider,
                id: provider_id,
                rules,
                supports_fix: provider.supports_fix(),
                scope: provider.scan_scope(),
                timeout,
            });
        }

        Ok(Self { entries })
    }

    pub(crate) fn per_file(&self) -> impl Iterator<Item = &ProviderEntry<'a>> {
        self.entries
            .iter()
            .filter(|entry| entry.scope == ScanScope::PerFile)
    }

    pub(crate) fn workspace(&self) -> impl Iterator<Item = &ProviderEntry<'a>> {
        self.entries
            .iter()
            .filter(|entry| entry.scope == ScanScope::Workspace)
    }

    pub(crate) fn start_all(&self) -> Result<usize, EngineError> {
        let mut started = 0usize;
        for entry in &self.entries {
            if let Err(error) = entry.provider.on_start() {
                let cleanup_result = self.finish_started(started);
                return Err(match cleanup_result {
                    Ok(()) => EngineError::ProviderLifecycle(error),
                    Err(cleanup_error) => {
                        crate::engine::combine_lifecycle_errors(error, cleanup_error)
                    }
                });
            }

            started += 1;
        }

        Ok(started)
    }

    pub(crate) fn finish_started(&self, count: usize) -> Result<(), EngineError> {
        let mut first_error = None;
        for entry in self.entries.iter().take(count).rev() {
            if let Err(error) = entry.provider.on_finish() {
                first_error.get_or_insert(error);
            }
        }

        if let Some(error) = first_error {
            Err(EngineError::ProviderLifecycle(error))
        } else {
            Ok(())
        }
    }
}

impl ProviderEntry<'_> {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn provider(&self) -> &dyn RuleProvider {
        self.provider
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(crate) fn prepare_finding(
        &self,
        ctx: &ScanContext,
        mut finding: Finding,
        diagnostics: &mut Vec<ScanDiagnostic>,
    ) -> Option<Finding> {
        self.prepare_finding_internal(
            &ctx.artifact.normalized_path,
            &ctx.content,
            &mut finding,
            diagnostics,
            Some(ctx),
        )
    }

    pub(crate) fn prepare_workspace_finding(
        &self,
        artifact_path: &str,
        content: &str,
        mut finding: Finding,
        diagnostics: &mut Vec<ScanDiagnostic>,
    ) -> Option<Finding> {
        self.prepare_finding_internal(artifact_path, content, &mut finding, diagnostics, None)
    }

    fn prepare_finding_internal(
        &self,
        artifact_path: &str,
        content: &str,
        finding: &mut Finding,
        diagnostics: &mut Vec<ScanDiagnostic>,
        ctx: Option<&ScanContext>,
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

        if self.supports_fix && finding.fix.is_none() {
            if let Some(ctx) = ctx {
                finding.fix = self.provider.fix(ctx, finding);
            }
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

fn validate_timeout(provider_id: &str, timeout: Duration) -> Result<(), EngineError> {
    if timeout.is_zero() {
        return Err(EngineError::ProviderContract(format!(
            "provider `{provider_id}` declares zero timeout"
        )));
    }

    Ok(())
}

fn validate_capabilities(provider: &dyn RuleProvider) -> Result<(), EngineError> {
    let _capabilities = provider.capabilities();
    Ok(())
}

fn provider_diagnostic(normalized_path: &str, message: String) -> ScanDiagnostic {
    ScanDiagnostic {
        normalized_path: normalized_path.to_owned(),
        severity: crate::DiagnosticSeverity::Warn,
        code: Some("provider_contract".to_owned()),
        message,
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
