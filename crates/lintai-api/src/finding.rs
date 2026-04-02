use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Category, Confidence, RuleMetadata};

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Span {
    pub start_byte: usize,
    pub end_byte: usize,
}

impl Span {
    pub fn new(start_byte: usize, end_byte: usize) -> Self {
        Self {
            start_byte,
            end_byte,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct LineColumn {
    pub line: usize,
    pub column: usize,
}

impl LineColumn {
    pub fn new(line: usize, column: usize) -> Self {
        Self { line, column }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Location {
    pub normalized_path: String,
    pub span: Span,
    pub start: Option<LineColumn>,
    pub end: Option<LineColumn>,
}

impl Location {
    pub fn new(normalized_path: impl Into<String>, span: Span) -> Self {
        Self {
            normalized_path: normalized_path.into(),
            span,
            start: None,
            end: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Claim,
    ObservedBehavior,
    Context,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub message: String,
    pub location: Option<Location>,
    pub subject_id: Option<String>,
    pub metadata: Option<Value>,
}

impl Evidence {
    pub fn new(kind: EvidenceKind, message: impl Into<String>, location: Option<Location>) -> Self {
        Self {
            kind,
            message: message.into(),
            location,
            subject_id: None,
            metadata: None,
        }
    }

    pub fn with_subject_id(mut self, subject_id: impl Into<String>) -> Self {
        self.subject_id = Some(subject_id.into());
        self
    }

    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Deny,
    Warn,
    Allow,
}

impl Severity {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Warn => "warn",
            Self::Allow => "allow",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Deny => "Deny",
            Self::Warn => "Warn",
            Self::Allow => "Allow",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Applicability {
    Safe,
    Unsafe,
    Suggestion,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Fix {
    pub span: Span,
    pub replacement: String,
    pub applicability: Applicability,
    pub message: Option<String>,
}

impl Fix {
    pub fn new(
        span: Span,
        replacement: impl Into<String>,
        applicability: Applicability,
        message: Option<String>,
    ) -> Self {
        Self {
            span,
            replacement: replacement.into(),
            applicability,
            message,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct StableKey {
    pub rule_code: String,
    pub normalized_path: String,
    pub span: Span,
    pub subject_id: Option<String>,
}

impl StableKey {
    pub fn new(
        rule_code: impl Into<String>,
        normalized_path: impl Into<String>,
        span: Span,
        subject_id: Option<String>,
    ) -> Self {
        Self {
            rule_code: rule_code.into(),
            normalized_path: normalized_path.into(),
            span,
            subject_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct RelatedFinding {
    pub rule_code: String,
    pub normalized_path: String,
    pub span: Span,
}

impl RelatedFinding {
    pub fn new(
        rule_code: impl Into<String>,
        normalized_path: impl Into<String>,
        span: Span,
    ) -> Self {
        Self {
            rule_code: rule_code.into(),
            normalized_path: normalized_path.into(),
            span,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Suggestion {
    pub message: String,
    pub fix: Option<Fix>,
}

impl Suggestion {
    pub fn new(message: impl Into<String>, fix: Option<Fix>) -> Self {
        Self {
            message: message.into(),
            fix,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Finding {
    pub stable_key: StableKey,
    pub rule_code: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub location: Location,
    pub evidence: Vec<Evidence>,
    pub fix: Option<Fix>,
    pub suggestions: Vec<Suggestion>,
    pub cwe: Vec<String>,
    pub tags: Vec<String>,
    pub related: Vec<RelatedFinding>,
    pub metadata: Option<Value>,
}

impl Finding {
    pub fn new(rule: &RuleMetadata, location: Location, message: impl Into<String>) -> Self {
        let message = message.into();
        let stable_key = StableKey::new(
            rule.code,
            location.normalized_path.clone(),
            location.span.clone(),
            None,
        );

        Self {
            stable_key,
            rule_code: rule.code.to_owned(),
            category: rule.category,
            severity: rule.default_severity,
            confidence: rule.default_confidence,
            message: message.clone(),
            evidence: vec![Evidence::new(
                EvidenceKind::Context,
                message.clone(),
                Some(location.clone()),
            )],
            location,
            fix: None,
            suggestions: Vec::new(),
            cwe: Vec::new(),
            tags: Vec::new(),
            related: Vec::new(),
            metadata: None,
        }
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    pub fn with_fix(mut self, fix: Fix) -> Self {
        self.fix = Some(fix);
        self
    }

    pub fn with_suggestion(mut self, suggestion: Suggestion) -> Self {
        self.suggestions.push(suggestion);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe.push(cwe.into());
        self
    }

    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}
