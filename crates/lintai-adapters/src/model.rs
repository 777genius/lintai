use lintai_api::{DocumentSemantics, ParsedDocument};
use lintai_parse::ParseDiagnostic;

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedArtifact {
    pub document: ParsedDocument,
    pub semantics: Option<DocumentSemantics>,
    pub diagnostics: Vec<ParseDiagnostic>,
}

impl ParsedArtifact {
    pub fn new(document: ParsedDocument, semantics: Option<DocumentSemantics>) -> Self {
        Self {
            document,
            semantics,
            diagnostics: Vec::new(),
        }
    }

    pub fn with_diagnostics(mut self, diagnostics: Vec<ParseDiagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
}
