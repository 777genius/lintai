use lintai_api::{DocumentSemantics, ParsedDocument};

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedArtifact {
    pub document: ParsedDocument,
    pub semantics: Option<DocumentSemantics>,
}

impl ParsedArtifact {
    pub fn new(document: ParsedDocument, semantics: Option<DocumentSemantics>) -> Self {
        Self {
            document,
            semantics,
        }
    }
}
