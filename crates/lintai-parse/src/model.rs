use lintai_api::{FrontmatterFormat, ParsedDocument};
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseDiagnostic {
    pub message: String,
}

impl ParseDiagnostic {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MarkdownParse {
    pub document: ParsedDocument,
    pub raw_frontmatter: Option<String>,
    pub frontmatter_format: Option<FrontmatterFormat>,
    pub frontmatter_value: Option<Value>,
    pub diagnostics: Vec<ParseDiagnostic>,
}

impl MarkdownParse {
    pub fn new(
        document: ParsedDocument,
        raw_frontmatter: Option<String>,
        frontmatter_format: Option<FrontmatterFormat>,
        frontmatter_value: Option<Value>,
        diagnostics: Vec<ParseDiagnostic>,
    ) -> Self {
        Self {
            document,
            raw_frontmatter,
            frontmatter_format,
            frontmatter_value,
            diagnostics,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonParse {
    pub document: ParsedDocument,
    pub value: Value,
}

impl JsonParse {
    pub fn new(document: ParsedDocument, value: Value) -> Self {
        Self { document, value }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ShellParse {
    pub document: ParsedDocument,
    pub lines: Vec<String>,
}

impl ShellParse {
    pub fn new(document: ParsedDocument, lines: Vec<String>) -> Self {
        Self { document, lines }
    }
}
