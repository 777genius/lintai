use lintai_api::Span;

pub(crate) const GITHUB_COPILOT_INSTRUCTIONS_CHAR_LIMIT: usize = 4000;

pub(crate) fn is_github_copilot_instruction_path(normalized_path: &str) -> bool {
    normalized_path == ".github/copilot-instructions.md"
        || (normalized_path.starts_with(".github/instructions/")
            && normalized_path.ends_with(".instructions.md"))
}

pub(crate) fn leading_markdown_file_relative_span(content: &str) -> Option<Span> {
    if content.is_empty() {
        return None;
    }

    let end = content.find('\n').unwrap_or(content.len()).max(1);
    Some(Span::new(0, end))
}
