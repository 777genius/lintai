use lintai_api::RegionKind;

use crate::parse;

#[test]
fn markdown_keeps_frontmatter_as_region_and_raw_value() {
    let parsed =
        parse::markdown::parse("---\nname: demo\ncapabilities:\n  exec: shell\n---\n# Heading\n")
            .unwrap();

    assert_eq!(parsed.document.regions.len(), 2);
    assert_eq!(
        parsed.raw_frontmatter.as_deref(),
        Some("name: demo\ncapabilities:\n  exec: shell")
    );
    assert_eq!(parsed.document.regions[1].kind, RegionKind::Heading);
    assert!(parsed.frontmatter_value.is_some());
}

#[test]
fn markdown_classifies_code_blocks_and_html_comments() {
    let parsed = parse::markdown::parse("<!-- note -->\n```sh\necho hi\n```\n").unwrap();

    assert!(
        parsed
            .document
            .regions
            .iter()
            .any(|region| region.kind == RegionKind::HtmlComment)
    );
    assert!(
        parsed
            .document
            .regions
            .iter()
            .any(|region| region.kind == RegionKind::CodeBlock)
    );
}

#[test]
fn markdown_rejects_unterminated_frontmatter() {
    let error = parse::markdown::parse("---\nname: demo\n# Heading\n").unwrap_err();

    assert!(error.message.contains("unterminated frontmatter"));
}

#[test]
fn markdown_supports_bom_prefixed_frontmatter() {
    let parsed = parse::markdown::parse("\u{feff}---\nname: demo\n---\n# Heading\n").unwrap();

    assert_eq!(parsed.raw_frontmatter.as_deref(), Some("name: demo"));
}

#[test]
fn json_parses_value() {
    let parsed = parse::json::parse(r#"{"url":"http://example.test"}"#).unwrap();
    assert_eq!(parsed.value["url"], "http://example.test");
}

#[test]
fn json_rejects_invalid_document() {
    let error = parse::json::parse("{").unwrap_err();
    assert!(error.message.contains("invalid JSON document"));
}

#[test]
fn shell_extracts_lines() {
    let parsed = parse::shell::parse("echo one\necho two\n");
    assert_eq!(
        parsed.lines,
        vec!["echo one".to_owned(), "echo two".to_owned()]
    );
}
