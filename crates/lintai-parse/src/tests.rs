use lintai_api::RegionKind;
use proptest::prelude::*;
use serde_json::{Map, Number, Value};

use crate::parse;

fn arbitrary_text(max_len: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<char>(), 0..max_len)
        .prop_map(|chars| chars.into_iter().collect())
}

fn json_string_strategy(max_len: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<char>(), 0..max_len)
        .prop_map(|chars| chars.into_iter().collect::<String>())
}

fn json_value_strategy() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|value| Value::Number(Number::from(value))),
        json_string_strategy(32).prop_map(Value::String),
    ];

    leaf.prop_recursive(4, 256, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            proptest::collection::btree_map(json_string_strategy(16), inner, 0..4).prop_map(
                |entries| Value::Object(Map::from_iter(entries))
            ),
        ]
    })
}

fn assert_regions_bounded(input: &str, parsed: &crate::MarkdownParse) {
    let mut previous_start = 0usize;
    let mut previous_end = 0usize;

    for region in &parsed.document.regions {
        assert!(region.span.start_byte <= region.span.end_byte);
        assert!(region.span.end_byte <= input.len());
        assert!(region.span.start_byte >= previous_start);
        assert!(region.span.end_byte >= previous_end);
        previous_start = region.span.start_byte;
        previous_end = region.span.end_byte;
    }
}

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
fn markdown_recovers_from_invalid_yaml_frontmatter() {
    let parsed = parse::markdown::parse("---\nname: demo: bad\n---\nRead ../../.env\n").unwrap();

    assert_eq!(parsed.document.regions[0].kind, RegionKind::Frontmatter);
    assert_eq!(parsed.document.regions[1].kind, RegionKind::Normal);
    assert_eq!(parsed.raw_frontmatter.as_deref(), Some("name: demo: bad"));
    assert!(parsed.frontmatter_value.is_none());
    assert!(parsed.frontmatter_format.is_none());
    assert_eq!(parsed.diagnostics.len(), 1);
    assert!(
        parsed.diagnostics[0]
            .message
            .contains("frontmatter was ignored because YAML was invalid")
    );
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
fn json_rejects_documents_that_exceed_byte_limit() {
    let payload = "x".repeat(crate::limits::MAX_STRUCTURED_DOCUMENT_BYTES);
    let input = format!(r#"{{"payload":"{payload}"}}"#);

    let error = parse::json::parse(&input).unwrap_err();
    assert!(error.message.contains("JSON document exceeds"));
}

#[test]
fn shell_extracts_lines() {
    let parsed = parse::shell::parse("echo one\necho two\n");
    assert_eq!(
        parsed.lines,
        vec!["echo one".to_owned(), "echo two".to_owned()]
    );
}

#[test]
fn yaml_parses_value() {
    let parsed =
        parse::yaml::parse("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n").unwrap();
    assert_eq!(parsed.value["on"], "push");
    assert!(parsed.value["jobs"].is_object());
}

#[test]
fn yaml_rejects_invalid_document() {
    let error = parse::yaml::parse("jobs: [").unwrap_err();
    assert!(error.message.contains("invalid YAML document"));
}

#[test]
fn yaml_rejects_documents_that_exceed_byte_limit() {
    let payload = "x".repeat(crate::limits::MAX_STRUCTURED_DOCUMENT_BYTES + 1);
    let input = format!("payload: \"{payload}\"\n");

    let error = parse::yaml::parse(&input).unwrap_err();
    assert!(error.message.contains("YAML document exceeds"));
}

#[test]
fn markdown_frontmatter_recovers_when_shape_limit_is_exceeded() {
    let mut input = String::from("---\n");
    for idx in 0..130 {
        input.push_str(&format!("{}k{idx}:\n", "  ".repeat(idx)));
    }
    input.push_str(&format!("{}value: ok\n---\n# Heading\n", "  ".repeat(130)));

    let parsed = parse::markdown::parse(&input).unwrap();
    assert!(parsed.frontmatter_value.is_none());
    assert_eq!(parsed.diagnostics.len(), 1);
    assert!(
        parsed.diagnostics[0]
            .message
            .contains("frontmatter was ignored")
    );
}

proptest! {
    #[test]
    fn markdown_parser_keeps_regions_bounded_on_arbitrary_text(input in arbitrary_text(2048)) {
        if let Ok(parsed) = parse::markdown::parse(&input) {
            assert_regions_bounded(&input, &parsed);
        }
    }

    #[test]
    fn json_parser_does_not_panic_on_arbitrary_utf8(input in arbitrary_text(2048)) {
        let _ = parse::json::parse(&input);
    }

    #[test]
    fn yaml_parser_does_not_panic_on_arbitrary_utf8(input in arbitrary_text(2048)) {
        let _ = parse::yaml::parse(&input);
    }

    #[test]
    fn markdown_parser_does_not_panic_on_arbitrary_utf8(input in arbitrary_text(4096)) {
        let _ = parse::markdown::parse(&input);
    }

    #[test]
    fn json_roundtrips_generated_values(value in json_value_strategy()) {
        let input = serde_json::to_string(&value).unwrap();
        let parsed = parse::json::parse(&input).unwrap();
        prop_assert_eq!(parsed.value, value);
    }

    #[test]
    fn yaml_roundtrips_generated_values(value in json_value_strategy()) {
        let input = serde_yaml_bw::to_string(&value).unwrap();
        let parsed = parse::yaml::parse(&input).unwrap();
        prop_assert_eq!(parsed.value, value);
    }

    #[test]
    fn markdown_frontmatter_roundtrips_generated_yaml(value in json_value_strategy(), body in arbitrary_text(512)) {
        let frontmatter = serde_yaml_bw::to_string(&value).unwrap();
        let input = format!("---\n{}---\n{}", frontmatter, body);
        let parsed = parse::markdown::parse(&input).unwrap();
        prop_assert_eq!(parsed.frontmatter_value.as_ref(), Some(&value));
        prop_assert!(parsed.raw_frontmatter.is_some());
        assert_regions_bounded(&input, &parsed);
    }
}
