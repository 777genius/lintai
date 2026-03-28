use lintai_api::{FrontmatterFormat, ParsedDocument, RegionKind, Span, TextRegion};

use super::frontmatter;
use crate::{MarkdownParse, ParseError};

pub fn parse(input: &str) -> Result<MarkdownParse, ParseError> {
    let extraction = frontmatter::extract(input)?;
    let mut regions = Vec::new();
    let mut normal_start = 0usize;
    let mut code_block_start: Option<usize> = None;
    let mut html_comment_start: Option<usize> = None;
    let mut frontmatter_format = None;
    let mut frontmatter_value = None;
    let mut diagnostics = Vec::new();

    if let Some(raw_frontmatter) = extraction.raw.as_deref() {
        let frontmatter_end = extraction.body_start.min(input.len());
        regions.push(TextRegion::new(
            Span::new(0, frontmatter_end),
            RegionKind::Frontmatter,
        ));
        normal_start = frontmatter_end;
        match frontmatter::parse_yaml(raw_frontmatter) {
            Ok(value) => {
                frontmatter_format = Some(FrontmatterFormat::Yaml);
                frontmatter_value = Some(value);
            }
            Err(error) => {
                diagnostics.push(frontmatter::recovery_diagnostic(&error));
            }
        }
    }

    for (line_start, line_end, line) in line_spans(input, normal_start) {
        let trimmed = line.trim_start();
        let fence = trimmed.starts_with("```") || trimmed.starts_with("~~~");

        if let Some(block_start) = code_block_start {
            if fence {
                regions.push(TextRegion::new(
                    Span::new(block_start, line_end),
                    RegionKind::CodeBlock,
                ));
                code_block_start = None;
            }
            continue;
        }

        if let Some(comment_start) = html_comment_start {
            if trimmed.contains("-->") {
                regions.push(TextRegion::new(
                    Span::new(comment_start, line_end),
                    RegionKind::HtmlComment,
                ));
                html_comment_start = None;
            }
            continue;
        }

        if fence {
            code_block_start = Some(line_start);
            continue;
        }

        if trimmed.starts_with("<!--") {
            if trimmed.contains("-->") {
                regions.push(TextRegion::new(
                    Span::new(line_start, line_end),
                    RegionKind::HtmlComment,
                ));
            } else {
                html_comment_start = Some(line_start);
            }
            continue;
        }

        let kind = if trimmed.starts_with('#') {
            RegionKind::Heading
        } else if trimmed.starts_with('>') {
            RegionKind::Blockquote
        } else {
            RegionKind::Normal
        };

        regions.push(TextRegion::new(Span::new(line_start, line_end), kind));
    }

    if let Some(block_start) = code_block_start {
        regions.push(TextRegion::new(
            Span::new(block_start, input.len()),
            RegionKind::CodeBlock,
        ));
    }

    if let Some(comment_start) = html_comment_start {
        regions.push(TextRegion::new(
            Span::new(comment_start, input.len()),
            RegionKind::HtmlComment,
        ));
    }

    if regions.is_empty() {
        regions.push(TextRegion::new(
            Span::new(0, input.len()),
            RegionKind::Normal,
        ));
    }

    let raw_frontmatter = extraction.raw;
    Ok(MarkdownParse::new(
        ParsedDocument::new(regions, raw_frontmatter.clone()),
        raw_frontmatter,
        frontmatter_format,
        frontmatter_value,
        diagnostics,
    ))
}

fn line_spans(input: &str, offset: usize) -> Vec<(usize, usize, &str)> {
    let mut spans = Vec::new();
    let mut start = offset;
    let mut cursor = offset;

    while cursor < input.len() {
        if let Some(relative_end) = input[cursor..].find('\n') {
            let end = cursor + relative_end + 1;
            spans.push((start, end, &input[start..end]));
            start = end;
            cursor = end;
        } else {
            spans.push((start, input.len(), &input[start..]));
            break;
        }
    }

    spans
}
