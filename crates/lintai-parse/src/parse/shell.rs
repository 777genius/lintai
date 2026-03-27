use lintai_api::{ParsedDocument, RegionKind, Span, TextRegion};

use crate::ShellParse;

pub fn parse(input: &str) -> ShellParse {
    let lines = input.lines().map(str::to_owned).collect::<Vec<_>>();

    ShellParse::new(
        ParsedDocument::new(
            vec![TextRegion::new(
                Span::new(0, input.len()),
                RegionKind::Normal,
            )],
            None,
        ),
        lines,
    )
}
