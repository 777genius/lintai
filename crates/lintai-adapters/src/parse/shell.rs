use lintai_api::{DocumentSemantics, ParsedDocument, RegionKind, ShellSemantics, Span, TextRegion};

use crate::ParsedArtifact;

pub fn parse(input: &str) -> ParsedArtifact {
    let lines = input.lines().map(str::to_owned).collect::<Vec<_>>();

    ParsedArtifact::new(
        ParsedDocument::new(
            vec![TextRegion::new(
                Span::new(0, input.len()),
                RegionKind::Normal,
            )],
            None,
        ),
        Some(DocumentSemantics::Shell(ShellSemantics::new(lines))),
    )
}
