use lintai_api::Artifact;

use crate::surface::{fallback_parse, surface_spec};
use crate::{ParseError, ParsedArtifact};

pub(crate) fn parse_document(
    artifact: &Artifact,
    content: &str,
) -> Result<ParsedArtifact, ParseError> {
    match surface_spec(artifact.kind, artifact.format) {
        Some(spec) => (spec.parse_fn)(content),
        None => Ok(fallback_parse(content)),
    }
}
