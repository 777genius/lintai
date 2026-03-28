mod adapter;
mod error;
mod model;
mod surface;

#[cfg(test)]
mod tests;

pub use detection::{DetectionRuleSpec, detection_rules};
pub use error::ParseError;
pub use model::ParsedArtifact;
pub use surface::route_for_artifact_kind;

mod detection;

use lintai_api::Artifact;

pub fn parse_document(artifact: &Artifact, content: &str) -> Result<ParsedArtifact, ParseError> {
    adapter::parse_document(artifact, content)
}
