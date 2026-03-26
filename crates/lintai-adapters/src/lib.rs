mod adapter;
mod error;
mod model;
pub mod parse;

#[cfg(test)]
mod tests;

pub use detection::{DetectionRuleSpec, detection_rules};
pub use error::ParseError;
pub use model::ParsedArtifact;

mod detection;

use lintai_api::Artifact;

pub fn parse_document(artifact: &Artifact, content: &str) -> Result<ParsedArtifact, ParseError> {
    adapter::parse_document(artifact, content)
}
