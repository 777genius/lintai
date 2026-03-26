use std::collections::BTreeMap;

use lintai_api::{Category, Confidence, Severity};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::Deserialize;

use crate::OutputFormat;
use lintai_api::{ArtifactKind, CapabilityConflictMode, CapabilityProfile, SourceFormat};

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub(crate) struct RawRootConfig {
    pub(super) project: Option<RawProject>,
    pub(super) files: Option<RawFiles>,
    pub(super) categories: Option<BTreeMap<Category, Severity>>,
    #[schemars(schema_with = "rules_schema")]
    pub(super) rules: Option<toml::Value>,
    pub(super) overrides: Option<Vec<RawOverride>>,
    pub(super) detection: Option<RawDetection>,
    pub(super) suppress: Option<RawSuppress>,
    pub(super) output: Option<RawOutput>,
    pub(super) ci: Option<RawCi>,
    pub(super) capabilities: Option<CapabilityProfile>,
    pub(super) policy: Option<RawPolicy>,
    #[schemars(schema_with = "reserved_object_schema")]
    pub(super) extends: Option<toml::Value>,
    #[schemars(schema_with = "reserved_array_schema")]
    pub(super) plugins: Option<toml::Value>,
    #[schemars(schema_with = "reserved_object_schema")]
    pub(super) cache: Option<toml::Value>,
    #[schemars(schema_with = "reserved_object_schema")]
    pub(super) fix: Option<toml::Value>,
    #[schemars(schema_with = "reserved_object_schema")]
    pub(super) disallowed: Option<toml::Value>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub(crate) struct RawProject {
    pub(super) root: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub(crate) struct RawFiles {
    pub(super) include: Option<Vec<String>>,
    pub(super) exclude: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub(crate) struct RawOverride {
    pub(super) files: Vec<String>,
    pub(super) categories: Option<BTreeMap<Category, Severity>>,
    pub(super) rules: Option<BTreeMap<String, Severity>>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub(crate) struct RawSuppress {
    pub(super) require_reason: Option<bool>,
    pub(super) report_unused: Option<bool>,
    pub(super) max_per_file: Option<usize>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub(crate) struct RawOutput {
    pub(super) format: Option<OutputFormat>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub(crate) struct RawCi {
    pub(super) min_confidence: Option<Confidence>,
    pub(super) fail_on: Option<Severity>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub(crate) struct RawPolicy {
    pub(super) capability_conflicts: Option<CapabilityConflictMode>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub(crate) struct RawDetection {
    pub(super) overrides: Option<Vec<RawDetectionOverride>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawDetectionOverride {
    pub(super) files: Vec<String>,
    pub(super) kind: ArtifactKind,
    pub(super) format: SourceFormat,
}

fn rules_schema(generator: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": generator.subschema_for::<Severity>()
            },
            {
                "type": "object",
                "description": "rule parameters are reserved but unsupported in this release"
            }
        ]
    })
}

fn reserved_object_schema(_generator: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "type": "object",
        "description": "reserved but unsupported in this release"
    })
}

fn reserved_array_schema(_generator: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "type": "array",
        "description": "reserved but unsupported in this release"
    })
}
