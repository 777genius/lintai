use std::collections::BTreeSet;
use std::path::PathBuf;

use lintai_api::Severity;
use serde::{Deserialize, Serialize};

pub(crate) const MACHINE_POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PolicyAction {
    Off,
    Warn,
    Deny,
}

impl PolicyAction {
    pub(crate) fn as_severity(self) -> Option<Severity> {
        match self {
            Self::Off => None,
            Self::Warn => Some(Severity::Warn),
            Self::Deny => Some(Severity::Deny),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyOsArgs {
    pub(crate) format_override: Option<lintai_engine::OutputFormat>,
    pub(crate) scope: crate::known_scan::InventoryOsScope,
    pub(crate) client_filters: BTreeSet<String>,
    pub(crate) preset_ids: Vec<String>,
    pub(crate) color_mode: crate::output::ColorMode,
    pub(crate) path_root: Option<PathBuf>,
    pub(crate) policy_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachinePolicyFile {
    pub(crate) schema_version: u32,
    #[serde(default)]
    pub(crate) rules: MachinePolicyRules,
    #[serde(default)]
    pub(crate) allow: MachinePolicyAllow,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachinePolicyRules {
    #[serde(default)]
    pub(crate) global_shell_wrapper_mcp: Option<PolicyAction>,
    #[serde(default)]
    pub(crate) plaintext_auth: Option<PolicyAction>,
    #[serde(default)]
    pub(crate) trust_disable: Option<PolicyAction>,
    #[serde(default)]
    pub(crate) high_risk_discovered_only: Option<PolicyAction>,
    #[serde(default)]
    pub(crate) unapproved_client: Option<PolicyAction>,
    #[serde(default)]
    pub(crate) unapproved_base_dir: Option<PolicyAction>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachinePolicyAllow {
    #[serde(default)]
    pub(crate) clients: Vec<String>,
    #[serde(default)]
    pub(crate) base_dirs: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
pub(crate) struct MachinePolicy {
    pub(crate) rules: EvaluatedPolicyRules,
    pub(crate) allow_clients: BTreeSet<String>,
    pub(crate) allow_base_dirs: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct EvaluatedPolicyRules {
    pub(crate) global_shell_wrapper_mcp: PolicyAction,
    pub(crate) plaintext_auth: PolicyAction,
    pub(crate) trust_disable: PolicyAction,
    pub(crate) high_risk_discovered_only: PolicyAction,
    pub(crate) unapproved_client: PolicyAction,
    pub(crate) unapproved_base_dir: PolicyAction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct PolicyMatch {
    pub(crate) policy_id: String,
    pub(crate) severity: String,
    pub(crate) client: String,
    pub(crate) surface: String,
    pub(crate) path: String,
    pub(crate) message: String,
    pub(crate) evidence: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub(crate) matched_findings: Vec<String>,
    pub(crate) mode: String,
    pub(crate) risk_level: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub(crate) struct PolicyStats {
    pub(crate) deny_matches: usize,
    pub(crate) warn_matches: usize,
    pub(crate) matched_roots: usize,
    pub(crate) matched_findings: usize,
}
