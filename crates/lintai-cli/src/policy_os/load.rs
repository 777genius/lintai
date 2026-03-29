use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use lintai_engine::normalize_path_string;

use crate::policy_os::model::{
    EvaluatedPolicyRules, MACHINE_POLICY_SCHEMA_VERSION, MachinePolicy, MachinePolicyFile,
    PolicyAction,
};

pub(crate) fn load_machine_policy(path: &Path) -> Result<MachinePolicy, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("failed to read policy {}: {error}", path.display()))?;
    let parsed: MachinePolicyFile = toml::from_str(&text)
        .map_err(|error| format!("failed to parse policy {}: {error}", path.display()))?;
    if parsed.schema_version != MACHINE_POLICY_SCHEMA_VERSION {
        return Err(format!(
            "unsupported policy schema_version {} in {} (expected {})",
            parsed.schema_version,
            path.display(),
            MACHINE_POLICY_SCHEMA_VERSION
        ));
    }

    let allow_clients = parsed
        .allow
        .clients
        .into_iter()
        .map(|client| client.trim().to_ascii_lowercase())
        .filter(|client| !client.is_empty())
        .collect::<BTreeSet<_>>();
    let allow_base_dirs = parsed
        .allow
        .base_dirs
        .into_iter()
        .map(|path| {
            if !path.is_absolute() {
                return Err(format!(
                    "policy allow.base_dirs must use absolute paths: {}",
                    path.display()
                ));
            }
            let normalized = fs::canonicalize(&path)
                .map(|canonical| normalize_path_string(&canonical))
                .unwrap_or_else(|_| normalize_path_string(&path));
            Ok(normalized)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let rules = EvaluatedPolicyRules {
        global_shell_wrapper_mcp: parsed
            .rules
            .global_shell_wrapper_mcp
            .unwrap_or(PolicyAction::Off),
        plaintext_auth: parsed.rules.plaintext_auth.unwrap_or(PolicyAction::Off),
        trust_disable: parsed.rules.trust_disable.unwrap_or(PolicyAction::Off),
        high_risk_discovered_only: parsed
            .rules
            .high_risk_discovered_only
            .unwrap_or(PolicyAction::Off),
        unapproved_client: parsed.rules.unapproved_client.unwrap_or(PolicyAction::Off),
        unapproved_base_dir: parsed
            .rules
            .unapproved_base_dir
            .unwrap_or(PolicyAction::Off),
    };

    if !matches!(rules.unapproved_client, PolicyAction::Off) && allow_clients.is_empty() {
        return Err("policy rule unapproved_client requires allow.clients".to_owned());
    }
    if !matches!(rules.unapproved_base_dir, PolicyAction::Off) && allow_base_dirs.is_empty() {
        return Err("policy rule unapproved_base_dir requires allow.base_dirs".to_owned());
    }

    Ok(MachinePolicy {
        rules,
        allow_clients,
        allow_base_dirs,
    })
}
