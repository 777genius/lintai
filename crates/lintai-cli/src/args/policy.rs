use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::known_scan::InventoryOsScope;
use crate::policy_os::PolicyOsArgs;

use super::common::{
    next_flag_value, normalize_client_filter, parse_inventory_scope, parse_output_format,
    unexpected_extra_argument, unknown_flag,
};

pub(crate) fn parse_policy_os_args(
    args: impl Iterator<Item = String>,
) -> Result<PolicyOsArgs, String> {
    let mut format_override = None;
    let mut scope = InventoryOsScope::Both;
    let mut client_filters = BTreeSet::new();
    let mut path_root = None;
    let mut policy_path = None;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        if let Some(value) = next_flag_value("--format", &arg, &mut args)? {
            format_override = Some(parse_output_format(&value)?);
            continue;
        }
        if let Some(value) = next_flag_value("--scope", &arg, &mut args)? {
            scope = parse_inventory_scope(&value)?;
            continue;
        }
        if let Some(value) = next_flag_value("--client", &arg, &mut args)? {
            client_filters.insert(normalize_client_filter(&value));
            continue;
        }
        if let Some(value) = next_flag_value("--path-root", &arg, &mut args)? {
            path_root = Some(PathBuf::from(value));
            continue;
        }
        if let Some(value) = next_flag_value("--policy", &arg, &mut args)? {
            policy_path = Some(PathBuf::from(value));
            continue;
        }

        if arg.starts_with('-') {
            return Err(unknown_flag(&arg));
        }
        return Err(unexpected_extra_argument(&arg));
    }

    let policy_path = policy_path.ok_or_else(|| "missing required --policy".to_owned())?;
    Ok(PolicyOsArgs {
        format_override,
        scope,
        client_filters,
        path_root,
        policy_path,
    })
}
