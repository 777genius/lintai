use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::known_scan::{InventoryOsArgs, InventoryOsScope};

use super::common::{
    next_flag_value, normalize_client_filter, parse_inventory_scope, parse_output_format,
    unexpected_extra_argument, unknown_flag,
};

pub(crate) fn parse_inventory_os_args(
    args: impl Iterator<Item = String>,
) -> Result<InventoryOsArgs, String> {
    let mut format_override = None;
    let mut scope = InventoryOsScope::Both;
    let mut client_filters = BTreeSet::new();
    let mut path_root = None;
    let mut write_baseline = None;
    let mut diff_against = None;
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
        if let Some(value) = next_flag_value("--write-baseline", &arg, &mut args)? {
            write_baseline = Some(PathBuf::from(value));
            continue;
        }
        if let Some(value) = next_flag_value("--diff-against", &arg, &mut args)? {
            diff_against = Some(PathBuf::from(value));
            continue;
        }

        if arg.starts_with('-') {
            return Err(unknown_flag(&arg));
        }
        return Err(unexpected_extra_argument(&arg));
    }

    Ok(InventoryOsArgs {
        format_override,
        scope,
        client_filters,
        path_root,
        write_baseline,
        diff_against,
    })
}
