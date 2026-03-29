use std::collections::BTreeSet;

use crate::known_scan::{KnownScope, ScanKnownArgs};

use super::common::{
    next_flag_value, normalize_client_filter, parse_known_scope, parse_output_format,
    unexpected_extra_argument, unknown_flag,
};

pub(crate) fn parse_scan_known_args(
    args: impl Iterator<Item = String>,
) -> Result<ScanKnownArgs, String> {
    let mut format_override = None;
    let mut scope = KnownScope::Both;
    let mut client_filters = BTreeSet::new();
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        if let Some(value) = next_flag_value("--format", &arg, &mut args)? {
            format_override = Some(parse_output_format(&value)?);
            continue;
        }
        if let Some(value) = next_flag_value("--scope", &arg, &mut args)? {
            scope = parse_known_scope(&value)?;
            continue;
        }
        if let Some(value) = next_flag_value("--client", &arg, &mut args)? {
            client_filters.insert(normalize_client_filter(&value));
            continue;
        }

        if arg.starts_with('-') {
            return Err(unknown_flag(&arg));
        }
        return Err(unexpected_extra_argument(&arg));
    }

    Ok(ScanKnownArgs {
        format_override,
        scope,
        client_filters,
    })
}
