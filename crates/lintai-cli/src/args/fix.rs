use std::path::PathBuf;

use crate::args::FixArgs;

use super::common::{next_flag_value, unexpected_extra_argument, unknown_flag};

pub(crate) fn parse_fix_args(args: impl Iterator<Item = String>) -> Result<FixArgs, String> {
    let mut target = None;
    let mut apply = false;
    let mut rule_filters = Vec::new();
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        if arg == "--apply" {
            apply = true;
            continue;
        }
        if let Some(value) = next_flag_value("--rule", &arg, &mut args)? {
            rule_filters.push(value);
            continue;
        }

        if arg.starts_with('-') {
            return Err(unknown_flag(&arg));
        }

        match target {
            Some(_) => return Err(unexpected_extra_argument(&arg)),
            None => target = Some(PathBuf::from(arg)),
        }
    }

    Ok(FixArgs {
        target: target.unwrap_or_else(|| PathBuf::from(".")),
        apply,
        rule_filters,
    })
}
