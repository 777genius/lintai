use std::path::PathBuf;

use crate::args::ScanArgs;

use super::common::{
    next_flag_value, parse_output_format, unexpected_extra_argument, unknown_flag,
};

pub(crate) fn parse_scan_args(args: impl Iterator<Item = String>) -> Result<ScanArgs, String> {
    let mut target = None;
    let mut format_override = None;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        if let Some(value) = next_flag_value("--format", &arg, &mut args)? {
            format_override = Some(parse_output_format(&value)?);
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

    Ok(ScanArgs {
        target: target.unwrap_or_else(|| PathBuf::from(".")),
        format_override,
    })
}
