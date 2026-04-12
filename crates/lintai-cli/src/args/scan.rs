use std::path::PathBuf;

use crate::args::ScanArgs;

use super::common::{
    next_flag_value, parse_color_mode, parse_output_format, push_preset_id,
    unexpected_extra_argument, unknown_flag,
};

pub(crate) fn parse_scan_args(args: impl Iterator<Item = String>) -> Result<ScanArgs, String> {
    let mut target = None;
    let mut format_override = None;
    let mut preset_ids = Vec::new();
    let mut color_mode = crate::output::ColorMode::Auto;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        if let Some(value) = next_flag_value("--format", &arg, &mut args)? {
            format_override = Some(parse_output_format(&value)?);
            continue;
        }

        if let Some(value) = next_flag_value("--color", &arg, &mut args)? {
            color_mode = parse_color_mode(&value)?;
            continue;
        }

        if let Some(value) = next_flag_value("--preset", &arg, &mut args)? {
            push_preset_id(&mut preset_ids, &value);
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
        preset_ids,
        color_mode,
    })
}
