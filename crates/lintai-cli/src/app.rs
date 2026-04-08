use std::process::ExitCode;

use crate::builtin_providers::run_provider_runner;
use crate::commands;

pub fn run() -> Result<ExitCode, String> {
    let current_dir =
        std::env::current_dir().map_err(|error| format!("cwd resolution failed: {error}"))?;
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Ok(ExitCode::SUCCESS);
    };

    match command.as_str() {
        "scan" => commands::scan::run(&current_dir, args),
        "scan-known" => commands::scan_known::run(&current_dir, args),
        "inventory-os" => commands::inventory_os::run(args),
        "policy-os" => commands::policy_os::run(args),
        "advisory-db" => commands::advisory_db::run(args),
        "fix" => commands::fix::run(&current_dir, args),
        "explain-config" => commands::explain_config::run(&current_dir, args),
        "__provider-runner" => run_provider_runner(args),
        "config-schema" => {
            println!("{}", lintai_engine::config_schema_pretty());
            Ok(ExitCode::SUCCESS)
        }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command: {other}")),
    }
}

fn print_usage() {
    println!("lintai scan [path] [--preset NAME] [--format=text|json]");
    println!("                    [--format=sarif]");
    println!("lintai scan-known [--scope=project|global|both] [--client NAME] [--preset NAME]");
    println!("                    [--format=text|json|sarif]");
    println!("lintai inventory-os [--scope=user|system|both] [--client NAME] [--preset NAME]");
    println!("                    [--path-root DIR] [--write-baseline FILE]");
    println!("                    [--diff-against FILE] [--format=text|json|sarif]");
    println!(
        "lintai policy-os --policy FILE [--scope=user|system|both] [--client NAME] [--preset NAME]"
    );
    println!("                    [--path-root DIR] [--format=text|json|sarif]");
    println!("lintai advisory-db export-bundled [output-file]");
    println!("lintai advisory-db update --input FILE --output FILE");
    println!("lintai fix [path] [--apply] [--rule CODE]");
    println!("lintai explain-config <file>");
    println!("lintai config-schema");
}
