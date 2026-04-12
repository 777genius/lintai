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
    let args = args.collect::<Vec<_>>();

    match command.as_str() {
        "scan" => dispatch_command("scan", args, |args| {
            commands::scan::run(&current_dir, args.into_iter())
        }),
        "scan-known" => dispatch_command("scan-known", args, |args| {
            commands::scan_known::run(&current_dir, args.into_iter())
        }),
        "inventory-os" => dispatch_command("inventory-os", args, |args| {
            commands::inventory_os::run(args.into_iter())
        }),
        "policy-os" => dispatch_command("policy-os", args, |args| {
            commands::policy_os::run(args.into_iter())
        }),
        "advisory-db" => dispatch_command("advisory-db", args, |args| {
            commands::advisory_db::run(args.into_iter())
        }),
        "fix" => dispatch_command("fix", args, |args| {
            commands::fix::run(&current_dir, args.into_iter())
        }),
        "explain-config" => dispatch_command("explain-config", args, |args| {
            commands::explain_config::run(&current_dir, args.into_iter())
        }),
        "__provider-runner" => run_provider_runner(args.into_iter()),
        "config-schema" => {
            println!("{}", lintai_engine::config_schema_pretty());
            Ok(ExitCode::SUCCESS)
        }
        "help" | "--help" | "-h" => {
            if let Some(topic) = args.first() {
                if print_command_usage(topic) {
                    return Ok(ExitCode::SUCCESS);
                }
                return Err(format!("unknown command: {topic}"));
            }
            print_usage();
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command: {other}")),
    }
}

fn dispatch_command(
    command: &str,
    args: Vec<String>,
    run: impl FnOnce(Vec<String>) -> Result<ExitCode, String>,
) -> Result<ExitCode, String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        print_command_usage(command);
        return Ok(ExitCode::SUCCESS);
    }
    run(args)
}

fn print_usage() {
    println!("{}", usage_line("scan"));
    println!("                    [--format=sarif]");
    println!("{}", usage_line("scan-known"));
    println!("                    [--color=auto|always|never]");
    println!("                    [--format=text|json|sarif]");
    println!("{}", usage_line("inventory-os"));
    println!("                    [--color=auto|always|never]");
    println!("                    [--path-root DIR] [--write-baseline FILE]");
    println!("                    [--diff-against FILE] [--format=text|json|sarif]");
    println!("{}", usage_line("policy-os"));
    println!(
        "                    [--path-root DIR] [--format=text|json|sarif] [--color=auto|always|never]"
    );
    println!("{}", usage_line("advisory-db"));
    println!("{}", usage_line("fix"));
    println!("{}", usage_line("explain-config"));
    println!("{}", usage_line("config-schema"));
}

fn print_command_usage(command: &str) -> bool {
    let Some(line) = usage_line_opt(command) else {
        return false;
    };
    println!("{line}");
    match command {
        "scan" => println!("                    [--format=sarif]"),
        "scan-known" => {
            println!("                    [--color=auto|always|never]");
            println!("                    [--format=text|json|sarif]");
        }
        "inventory-os" => {
            println!("                    [--color=auto|always|never]");
            println!("                    [--path-root DIR] [--write-baseline FILE]");
            println!("                    [--diff-against FILE] [--format=text|json|sarif]");
        }
        "policy-os" => {
            println!(
                "                    [--path-root DIR] [--format=text|json|sarif] [--color=auto|always|never]"
            );
        }
        _ => {}
    }
    true
}

fn usage_line(command: &str) -> &'static str {
    usage_line_opt(command).expect("known command usage must exist")
}

fn usage_line_opt(command: &str) -> Option<&'static str> {
    match command {
        "scan" => Some(
            "lintai scan [path] [--preset NAME] [--format=text|json] [--color=auto|always|never]",
        ),
        "scan-known" => {
            Some("lintai scan-known [--scope=project|global|both] [--client NAME] [--preset NAME]")
        }
        "inventory-os" => {
            Some("lintai inventory-os [--scope=user|system|both] [--client NAME] [--preset NAME]")
        }
        "policy-os" => Some(
            "lintai policy-os --policy FILE [--scope=user|system|both] [--client NAME] [--preset NAME]",
        ),
        "advisory-db" => Some("lintai advisory-db export-bundled [output-file]"),
        "fix" => Some("lintai fix [path] [--apply] [--rule CODE]"),
        "explain-config" => Some("lintai explain-config <file>"),
        "config-schema" => Some("lintai config-schema"),
        _ => None,
    }
}
