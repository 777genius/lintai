use std::io::Read;
use std::process::ExitCode;

use lintai_runtime::{RunnerPhase, RunnerRequest, RunnerResponse};

use crate::builtin_providers::kind::BuiltInProviderKind;

pub(crate) fn run_provider_runner(args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    if args.into_iter().next().is_some() {
        return Err("provider runner does not accept extra arguments".to_owned());
    }

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("provider runner failed to read stdin: {error}"))?;
    let request: RunnerRequest<BuiltInProviderKind> = serde_json::from_str(&input)
        .map_err(|error| format!("provider runner request decode failed: {error}"))?;

    let provider = request.provider.instantiate();
    let result = match request.phase {
        RunnerPhase::File => provider.check_result(
            request
                .scan
                .as_ref()
                .ok_or_else(|| "provider runner missing file scan context".to_owned())?,
        ),
        RunnerPhase::Workspace => provider.check_workspace_result(
            request
                .workspace
                .as_ref()
                .ok_or_else(|| "provider runner missing workspace scan context".to_owned())?,
        ),
    };
    let response = RunnerResponse { result };
    serde_json::to_writer(std::io::stdout(), &response)
        .map_err(|error| format!("provider runner response encode failed: {error}"))?;
    Ok(ExitCode::SUCCESS)
}
