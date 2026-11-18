use std::process::ExitCode;

fn main() -> ExitCode {
    let config = harness::config_from_env();
    match harness::execute(&config) {
        Ok(summary) if summary.ok => ExitCode::SUCCESS,
        Ok(summary) => {
            eprintln!("{}", summary.detail);
            ExitCode::from(1)
        }
        Err(err) => {
            eprintln!("harness: {err:#}");
            ExitCode::from(1)
        }
    }
}
