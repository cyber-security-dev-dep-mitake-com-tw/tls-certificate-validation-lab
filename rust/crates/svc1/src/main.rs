use anyhow::Result;
use std::process::ExitCode;
use std::sync::mpsc;

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("svc1: {err:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run() -> Result<()> {
    let config = svc1::config_from_env();
    if config.domain.is_empty() || config.domain.contains(['/', ':', ' ']) {
        anyhow::bail!("LAB_DOMAIN must be a bare DNS name");
    }
    let issued = svc1::prepare(&config)?;
    let running = svc1::serve(&config, &issued)?;
    let (tx, rx) = mpsc::channel();
    let _ = ctrlc::set_handler(move || {
        let _ = tx.send(());
    });
    let _ = rx.recv();
    running.shutdown();
    Ok(())
}
