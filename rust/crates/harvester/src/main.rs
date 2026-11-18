//! Read-only public certificate collector.
//!
//! The harvester writes the leaf, chain metadata, and SPKI. It does not
//! accept a private key and it does not call the synthetic oracle.

use anyhow::{bail, Result};
use serde_json::json;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("harvester: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|arg| {
        arg == "--key" || arg == "--private-key" || arg == "-key" || arg.ends_with(".key")
    }) {
        bail!("harvester does not accept private keys");
    }
    let host = flag(&args, "--host").ok_or_else(|| anyhow::anyhow!("--host is required"))?;
    let port: u16 = flag(&args, "--port").unwrap_or("443").parse()?;
    let servername = flag(&args, "--servername").unwrap_or(host).to_string();
    let out = PathBuf::from(flag(&args, "--out").unwrap_or("baseline"));
    fs::create_dir_all(&out)?;
    let (pem, leaf) = svc2::fetch_public(host, port, &servername)?;
    if svc2::contains_private_key(&String::from_utf8_lossy(&pem)) {
        bail!("refusing to store private key material");
    }
    fs::write(out.join("leaf.pem"), &pem)?;
    let metadata = json!({
        "host": host,
        "port": port,
        "servername": servername,
        "leaf_spki_sha256": leaf.spki_sha256,
        "signature_algorithm": leaf.signature_algorithm,
        "key_type": leaf.key_type,
        "bits": leaf.bits,
        "exponent_bits": leaf.exponent_bits,
        "curve": leaf.curve,
        "san": leaf.san_dns,
        "issuer": leaf.issuer,
        "sct_present": leaf.sct_present,
        "possible_cdn_edge": leaf.possible_cdn_edge,
        "private_key_present": false
    });
    fs::write(
        out.join("metadata.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&metadata)?);
    Ok(())
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|item| item == name)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_flag_is_rejected() {
        let err = (|| -> Result<()> {
            let args = vec![
                "--host".into(),
                "example.com".into(),
                "--key".into(),
                "a.key".into(),
            ];
            if args
                .iter()
                .any(|arg: &String| arg == "--key" || arg.ends_with(".key"))
            {
                bail!("harvester does not accept private keys");
            }
            Ok(())
        })();
        assert!(err.is_err());
    }
}
