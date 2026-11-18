use harness::ExecuteConfig;
use std::path::{Path, PathBuf};
use std::process::Command;
use svc1::{serve, LabConfig};

#[test]
fn lab_matrix_matches_ground_truth() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let possession = build_possession(&repo.join("zig/possession"));
    let tmp = tempfile::tempdir().unwrap();
    let config = LabConfig {
        domain: "tls-lab.example.test".into(),
        state_dir: tmp.path().join("state"),
        trust_dir: tmp.path().join("trust"),
        bind: "127.0.0.1".into(),
        advertised_host: "127.0.0.1".into(),
        port_offset: 20000,
        generate_script: repo.join("julia/generate.jl"),
        possession_bin: possession,
    };
    let issued = svc1::prepare(&config).expect("issue lab");
    let running = serve(&config, &issued).expect("serve lab");
    let summary = harness::execute(&ExecuteConfig {
        domain: config.domain.clone(),
        host: config.advertised_host.clone(),
        ca_file: issued.trusted_root.clone(),
        policy_dir: config.trust_dir.clone(),
        possession_leaf: issued.possession_cert.clone(),
        report_dir: tmp.path().join("reports"),
        analyze_script: repo.join("julia/analyze.jl"),
        oracle_script: repo.join("julia/oracle.jl"),
        port_offset: config.port_offset,
        llm_provider: "scripted".into(),
    })
    .expect("matrix");
    running.shutdown();
    if !summary.ok {
        panic!("{}", summary.detail);
    }
}

fn build_possession(dir: &Path) -> PathBuf {
    let zig = std::env::var("ZIG").unwrap_or_else(|_| {
        let known = "/tmp/zig-lab/zig-aarch64-macos-0.17.1/zig";
        if Path::new(known).exists() {
            known.to_string()
        } else {
            "zig".to_string()
        }
    });
    let status = Command::new(zig)
        .arg("build")
        .arg("-Doptimize=ReleaseSafe")
        .current_dir(dir)
        .status()
        .expect("zig");
    assert!(status.success(), "zig build failed");
    dir.join("zig-out/bin/possession")
}
