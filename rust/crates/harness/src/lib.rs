//! Ground truth stays in this crate. Detector calls do not receive it.

use anyhow::Result;
use oracle_client::OracleClient;
use policy::{port, Policy, CASES};
use rea::{
    apply_advisory, provider_from_name, AdvisoryRequest, DeterministicRea, ReaAdvisor,
    VerdictSnapshot,
};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use svc2::{inspect_tls, observation_from, offline_chain_valid, InspectRequest, JuliaAnalyzer};

#[derive(Clone, Copy, Debug)]
struct Expectation {
    handshake: &'static str,
    certificate_status: &'static str,
    risk_class: Option<&'static str>,
    protocol_policy: &'static str,
}

fn expect(case: &str, version: &str) -> Expectation {
    let protocol_policy = if version == "1.1" {
        "DEPRECATED"
    } else {
        "ALLOWED"
    };
    let completed = |certificate_status, risk_class| Expectation {
        handshake: "COMPLETED",
        certificate_status,
        risk_class,
        protocol_policy,
    };
    match (case, version) {
        ("good", _) => completed("VALID", None),
        ("self_signed", _) => completed("SELF_SIGNED", Some("INVALID_CERTIFICATE")),
        ("rogue_ca", _) => completed("UNKNOWN_ISSUER", Some("INVALID_CERTIFICATE")),
        ("wrong_san", _) => completed("HOSTNAME_MISMATCH", Some("INVALID_CERTIFICATE")),
        ("expired", _) => completed("EXPIRED", Some("INVALID_CERTIFICATE")),
        ("future", _) => completed("NOT_YET_VALID", Some("INVALID_CERTIFICATE")),
        ("wrong_eku", _) => completed("INVALID_PURPOSE", Some("INVALID_CERTIFICATE")),
        ("unapproved_leaf", _) => completed("KEY_NOT_APPROVED", Some("VALID_BUT_UNAUTHORIZED")),
        ("possession_failed", _) => Expectation {
            handshake: "REJECTED",
            certificate_status: "HANDSHAKE_REJECTED",
            risk_class: None,
            protocol_policy,
        },
        ("compromised_endpoint", _) => {
            completed("UNAUTHORIZED_ENDPOINT", Some("VALID_BUT_UNAUTHORIZED"))
        }
        (
            "weak_rsa" | "shared_prime_a" | "shared_prime_b" | "roca_fingerprint" | "wiener_rsa"
            | "fermat_rsa",
            "1.3",
        ) => Expectation {
            // TLS 1.3 rejects these 512-bit RSA authentication keys before a
            // certificate verdict is available.
            handshake: "REJECTED",
            certificate_status: "HANDSHAKE_REJECTED",
            risk_class: None,
            protocol_policy,
        },
        ("weak_rsa", _) => completed("WEAK_KEY", Some("WEAK_CRYPTOGRAPHY")),
        ("shared_prime_a" | "shared_prime_b", _) => {
            completed("SHARED_FACTOR", Some("WEAK_CRYPTOGRAPHY"))
        }
        ("roca_fingerprint", _) => completed("ROCA_FINGERPRINT", Some("WEAK_CRYPTOGRAPHY")),
        ("sha1_cert", _) => completed("WEAK_SIGNATURE", Some("WEAK_CRYPTOGRAPHY")),
        ("wiener_rsa", _) => completed("STRUCTURAL_WEAKNESS", Some("WEAK_CRYPTOGRAPHY")),
        ("fermat_rsa", _) => completed("WEAK_KEY", Some("WEAK_CRYPTOGRAPHY")),
        ("nonce_reuse", _) => completed("NONCE_REUSE", Some("WEAK_CRYPTOGRAPHY")),
        _ => Expectation {
            handshake: "REJECTED",
            certificate_status: "HANDSHAKE_REJECTED",
            risk_class: None,
            protocol_policy,
        },
    }
}

pub struct ExecuteConfig {
    pub domain: String,
    pub host: String,
    pub ca_file: PathBuf,
    pub policy_dir: PathBuf,
    pub possession_leaf: PathBuf,
    pub report_dir: PathBuf,
    pub analyze_script: PathBuf,
    pub oracle_script: PathBuf,
    pub port_offset: u16,
    pub llm_provider: String,
}

#[derive(Clone, Debug, Serialize)]
struct Row {
    scenario: String,
    requested_tls: String,
    negotiated_tls: Option<String>,
    handshake: String,
    expected_handshake: String,
    certificate_status: String,
    expected_certificate_status: String,
    risk_class: Option<String>,
    expected_risk_class: Option<String>,
    protocol_policy: String,
    overall_accept: bool,
    handshake_correct: bool,
    reason_correct: bool,
    risk_correct: bool,
    findings: Vec<String>,
    offline_certificate_valid: Option<bool>,
    advisory_source: String,
    threat_event: String,
    llm_threat_event: Option<String>,
    verdict_preserved: bool,
}

pub struct Summary {
    pub ok: bool,
    pub detail: String,
}

pub fn execute(config: &ExecuteConfig) -> Result<Summary> {
    let policy = Policy::load(&config.policy_dir).map_err(|err| anyhow::anyhow!("{err}"))?;
    let mut analyzer = JuliaAnalyzer::start(&config.analyze_script)?;
    let mut oracle = OracleClient::start(&config.oracle_script)?;
    oracle.refuse_harvested()?;
    let offline = offline_chain_valid(
        &fs::read(&config.ca_file)?,
        &fs::read(&config.possession_leaf)?,
    )?;
    let mut inspections = Vec::new();
    let mut labels = Vec::new();
    for case in CASES {
        for version in case.versions {
            let inspection = inspect_tls(InspectRequest {
                host: &config.host,
                port: port(case, version, config.port_offset).expect("port"),
                servername: &config.domain,
                version,
                ca_file: &config.ca_file,
                policy: &policy,
                lab_mode: true,
                analyzer: &mut analyzer,
            })?;
            labels.push((case.name, *version));
            inspections.push(inspection);
        }
    }
    svc2::apply_shared_factors(&mut inspections, &mut analyzer)?;
    let provider = provider_from_name(&config.llm_provider);
    let mut rows = Vec::new();
    for ((scenario, version), inspection) in labels.into_iter().zip(inspections) {
        let expected = expect(scenario, version);
        let verdict = VerdictSnapshot {
            certificate_status: inspection.certificate_status.clone(),
            risk_class: inspection.risk_class.clone(),
        };
        let advisory = DeterministicRea.advise(&observation_from(&inspection), &verdict);
        let applied = apply_advisory(&verdict, advisory.clone());
        let llm = if provider.enabled() {
            provider
                .complete(&AdvisoryRequest {
                    observation: observation_from(&inspection),
                    certificate_status: verdict.certificate_status.clone(),
                    risk_class: verdict.risk_class.clone(),
                })
                .ok()
        } else {
            None
        };
        let llm_applied = llm
            .as_ref()
            .map(|advice| apply_advisory(&verdict, advice.clone()));
        let verdict_preserved = applied.verdict == verdict
            && llm_applied
                .as_ref()
                .map(|item| item.verdict == verdict)
                .unwrap_or(true);
        let offline_certificate_valid = if scenario == "possession_failed" {
            Some(offline)
        } else {
            None
        };
        rows.push(Row {
            scenario: scenario.to_string(),
            requested_tls: inspection.requested_tls.clone(),
            negotiated_tls: inspection.negotiated_tls.clone(),
            handshake: inspection.handshake.clone(),
            expected_handshake: expected.handshake.to_string(),
            certificate_status: inspection.certificate_status.clone(),
            expected_certificate_status: expected.certificate_status.to_string(),
            risk_class: inspection.risk_class.clone(),
            expected_risk_class: expected.risk_class.map(str::to_string),
            protocol_policy: inspection.protocol_policy.clone(),
            overall_accept: inspection.overall_accept,
            handshake_correct: inspection.handshake == expected.handshake,
            reason_correct: inspection.certificate_status == expected.certificate_status,
            risk_correct: inspection.risk_class.as_deref() == expected.risk_class,
            findings: inspection.findings.clone(),
            offline_certificate_valid,
            advisory_source: advisory.source,
            threat_event: applied.advisory.threat_event,
            llm_threat_event: llm.map(|item| item.threat_event),
            verdict_preserved,
        });
        println!(
            "{scenario:22} TLS{version} -> {:22} risk={} handshake={}",
            rows.last().unwrap().certificate_status,
            rows.last().unwrap().risk_class.as_deref().unwrap_or("-"),
            rows.last().unwrap().handshake
        );
    }
    let ok = rows.iter().all(|row| {
        row.handshake_correct
            && row.reason_correct
            && row.risk_correct
            && row.verdict_preserved
            && row.protocol_policy
                == expect(&row.scenario, version_of(&row.requested_tls)).protocol_policy
            && row.offline_certificate_valid.unwrap_or(true)
    }) && offline;
    fs::create_dir_all(&config.report_dir)?;
    let document = json!({
        "ok": ok,
        "test_count": rows.len(),
        "reason_correct": rows.iter().filter(|row| row.reason_correct).count(),
        "cases": &rows,
    });
    fs::write(
        config.report_dir.join("report.json"),
        serde_json::to_vec_pretty(&document)?,
    )?;
    write_csv(&config.report_dir.join("report.csv"), &rows)?;
    let mut detail = String::new();
    for row in rows.iter().filter(|row| {
        !row.reason_correct || !row.handshake_correct || !row.risk_correct || !row.verdict_preserved
    }) {
        detail.push_str(&format!(
            "{} {} got {}/{:?}/{} expected {}/{:?}/{}\n",
            row.scenario,
            row.requested_tls,
            row.certificate_status,
            row.risk_class,
            row.handshake,
            row.expected_certificate_status,
            row.expected_risk_class,
            row.expected_handshake
        ));
    }
    if !offline {
        detail.push_str("possession leaf did not validate offline\n");
    }
    Ok(Summary { ok, detail })
}

fn version_of(requested: &str) -> &str {
    requested.trim_start_matches("TLSv")
}

fn write_csv(path: &Path, rows: &[Row]) -> Result<()> {
    let mut out = String::from("scenario,requested_tls,handshake,certificate_status,expected_certificate_status,risk_class,reason_correct,handshake_correct\n");
    for row in rows {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            row.scenario,
            row.requested_tls,
            row.handshake,
            row.certificate_status,
            row.expected_certificate_status,
            row.risk_class.as_deref().unwrap_or(""),
            row.reason_correct,
            row.handshake_correct
        ));
    }
    fs::write(path, out)?;
    Ok(())
}

pub fn config_from_env() -> ExecuteConfig {
    ExecuteConfig {
        domain: std::env::var("LAB_DOMAIN").unwrap_or_else(|_| "tls-lab.example.test".into()),
        host: std::env::var("LAB_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
        ca_file: std::env::var("LAB_TRUST_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/trust/trusted_root_ca.pem")),
        policy_dir: std::env::var("LAB_POLICY_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/trust")),
        possession_leaf: std::env::var("LAB_POSSESSION_LEAF")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/trust/possession_leaf.pem")),
        report_dir: std::env::var("REPORT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/reports")),
        analyze_script: std::env::var("JULIA_ANALYZE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/opt/lab/julia/analyze.jl")),
        oracle_script: std::env::var("JULIA_ORACLE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/opt/lab/julia/oracle.jl")),
        port_offset: std::env::var("LAB_PORT_OFFSET")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        llm_provider: std::env::var("LAB_LLM_PROVIDER").unwrap_or_else(|_| "disabled".into()),
    }
}
