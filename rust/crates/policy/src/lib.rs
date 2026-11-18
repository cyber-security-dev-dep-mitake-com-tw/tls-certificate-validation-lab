//! Operator baselines and public port map.
//!
//! Nothing in this crate is a scenario answer. SVC2 may read the policy
//! documents; it must not be given the ground-truth table.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const TLS_VERSIONS: &[&str] = &["1.1", "1.2", "1.3"];

#[derive(Clone, Copy, Debug)]
pub struct Case {
    pub name: &'static str,
    pub port_base: u16,
    pub versions: &'static [&'static str],
}

pub const CASES: &[Case] = &[
    Case {
        name: "good",
        port_base: 15100,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "self_signed",
        port_base: 15200,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "rogue_ca",
        port_base: 15300,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "wrong_san",
        port_base: 15400,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "expired",
        port_base: 15500,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "future",
        port_base: 15600,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "wrong_eku",
        port_base: 15700,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "unapproved_leaf",
        port_base: 15800,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "possession_failed",
        port_base: 15900,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "compromised_endpoint",
        port_base: 16000,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "weak_rsa",
        port_base: 16100,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "shared_prime_a",
        port_base: 16200,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "shared_prime_b",
        port_base: 16300,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "roca_fingerprint",
        port_base: 16400,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "sha1_cert",
        port_base: 16500,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "wiener_rsa",
        port_base: 16600,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "fermat_rsa",
        port_base: 16700,
        versions: TLS_VERSIONS,
    },
    Case {
        name: "nonce_reuse",
        port_base: 16800,
        versions: &["1.2"],
    },
];

pub fn case(name: &str) -> Option<&'static Case> {
    CASES.iter().find(|item| item.name == name)
}

pub fn port(case: &Case, version: &str, offset: u16) -> Option<u16> {
    let suffix: u16 = match version {
        "1.1" => 11,
        "1.2" => 12,
        "1.3" => 13,
        _ => return None,
    };
    Some(case.port_base.saturating_add(offset).saturating_add(suffix))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuanceRecord {
    pub serial: String,
    pub issuer: String,
    pub san: Vec<String>,
    pub spki_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ApprovedFile {
    spki_sha256: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IssuanceFile {
    records: Vec<IssuanceRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BindingFile {
    host: String,
    ports_by_spki: HashMap<String, Vec<u16>>,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub approved_spki: Vec<String>,
    pub issuance: Vec<IssuanceRecord>,
    pub host: String,
    pub ports_by_spki: HashMap<String, Vec<u16>>,
}

impl Policy {
    pub fn store(
        dir: &Path,
        approved_spki: &[String],
        issuance: &[IssuanceRecord],
        host: &str,
        ports_by_spki: &HashMap<String, Vec<u16>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(dir)?;
        fs::write(
            dir.join("approved_spki.json"),
            serde_json::to_vec_pretty(&ApprovedFile {
                spki_sha256: approved_spki.to_vec(),
            })?,
        )?;
        fs::write(
            dir.join("issuance_log.json"),
            serde_json::to_vec_pretty(&IssuanceFile {
                records: issuance.to_vec(),
            })?,
        )?;
        fs::write(
            dir.join("endpoint_bindings.json"),
            serde_json::to_vec_pretty(&BindingFile {
                host: host.to_string(),
                ports_by_spki: ports_by_spki.clone(),
            })?,
        )?;
        Ok(())
    }

    pub fn load(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let approved: ApprovedFile =
            serde_json::from_slice(&fs::read(dir.join("approved_spki.json"))?)?;
        let issuance: IssuanceFile =
            serde_json::from_slice(&fs::read(dir.join("issuance_log.json"))?)?;
        let bindings: BindingFile =
            serde_json::from_slice(&fs::read(dir.join("endpoint_bindings.json"))?)?;
        let mut ports_by_spki = HashMap::new();
        for (spki, ports) in bindings.ports_by_spki {
            ports_by_spki.insert(spki.to_ascii_lowercase(), ports);
        }
        Ok(Self {
            approved_spki: approved
                .spki_sha256
                .into_iter()
                .map(|item| item.to_ascii_lowercase())
                .collect(),
            issuance: issuance.records,
            host: bindings.host,
            ports_by_spki,
        })
    }
}
