//! SVC2 detector.
//!
//! The detector sees a handshake, a certificate, and the operator policy.
//! It does not receive scenario names, expected answers, or private keys.

mod analyze;

use anyhow::{Context, Result};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509NameRef, X509StoreContext, X509};
use policy::{hex_encode, Policy};
use serde::Serialize;
use serde_json::Value;
use std::cell::RefCell;
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

pub use analyze::JuliaAnalyzer;

const SCT_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x01];
const SERVER_AUTH_OID: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const WEAK_ORDER: &[&str] = &[
    "SHARED_FACTOR",
    "ROCA_FINGERPRINT",
    "WEAK_SIGNATURE",
    "NONCE_REUSE",
    "STRUCTURAL_WEAKNESS",
    "WEAK_KEY",
];

thread_local! {
    static VERIFY_CODE: RefCell<Option<i32>> = const { RefCell::new(None) };
}

pub trait PublicAnalyzer {
    fn inspect(&mut self, n: &str, e: &str, sig_alg: &str) -> Result<Vec<String>>;
    fn batch_gcd(&mut self, moduli: &[String]) -> Result<Vec<(usize, usize)>>;
}

impl PublicAnalyzer for JuliaAnalyzer {
    fn inspect(&mut self, n: &str, e: &str, sig_alg: &str) -> Result<Vec<String>> {
        JuliaAnalyzer::inspect(self, n, e, sig_alg)
    }
    fn batch_gcd(&mut self, moduli: &[String]) -> Result<Vec<(usize, usize)>> {
        JuliaAnalyzer::batch_gcd(self, moduli)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LeafInfo {
    pub subject: String,
    pub issuer: String,
    pub san_dns: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
    pub spki_sha256: String,
    pub signature_algorithm: String,
    pub serial_hex: String,
    pub key_type: String,
    pub bits: Option<u32>,
    pub exponent_bits: Option<u32>,
    pub curve: Option<String>,
    pub sct_present: bool,
    pub possible_cdn_edge: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Inspection {
    pub host: String,
    pub port: u16,
    pub servername: String,
    pub requested_tls: String,
    pub negotiated_tls: Option<String>,
    pub handshake: String,
    pub certificate_status: String,
    pub risk_class: Option<String>,
    pub findings: Vec<String>,
    pub certificate_authenticated: bool,
    pub spki_authorized: Option<bool>,
    pub protocol_policy: String,
    pub overall_accept: bool,
    pub leaf: Option<LeafInfo>,
    #[serde(skip)]
    pub rsa_modulus: Option<String>,
    #[serde(skip)]
    pub duplicate_nonce_r: bool,
}

pub struct InspectRequest<'a, A: PublicAnalyzer + ?Sized> {
    pub host: &'a str,
    pub port: u16,
    pub servername: &'a str,
    pub version: &'a str,
    pub ca_file: &'a Path,
    pub policy: &'a Policy,
    pub lab_mode: bool,
    pub analyzer: &'a mut A,
}

pub fn inspect_tls<A: PublicAnalyzer + ?Sized>(
    request: InspectRequest<'_, A>,
) -> Result<Inspection> {
    let protocol_policy = if request.version == "1.1" {
        "DEPRECATED"
    } else {
        "ALLOWED"
    };
    let mut inspection = blank(
        request.host,
        request.port,
        request.servername,
        request.version,
        protocol_policy,
    );
    let connected = connect(&request);
    let (mut stream, leaf) = match connected {
        Ok(value) => value,
        Err(_) => {
            refresh(&mut inspection);
            return Ok(inspection);
        }
    };
    inspection.handshake = "COMPLETED".into();
    inspection.negotiated_tls = Some(stream.ssl().version_str().to_string());
    let code = VERIFY_CODE.with(|slot| slot.borrow().unwrap_or(0));
    let mut chain_status = map_verify(code, same_name(&leaf));
    if chain_status == "VALID" && !server_auth(&leaf) {
        chain_status = "INVALID_PURPOSE".into();
    }
    let info = leaf_info(&leaf)?;
    inspection.duplicate_nonce_r = duplicate_r(&read_body(&mut stream));
    inspection.leaf = Some(info.clone());
    let mut weak = Vec::new();
    if let Some(rsa) = info.key_type.eq("rsa").then_some(()) {
        let _ = rsa;
        if let (Some(n), Some(e_bits)) = (rsa_modulus(&leaf)?, info.exponent_bits) {
            let e = rsa_exponent(&leaf)?;
            let _ = e_bits;
            inspection.rsa_modulus = Some(n.clone());
            weak.extend(
                request
                    .analyzer
                    .inspect(&n, &e, &info.signature_algorithm)?,
            );
        }
    }
    if inspection.duplicate_nonce_r {
        weak.push("NONCE_REUSE".into());
    }
    let auth = if chain_status == "VALID" {
        authorization(request.policy, request.host, request.port, &info)
    } else {
        None
    };
    inspection.certificate_authenticated = chain_status == "VALID";
    inspection.spki_authorized = if chain_status == "VALID" {
        Some(
            request
                .policy
                .approved_spki
                .iter()
                .any(|item| item == &info.spki_sha256),
        )
    } else {
        None
    };
    let (status, risk, findings) = classify(true, &chain_status, &weak, auth.as_deref());
    inspection.certificate_status = status;
    inspection.risk_class = risk;
    inspection.findings = findings;
    refresh(&mut inspection);
    Ok(inspection)
}

pub fn apply_shared_factors<A: PublicAnalyzer + ?Sized>(
    rows: &mut [Inspection],
    analyzer: &mut A,
) -> Result<()> {
    let mut sent: Vec<(usize, String)> = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if let Some(modulus) = &row.rsa_modulus {
            if modulus.trim_start_matches('0').len() <= 309 {
                sent.push((index, modulus.clone()));
            }
        }
    }
    if sent.len() < 2 {
        return Ok(());
    }
    let moduli: Vec<String> = sent.iter().map(|(_, n)| n.clone()).collect();
    for (left, right) in analyzer.batch_gcd(&moduli)? {
        mark_shared(rows, sent.get(left).map(|item| item.0));
        mark_shared(rows, sent.get(right).map(|item| item.0));
    }
    Ok(())
}

pub fn offline_chain_valid(ca_pem: &[u8], leaf_pem: &[u8]) -> Result<bool> {
    let ca = X509::from_pem(ca_pem)?;
    let leaf = X509::from_pem(leaf_pem)?;
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(ca)?;
    let store = store.build();
    let chain = openssl::stack::Stack::new()?;
    let mut context = X509StoreContext::new()?;
    Ok(context.init(&store, &leaf, &chain, |ctx| ctx.verify_cert())?)
}

pub fn possible_cdn(issuer: &str) -> bool {
    let lowered = issuer.to_ascii_lowercase();
    ["cloudflare", "akamai", "fastly", "amazon", "cloudfront"]
        .iter()
        .any(|name| lowered.contains(name))
}

pub fn contains_private_key(pem: &str) -> bool {
    pem.contains("PRIVATE KEY")
}

pub fn classify(
    handshake_completed: bool,
    chain_status: &str,
    weak: &[String],
    auth: Option<&str>,
) -> (String, Option<String>, Vec<String>) {
    if !handshake_completed {
        return ("HANDSHAKE_REJECTED".into(), None, Vec::new());
    }
    if chain_status != "VALID" {
        return (
            chain_status.to_string(),
            Some("INVALID_CERTIFICATE".into()),
            Vec::new(),
        );
    }
    if let Some(primary) = pick_weak(weak) {
        let mut findings = Vec::new();
        for reason in weak {
            if reason != &primary && !findings.contains(reason) {
                findings.push(reason.clone());
            }
        }
        if let Some(auth) = auth {
            if !findings.contains(&auth.to_string()) {
                findings.push(auth.to_string());
            }
        }
        return (primary, Some("WEAK_CRYPTOGRAPHY".into()), findings);
    }
    if let Some(auth) = auth {
        return (
            auth.to_string(),
            Some("VALID_BUT_UNAUTHORIZED".into()),
            Vec::new(),
        );
    }
    ("VALID".into(), None, Vec::new())
}

fn mark_shared(rows: &mut [Inspection], index: Option<usize>) {
    let Some(index) = index else { return };
    let Some(row) = rows.get_mut(index) else {
        return;
    };
    if row.handshake != "COMPLETED" || row.risk_class.as_deref() == Some("INVALID_CERTIFICATE") {
        return;
    }
    if row.certificate_status != "SHARED_FACTOR" && row.certificate_status != "VALID" {
        row.findings.push(row.certificate_status.clone());
    }
    row.certificate_status = "SHARED_FACTOR".into();
    row.risk_class = Some("WEAK_CRYPTOGRAPHY".into());
    refresh(row);
}

fn pick_weak(reasons: &[String]) -> Option<String> {
    WEAK_ORDER
        .iter()
        .find(|item| reasons.iter().any(|reason| reason == *item))
        .map(|item| (*item).to_string())
}

fn authorization(policy: &Policy, host: &str, port: u16, leaf: &LeafInfo) -> Option<String> {
    let approved = policy
        .approved_spki
        .iter()
        .any(|item| item == &leaf.spki_sha256);
    if !approved {
        return Some("KEY_NOT_APPROVED".into());
    }
    let issued = policy.issuance.iter().any(|record| {
        record.spki_sha256.eq_ignore_ascii_case(&leaf.spki_sha256)
            && record.serial.eq_ignore_ascii_case(&leaf.serial_hex)
    });
    if !issued {
        return Some("UNAUTHORIZED_ISSUANCE".into());
    }
    match policy.ports_by_spki.get(&leaf.spki_sha256) {
        Some(ports) if policy.host == host && ports.contains(&port) => None,
        _ => Some("UNAUTHORIZED_ENDPOINT".into()),
    }
}

fn blank(
    host: &str,
    port: u16,
    servername: &str,
    version: &str,
    protocol_policy: &str,
) -> Inspection {
    Inspection {
        host: host.to_string(),
        port,
        servername: servername.to_string(),
        requested_tls: format!("TLSv{version}"),
        negotiated_tls: None,
        handshake: "REJECTED".into(),
        certificate_status: "HANDSHAKE_REJECTED".into(),
        risk_class: None,
        findings: Vec::new(),
        certificate_authenticated: false,
        spki_authorized: None,
        protocol_policy: protocol_policy.to_string(),
        overall_accept: false,
        leaf: None,
        rsa_modulus: None,
        duplicate_nonce_r: false,
    }
}

fn refresh(row: &mut Inspection) {
    row.overall_accept = row.handshake == "COMPLETED"
        && row.certificate_status == "VALID"
        && row.risk_class.is_none()
        && row.protocol_policy == "ALLOWED";
}

fn connect<'a, A: PublicAnalyzer + ?Sized>(
    request: &'a InspectRequest<'a, A>,
) -> Result<(openssl::ssl::SslStream<TcpStream>, X509)> {
    VERIFY_CODE.with(|slot| *slot.borrow_mut() = None);
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_ca_file(request.ca_file)?;
    builder.set_verify_callback(SslVerifyMode::PEER, |ok, ctx| {
        if !ok {
            VERIFY_CODE.with(|slot| {
                let mut current = slot.borrow_mut();
                if current.is_none() || ctx.error_depth() == 0 {
                    *current = Some(ctx.error().as_raw());
                }
            });
        }
        true
    });
    if !request.lab_mode && request.version == "1.1" {
        anyhow::bail!("public probe does not negotiate TLS 1.1");
    }
    let version = ssl_version(request.version)?;
    builder.set_min_proto_version(Some(version))?;
    builder.set_max_proto_version(Some(version))?;
    if request.lab_mode {
        builder.set_security_level(0);
        builder.set_cipher_list("DEFAULT:@SECLEVEL=0")?;
    }
    let connector = builder.build();
    let address = (request.host, request.port)
        .to_socket_addrs_first()
        .context("resolve")?;
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    tcp.set_read_timeout(Some(Duration::from_secs(3)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut config = connector.configure()?;
    config.set_verify_hostname(true);
    config.set_use_server_name_indication(true);
    let stream = config.connect(request.servername, tcp)?;
    let leaf = stream
        .ssl()
        .peer_certificate()
        .context("peer sent no certificate")?;
    Ok((stream, leaf))
}

trait FirstAddr {
    fn to_socket_addrs_first(&self) -> Result<std::net::SocketAddr>;
}

impl FirstAddr for (&str, u16) {
    fn to_socket_addrs_first(&self) -> Result<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        Ok(self.to_socket_addrs()?.next().context("no address")?)
    }
}

fn ssl_version(version: &str) -> Result<SslVersion> {
    Ok(match version {
        "1.1" => SslVersion::TLS1_1,
        "1.2" => SslVersion::TLS1_2,
        "1.3" => SslVersion::TLS1_3,
        _ => anyhow::bail!("unsupported tls version"),
    })
}

fn map_verify(code: i32, self_issued: bool) -> String {
    match code {
        0 => "VALID",
        9 => "NOT_YET_VALID",
        10 => "EXPIRED",
        18 | 19 => "SELF_SIGNED",
        2 | 20 | 21 if self_issued => "SELF_SIGNED",
        2 | 20 | 21 => "UNKNOWN_ISSUER",
        26 => "INVALID_PURPOSE",
        62 => "HOSTNAME_MISMATCH",
        _ => "VERIFY_FAILED_OTHER",
    }
    .to_string()
}

fn same_name(cert: &X509) -> bool {
    name_text(cert.subject_name()) == name_text(cert.issuer_name())
}

fn name_text(name: &X509NameRef) -> String {
    name.entries()
        .filter_map(|entry| entry.data().to_string().ok())
        .collect::<Vec<_>>()
        .join("/")
}

fn server_auth(cert: &X509) -> bool {
    let Ok(der) = cert.to_der() else {
        return false;
    };
    der.windows(SERVER_AUTH_OID.len())
        .any(|window| window == SERVER_AUTH_OID)
}

fn leaf_info(cert: &X509) -> Result<LeafInfo> {
    let der = cert.to_der()?;
    let spki = cert.public_key()?.public_key_to_der()?;
    let signature = cert
        .signature_algorithm()
        .object()
        .nid()
        .short_name()?
        .to_string();
    let mut san = Vec::new();
    if let Some(names) = cert.subject_alt_names() {
        for name in names {
            if let Some(dns) = name.dnsname() {
                san.push(dns.to_string());
            }
        }
    }
    let issuer = name_text(cert.issuer_name());
    let (key_type, bits, exponent_bits, curve) = key_shape(cert)?;
    Ok(LeafInfo {
        subject: name_text(cert.subject_name()),
        issuer: issuer.clone(),
        san_dns: san,
        not_before: cert.not_before().to_string(),
        not_after: cert.not_after().to_string(),
        fingerprint_sha256: hex_encode(&openssl::sha::sha256(&der)),
        spki_sha256: hex_encode(&openssl::sha::sha256(&spki)),
        signature_algorithm: signature,
        serial_hex: serial_hex(cert)?,
        key_type,
        bits,
        exponent_bits,
        curve,
        sct_present: der.windows(SCT_OID.len()).any(|window| window == SCT_OID),
        possible_cdn_edge: possible_cdn(&issuer),
    })
}

fn key_shape(cert: &X509) -> Result<(String, Option<u32>, Option<u32>, Option<String>)> {
    let key = cert.public_key()?;
    if let Ok(rsa) = key.rsa() {
        return Ok((
            "rsa".into(),
            Some(rsa.n().num_bits() as u32),
            Some(rsa.e().num_bits() as u32),
            None,
        ));
    }
    if let Ok(ec) = key.ec_key() {
        let curve = ec
            .group()
            .curve_name()
            .map(|nid| nid.short_name().unwrap_or("ec").to_string());
        return Ok(("ec".into(), None, None, curve));
    }
    Ok(("unknown".into(), None, None, None))
}

fn serial_hex(cert: &X509) -> Result<String> {
    Ok(hex_encode(&cert.serial_number().to_bn()?.to_vec()))
}

fn rsa_modulus(cert: &X509) -> Result<Option<String>> {
    let key = cert.public_key()?;
    if let Ok(rsa) = key.rsa() {
        return Ok(Some(rsa.n().to_dec_str()?.to_string()));
    }
    Ok(None)
}

fn rsa_exponent(cert: &X509) -> Result<String> {
    Ok(cert.public_key()?.rsa()?.e().to_dec_str()?.to_string())
}

fn read_body(stream: &mut openssl::ssl::SslStream<TcpStream>) -> String {
    use std::io::{Read, Write};
    let _ = stream.write_all(b"GET / HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n");
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 65_536 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn duplicate_r(raw: &str) -> bool {
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(raw);
    let Ok(parsed) = serde_json::from_str::<Value>(body.trim()) else {
        return false;
    };
    let Some(sigs) = parsed.get("signatures").and_then(Value::as_array) else {
        return false;
    };
    if sigs.len() < 2 {
        return false;
    }
    let r0 = sigs[0].get("r").and_then(Value::as_str).unwrap_or("");
    let r1 = sigs[1].get("r").and_then(Value::as_str).unwrap_or("");
    !r0.is_empty() && r0 == r1
}

pub fn fetch_public(host: &str, port: u16, servername: &str) -> Result<(Vec<u8>, LeafInfo)> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_default_verify_paths()?;
    builder.set_verify(SslVerifyMode::PEER);
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    let connector = builder.build();
    let address = (host, port).to_socket_addrs_first()?;
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(8))?;
    let mut config = connector.configure()?;
    config.set_verify_hostname(true);
    config.set_use_server_name_indication(true);
    let stream = config.connect(servername, tcp)?;
    let cert = stream
        .ssl()
        .peer_certificate()
        .context("peer sent no certificate")?;
    let pem = cert.to_pem()?;
    if contains_private_key(&String::from_utf8_lossy(&pem)) {
        anyhow::bail!("refusing private key material");
    }
    Ok((pem, leaf_info(&cert)?))
}

pub fn observation_from(inspection: &Inspection) -> rea::PublicObservation {
    let leaf = inspection.leaf.as_ref();
    rea::PublicObservation {
        key_type: leaf.map(|item| item.key_type.clone()),
        bits: leaf.and_then(|item| item.bits),
        exponent_bits: leaf.and_then(|item| item.exponent_bits),
        signature_algorithm: leaf.map(|item| item.signature_algorithm.clone()),
        duplicate_nonce_r: inspection.duplicate_nonce_r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_certificate_outranks_weak_material() {
        let (status, risk, _) = classify(
            true,
            "EXPIRED",
            &["WEAK_KEY".into()],
            Some("KEY_NOT_APPROVED"),
        );
        assert_eq!(status, "EXPIRED");
        assert_eq!(risk.as_deref(), Some("INVALID_CERTIFICATE"));
    }

    #[test]
    fn weak_crypto_outranks_authorization_and_keeps_the_finding() {
        let (status, risk, findings) = classify(
            true,
            "VALID",
            &["WEAK_KEY".into(), "ROCA_FINGERPRINT".into()],
            Some("KEY_NOT_APPROVED"),
        );
        assert_eq!(status, "ROCA_FINGERPRINT");
        assert_eq!(risk.as_deref(), Some("WEAK_CRYPTOGRAPHY"));
        assert!(findings.iter().any(|item| item == "WEAK_KEY"));
        assert!(findings.iter().any(|item| item == "KEY_NOT_APPROVED"));
    }

    #[test]
    fn valid_but_unauthorized_is_separate_from_an_invalid_chain() {
        let (status, risk, _) = classify(true, "VALID", &[], Some("UNAUTHORIZED_ENDPOINT"));
        assert_eq!(status, "UNAUTHORIZED_ENDPOINT");
        assert_eq!(risk.as_deref(), Some("VALID_BUT_UNAUTHORIZED"));
    }

    #[test]
    fn rejected_handshake_has_no_risk_class() {
        let (status, risk, _) = classify(false, "VALID", &["WEAK_KEY".into()], None);
        assert_eq!(status, "HANDSHAKE_REJECTED");
        assert!(risk.is_none());
    }

    #[test]
    fn cdn_marker_is_only_a_hint() {
        assert!(possible_cdn("CN=Cloudflare Inc ECC CA-3"));
        assert!(!possible_cdn("CN=TLS-LAB Trusted Root CA"));
    }

    struct PairAnalyzer;
    impl PublicAnalyzer for PairAnalyzer {
        fn inspect(&mut self, _: &str, _: &str, _: &str) -> Result<Vec<String>> {
            Ok(vec!["WEAK_KEY".into()])
        }
        fn batch_gcd(&mut self, _: &[String]) -> Result<Vec<(usize, usize)>> {
            Ok(vec![(0, 1)])
        }
    }

    #[test]
    fn shared_factor_upgrade_does_not_keep_a_private_factor() {
        let mut rows = vec![
            Inspection {
                certificate_status: "WEAK_KEY".into(),
                risk_class: Some("WEAK_CRYPTOGRAPHY".into()),
                handshake: "COMPLETED".into(),
                rsa_modulus: Some("35".into()),
                protocol_policy: "ALLOWED".into(),
                ..blank("127.0.0.1", 1, "lab", "1.2", "ALLOWED")
            },
            Inspection {
                certificate_status: "WEAK_KEY".into(),
                risk_class: Some("WEAK_CRYPTOGRAPHY".into()),
                handshake: "COMPLETED".into(),
                rsa_modulus: Some("55".into()),
                protocol_policy: "ALLOWED".into(),
                ..blank("127.0.0.1", 2, "lab", "1.2", "ALLOWED")
            },
        ];
        apply_shared_factors(&mut rows, &mut PairAnalyzer).unwrap();
        assert_eq!(rows[0].certificate_status, "SHARED_FACTOR");
        assert!(rows[0].findings.iter().any(|item| item == "WEAK_KEY"));
        let encoded = serde_json::to_string(&rows[0]).unwrap();
        assert!(!encoded.contains("\"35\""));
    }
}
