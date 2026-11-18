//! Lab certificate issuance.
//!
//! Weak RSA parameters come from Julia and are capped at 512 bits. This crate
//! only wraps those parameters in X.509. It does not factor a supplied modulus.

use anyhow::{anyhow, bail, Context, Result};
use jsonline::JsonProcess;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, BigNumContext};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509NameBuilder, X509};
use policy::{hex_encode, port, Case, IssuanceRecord, CASES};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const LAB_OPENSSL_CONF: &str = "\
openssl_conf = openssl_init

[openssl_init]
alg_section = evp_properties

[evp_properties]
rh-allow-sha1-signatures = yes
";

#[derive(Clone, Debug)]
pub struct ListenerSpec {
    pub case_name: String,
    pub version: String,
    pub port: u16,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub chain_pem: Option<Vec<u8>>,
    pub body: Vec<u8>,
}

pub struct IssuedLab {
    pub listeners: Vec<ListenerSpec>,
    pub possession_cert: PathBuf,
    pub possession_ports: Vec<u16>,
    pub trusted_root: PathBuf,
}

struct Identity {
    key: PKey<Private>,
    cert: X509,
}

pub fn enable_lab_sha1(state_dir: &Path) -> Result<()> {
    fs::create_dir_all(state_dir)?;
    let path = state_dir.join("openssl-lab.cnf");
    fs::write(&path, LAB_OPENSSL_CONF)?;
    std::env::set_var("OPENSSL_CONF", &path);
    // OpenSSL reads this on first use. Callers must invoke this before other
    // OpenSSL calls in the process. SHA-1 is enabled only so the lab can mint
    // a deprecated-signature fixture. MD5 is intentionally not enabled.
    Ok(())
}

pub fn issue(
    domain: &str,
    state_dir: &Path,
    trust_dir: &Path,
    host: &str,
    offset: u16,
    generate_script: &Path,
) -> Result<IssuedLab> {
    fs::create_dir_all(state_dir)?;
    fs::create_dir_all(trust_dir)?;
    let mut generator = JsonProcess::spawn(generate_script)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let trusted = root(
        "TLS-LAB Trusted Root CA",
        now,
        2048,
        MessageDigest::sha256(),
    )?;
    let rogue = root(
        "TLS-LAB Unauthorized Root CA",
        now,
        2048,
        MessageDigest::sha256(),
    )?;
    write_secret(
        &state_dir.join("trusted_root.key"),
        &trusted.key.private_key_to_pem_pkcs8()?,
    )?;
    write_public(&state_dir.join("trusted_root.pem"), &trusted.cert.to_pem()?)?;
    write_secret(
        &state_dir.join("rogue_root.key"),
        &rogue.key.private_key_to_pem_pkcs8()?,
    )?;
    write_public(&state_dir.join("rogue_root.pem"), &rogue.cert.to_pem()?)?;
    let trusted_root = trust_dir.join("trusted_root_ca.pem");
    write_public(&trusted_root, &trusted.cert.to_pem()?)?;

    let good = leaf(
        &trusted,
        domain,
        domain,
        "good",
        now,
        MessageDigest::sha256(),
        2048,
        None,
    )?;
    let good_spki = spki_sha256(&good.cert)?;
    let good_serial = serial_hex(&good.cert)?;
    let approved = vec![good_spki.clone()];
    let mut ports_by_spki: HashMap<String, Vec<u16>> = HashMap::new();
    let mut good_ports = Vec::new();
    for version in case("good").versions {
        good_ports.push(port(case("good"), version, offset).unwrap());
    }
    let nonce_port = port(case("nonce_reuse"), "1.2", offset).unwrap();
    good_ports.push(nonce_port);
    ports_by_spki.insert(good_spki.clone(), good_ports);

    let mut made = HashMap::new();
    made.insert("good".to_string(), good);
    made.insert("self_signed".to_string(), self_signed(domain, now)?);
    made.insert(
        "rogue_ca".to_string(),
        leaf(
            &rogue,
            domain,
            domain,
            "rogue_ca",
            now,
            MessageDigest::sha256(),
            2048,
            None,
        )?,
    );
    made.insert(
        "wrong_san".to_string(),
        leaf(
            &trusted,
            domain,
            "unrelated.invalid",
            "wrong_san",
            now,
            MessageDigest::sha256(),
            2048,
            None,
        )?,
    );
    made.insert(
        "expired".to_string(),
        leaf(
            &trusted,
            domain,
            domain,
            "expired",
            now,
            MessageDigest::sha256(),
            2048,
            None,
        )?,
    );
    made.insert(
        "future".to_string(),
        leaf(
            &trusted,
            domain,
            domain,
            "future",
            now,
            MessageDigest::sha256(),
            2048,
            None,
        )?,
    );
    made.insert(
        "wrong_eku".to_string(),
        leaf(
            &trusted,
            domain,
            domain,
            "wrong_eku",
            now,
            MessageDigest::sha256(),
            2048,
            None,
        )?,
    );
    made.insert(
        "unapproved_leaf".to_string(),
        leaf(
            &trusted,
            domain,
            domain,
            "unapproved_leaf",
            now,
            MessageDigest::sha256(),
            2048,
            None,
        )?,
    );
    made.insert(
        "compromised_endpoint".to_string(),
        clone_identity(made.get("good").unwrap())?,
    );

    let weak = synthetic_identity(
        &mut generator,
        &trusted,
        domain,
        now,
        "weak_rsa",
        "weak_rsa",
    )?;
    let shared = synthetic_pair(&mut generator, &trusted, domain, now)?;
    let roca = synthetic_identity(
        &mut generator,
        &trusted,
        domain,
        now,
        "roca",
        "roca_fingerprint",
    )?;
    let wiener = synthetic_identity(
        &mut generator,
        &trusted,
        domain,
        now,
        "wiener",
        "wiener_rsa",
    )?;
    let fermat = synthetic_identity(
        &mut generator,
        &trusted,
        domain,
        now,
        "fermat",
        "fermat_rsa",
    )?;
    let sha1 = leaf(
        &trusted,
        domain,
        domain,
        "sha1_cert",
        now,
        MessageDigest::sha1(),
        2048,
        None,
    )
    .context("OpenSSL refused SHA-1 signatures; MD5 is intentionally unsupported")?;
    made.insert("weak_rsa".into(), weak);
    made.insert("shared_prime_a".into(), shared.0);
    made.insert("shared_prime_b".into(), shared.1);
    made.insert("roca_fingerprint".into(), roca);
    made.insert("wiener_rsa".into(), wiener);
    made.insert("fermat_rsa".into(), fermat);
    made.insert("sha1_cert".into(), sha1);
    made.insert(
        "nonce_reuse".into(),
        clone_identity(made.get("good").unwrap())?,
    );

    for (name, identity) in &made {
        write_secret(
            &state_dir.join(format!("{name}.key")),
            &identity.key.private_key_to_pem_pkcs8()?,
        )?;
        write_public(
            &state_dir.join(format!("{name}.pem")),
            &identity.cert.to_pem()?,
        )?;
    }
    let possession_cert = trust_dir.join("possession_leaf.pem");
    write_public(&possession_cert, &made.get("good").unwrap().cert.to_pem()?)?;

    policy::Policy::store(
        trust_dir,
        &approved,
        &[IssuanceRecord {
            serial: good_serial,
            issuer: common_name(trusted.cert.subject_name())?,
            san: vec![domain.to_string()],
            spki_sha256: good_spki,
        }],
        host,
        &ports_by_spki,
    )
    .map_err(|err| anyhow!("{err}"))?;

    let nonce_body = nonce_signatures()?;
    let mut listeners = Vec::new();
    for item in CASES {
        if item.name == "possession_failed" {
            continue;
        }
        let identity = made.get(item.name).context("missing case identity")?;
        // The client already has the trust anchor. Sending an untrusted root
        // makes that root look like a self-signed chain instead of an unknown issuer.
        for version in item.versions {
            listeners.push(ListenerSpec {
                case_name: item.name.to_string(),
                version: (*version).to_string(),
                port: port(item, version, offset).unwrap(),
                cert_pem: identity.cert.to_pem()?,
                key_pem: identity.key.private_key_to_pem_pkcs8()?,
                chain_pem: None,
                body: if item.name == "nonce_reuse" {
                    nonce_body.clone()
                } else {
                    b"TLS validation lab. No user data.\n".to_vec()
                },
            });
        }
    }
    let _ = approved;
    Ok(IssuedLab {
        listeners,
        possession_cert,
        possession_ports: case("possession_failed")
            .versions
            .iter()
            .map(|version| port(case("possession_failed"), version, offset).unwrap())
            .collect(),
        trusted_root,
    })
}

fn case(name: &str) -> &'static Case {
    policy::case(name).expect("known case")
}

fn clone_identity(identity: &Identity) -> Result<Identity> {
    Ok(Identity {
        key: PKey::private_key_from_pem(&identity.key.private_key_to_pem_pkcs8()?)?,
        cert: X509::from_pem(&identity.cert.to_pem()?)?,
    })
}

fn synthetic_identity(
    generator: &mut JsonProcess,
    issuer: &Identity,
    domain: &str,
    now: i64,
    profile: &str,
    case_name: &str,
) -> Result<Identity> {
    let response = generator.call(&json!({
        "op": "generate",
        "profile": profile,
        "bits": 512,
        "origin": "synthetic"
    }))?;
    if response.get("ok") != Some(&Value::Bool(true)) {
        bail!("julia refused {profile}: {response}");
    }
    let key = &response["keys"][0];
    ensure_capped(key)?;
    leaf(
        issuer,
        domain,
        domain,
        case_name,
        now,
        MessageDigest::sha256(),
        0,
        Some(key),
    )
}

fn synthetic_pair(
    generator: &mut JsonProcess,
    issuer: &Identity,
    domain: &str,
    now: i64,
) -> Result<(Identity, Identity)> {
    let response = generator.call(&json!({
        "op": "generate",
        "profile": "shared_prime",
        "bits": 512,
        "origin": "synthetic"
    }))?;
    if response.get("ok") != Some(&Value::Bool(true)) {
        bail!("julia refused shared_prime: {response}");
    }
    ensure_capped(&response["keys"][0])?;
    ensure_capped(&response["keys"][1])?;
    Ok((
        leaf(
            issuer,
            domain,
            domain,
            "shared_prime_a",
            now,
            MessageDigest::sha256(),
            0,
            Some(&response["keys"][0]),
        )?,
        leaf(
            issuer,
            domain,
            domain,
            "shared_prime_b",
            now,
            MessageDigest::sha256(),
            0,
            Some(&response["keys"][1]),
        )?,
    ))
}

fn ensure_capped(key: &Value) -> Result<()> {
    let n = key["n"].as_str().context("missing n")?;
    let bits = BigNum::from_dec_str(n)?.num_bits();
    if bits > 512 {
        bail!("julia returned a {bits}-bit key");
    }
    Ok(())
}

fn root(cn: &str, now: i64, bits: u32, digest: MessageDigest) -> Result<Identity> {
    let key = PKey::from_rsa(Rsa::generate(bits)?)?;
    let name = name(cn)?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&key)?;
    builder.set_not_before(time_at(now - 86_400)?.as_ref())?;
    builder.set_not_after(time_at(now + 365 * 86_400)?.as_ref())?;
    builder.set_serial_number(random_serial()?.as_ref())?;
    builder.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;
    let ski = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(ski)?;
    builder.sign(&key, digest)?;
    Ok(Identity {
        cert: builder.build(),
        key,
    })
}

fn self_signed(domain: &str, now: i64) -> Result<Identity> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    build_leaf(
        &key,
        &key,
        None,
        domain,
        domain,
        "self_signed",
        now,
        MessageDigest::sha256(),
    )
}

fn leaf(
    issuer: &Identity,
    subject_cn: &str,
    san: &str,
    case_name: &str,
    now: i64,
    digest: MessageDigest,
    bits: u32,
    components: Option<&Value>,
) -> Result<Identity> {
    let key = if let Some(components) = components {
        pkey_from_components(components)?
    } else {
        PKey::from_rsa(Rsa::generate(bits)?)?
    };
    build_leaf(
        &issuer.key,
        &key,
        Some(&issuer.cert),
        subject_cn,
        san,
        case_name,
        now,
        digest,
    )
}

fn build_leaf(
    signer: &PKey<Private>,
    subject_key: &PKey<Private>,
    issuer_cert: Option<&X509>,
    subject_cn: &str,
    san: &str,
    case_name: &str,
    now: i64,
    digest: MessageDigest,
) -> Result<Identity> {
    let (start, end) = match case_name {
        "expired" => (now - 35 * 86_400, now - 86_400),
        "future" => (now + 2 * 86_400, now + 35 * 86_400),
        _ => (now - 86_400, now + 7 * 86_400),
    };
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    let subject_name = name(subject_cn)?;
    builder.set_subject_name(&subject_name)?;
    let issuer_name = if let Some(issuer) = issuer_cert {
        issuer.subject_name().to_owned()?
    } else {
        name(subject_cn)?
    };
    builder.set_issuer_name(&issuer_name)?;
    builder.set_pubkey(subject_key)?;
    builder.set_not_before(time_at(start)?.as_ref())?;
    builder.set_not_after(time_at(end)?.as_ref())?;
    builder.set_serial_number(random_serial()?.as_ref())?;
    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;
    let mut eku = ExtendedKeyUsage::new();
    if case_name == "wrong_eku" {
        eku.client_auth();
    } else {
        eku.server_auth();
    }
    builder.append_extension(eku.build()?)?;
    let issuer_ref = issuer_cert.map(|cert| cert.as_ref());
    let context = builder.x509v3_context(issuer_ref, None);
    builder.append_extension(SubjectAlternativeName::new().dns(san).build(&context)?)?;
    let context = builder.x509v3_context(issuer_ref, None);
    builder.append_extension(SubjectKeyIdentifier::new().build(&context)?)?;
    if issuer_cert.is_some() {
        let context = builder.x509v3_context(issuer_ref, None);
        builder.append_extension(AuthorityKeyIdentifier::new().keyid(true).build(&context)?)?;
    }
    builder.sign(signer, digest)?;
    Ok(Identity {
        cert: builder.build(),
        key: PKey::private_key_from_pem(&subject_key.private_key_to_pem_pkcs8()?)?,
    })
}

fn pkey_from_components(value: &Value) -> Result<PKey<Private>> {
    let n = BigNum::from_dec_str(value["n"].as_str().context("n")?)?;
    let e = BigNum::from_dec_str(value["e"].as_str().context("e")?)?;
    let d = BigNum::from_dec_str(value["d"].as_str().context("d")?)?;
    let mut p = BigNum::from_dec_str(value["p"].as_str().context("p")?)?;
    let mut q = BigNum::from_dec_str(value["q"].as_str().context("q")?)?;
    if p < q {
        std::mem::swap(&mut p, &mut q);
    }
    let mut ctx = BigNumContext::new()?;
    let one = BigNum::from_u32(1)?;
    let mut pm1 = BigNum::new()?;
    let mut qm1 = BigNum::new()?;
    pm1.checked_sub(&p, &one)?;
    qm1.checked_sub(&q, &one)?;
    let mut dmp1 = BigNum::new()?;
    let mut dmq1 = BigNum::new()?;
    let mut iqmp = BigNum::new()?;
    dmp1.nnmod(&d, &pm1, &mut ctx)?;
    dmq1.nnmod(&d, &qm1, &mut ctx)?;
    iqmp.mod_inverse(&q, &p, &mut ctx)?;
    let rsa = Rsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp)?;
    rsa.check_key()?;
    Ok(PKey::from_rsa(rsa)?)
}

fn name(cn: &str) -> Result<openssl::x509::X509Name> {
    let mut builder = X509NameBuilder::new()?;
    builder.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    Ok(builder.build())
}

fn time_at(unix: i64) -> Result<Asn1Time> {
    Ok(Asn1Time::from_unix(unix)?)
}

fn random_serial() -> Result<Asn1Integer> {
    let mut bytes = [0u8; 16];
    openssl::rand::rand_bytes(&mut bytes)?;
    bytes[0] &= 0x7f;
    if bytes.iter().all(|b| *b == 0) {
        bytes[15] = 1;
    }
    Ok(Asn1Integer::from_bn(BigNum::from_slice(&bytes)?.as_ref())?)
}

fn serial_hex(cert: &X509) -> Result<String> {
    Ok(hex_encode(&cert.serial_number().to_bn()?.to_vec()))
}

fn spki_sha256(cert: &X509) -> Result<String> {
    let der = cert.public_key()?.public_key_to_der()?;
    Ok(hex_encode(&openssl::sha::sha256(&der)))
}

fn common_name(name: &openssl::x509::X509NameRef) -> Result<String> {
    for entry in name.entries() {
        if entry.object().nid() == Nid::COMMONNAME {
            return Ok(format!("CN={}", entry.data().to_string()?));
        }
    }
    Err(anyhow!("missing common name"))
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

pub fn nonce_signatures() -> Result<Vec<u8>> {
    use ecdsa::hazmat::SignPrimitive;
    use p256::{FieldBytes, NonZeroScalar};
    use sha2::{Digest, Sha256};

    // Fixed lab nonce. The private scalar never leaves this function.
    let mut secret = [0u8; 32];
    openssl::rand::rand_bytes(&mut secret)?;
    secret[0] = 0x20;
    let mut nonce = [0u8; 32];
    nonce[0] = 0x01;
    nonce[1] = 0x11;
    let d = *NonZeroScalar::from_repr(secret.into())
        .into_option()
        .context("lab scalar")?
        .as_ref();
    let k = *NonZeroScalar::from_repr(nonce.into())
        .into_option()
        .context("lab nonce")?
        .as_ref();
    let first = Sha256::digest(b"lab-nonce-one");
    let second = Sha256::digest(b"lab-nonce-two");
    let (left, _) = d
        .try_sign_prehashed::<p256::Scalar>(k, &FieldBytes::clone_from_slice(&first))
        .map_err(|_| anyhow!("lab signature"))?;
    let (right, _) = d
        .try_sign_prehashed::<p256::Scalar>(k, &FieldBytes::clone_from_slice(&second))
        .map_err(|_| anyhow!("lab signature"))?;
    let left_bytes = left.to_bytes();
    let right_bytes = right.to_bytes();
    let body = json!({
        "signatures": [
            {"r": hex_encode(&left_bytes[..32]), "s": hex_encode(&left_bytes[32..])},
            {"r": hex_encode(&right_bytes[..32]), "s": hex_encode(&right_bytes[32..])}
        ]
    });
    Ok(serde_json::to_vec(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_nonce_keeps_the_same_r() {
        let body = nonce_signatures().unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let r0 = parsed["signatures"][0]["r"].as_str().unwrap();
        let r1 = parsed["signatures"][1]["r"].as_str().unwrap();
        assert_eq!(r0, r1);
        assert!(!r0.is_empty());
        let text = String::from_utf8(body).unwrap();
        assert!(!text.contains("PRIVATE"));
    }
}
