"""Generate local-only CA and leaf certificates. No public CA is impersonated."""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from config import CASES


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(common_name: str):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _save_key(path: Path, key):
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    os.chmod(path, 0o600)


def _save_cert(path: Path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(path, 0o644)


def _root(common_name, now):
    key = _key()
    subject = _name(common_name)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(case, hostname, now, trusted, rogue):
    key = _key()
    if case == "self_signed":
        signing_key = key
        issuer = _name(hostname)
    elif case == "rogue_ca":
        signing_key, issuer_cert = rogue
        issuer = issuer_cert.subject
    else:
        signing_key, issuer_cert = trusted
        issuer = issuer_cert.subject

    if case == "expired":
        start, end = now - timedelta(days=35), now - timedelta(days=1)
    elif case == "future":
        start, end = now + timedelta(days=2), now + timedelta(days=35)
    else:
        start, end = now - timedelta(days=1), now + timedelta(days=7)

    cert_hostname = "unrelated.invalid" if case == "wrong_san" else hostname
    eku = (ExtendedKeyUsageOID.CLIENT_AUTH if case == "wrong_eku"
           else ExtendedKeyUsageOID.SERVER_AUTH)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(hostname)).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(start).not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cert_hostname)]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if case != "self_signed":
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),
            critical=False,
        )
    return key, builder.sign(signing_key, hashes.SHA256())


def generate(hostname: str, state_dir: Path, trust_dir: Path):
    state_dir.mkdir(parents=True, exist_ok=True)
    trust_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    trusted = _root("TLS-LAB Trusted Root CA", now)
    rogue = _root("TLS-LAB Unauthorized Root CA", now)

    for name, ca in (("trusted", trusted), ("rogue", rogue)):
        _save_key(state_dir / f"{name}_root.key", ca[0])
        _save_cert(state_dir / f"{name}_root.pem", ca[1])

    # SVC2 receives ONLY the public trusted root, never rogue CA or private keys.
    _save_cert(trust_dir / "trusted_root_ca.pem", trusted[1])
    for case in CASES:
        key, cert = _leaf(case, hostname, now, trusted, rogue)
        _save_key(state_dir / f"{case}.key", key)
        _save_cert(state_dir / f"{case}.pem", cert)
        if case == "good":
            # An explicitly configured authorized key baseline, not inferable
            # from an arbitrary peer certificate. Rotation requires approvals.
            spki_der = key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            (trust_dir / "approved_spki_sha256.txt").write_text(
                hashlib.sha256(spki_der).hexdigest() + "\n"
            )
