"""SVC2 detector: no access to scenario labels, rogue roots or SVC1 keys.

Runs strict X.509 hostname and chain validation on the *same TLS connection*
used to read peer metadata. This avoids a time-of-check/time-of-use mismatch
between two handshakes when a server rotates its certificate.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID

PROTOCOL_FLAGS = {"1.1": "-tls1_1", "1.2": "-tls1_2", "1.3": "-tls1_3"}
PEM = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
ERROR_PATTERNS = (
    ("HOSTNAME_MISMATCH", ("hostname mismatch",)),
    ("EXPIRED", ("certificate has expired",)),
    ("NOT_YET_VALID", ("certificate is not yet valid",)),
    ("INVALID_PURPOSE", ("unsuitable certificate purpose", "unsupported certificate purpose")),
    ("SELF_SIGNED", ("self-signed certificate", "self signed certificate")),
    ("UNKNOWN_ISSUER", ("unable to get local issuer certificate", "unable to verify the first certificate")),
)


def _execute(args, timeout=7):
    try:
        return subprocess.run(args, text=True, input="", capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def _client_args(host: str, port: int, name: str, version: str):
    args = ["openssl", "s_client", "-connect", f"{host}:{port}",
            "-servername", name, PROTOCOL_FLAGS[version]]
    if version == "1.1":
        args += ["-cipher", "DEFAULT:@SECLEVEL=0"]
    return args


def _parse_leaf(output: str) -> dict:
    matches = PEM.findall(output)
    if not matches:
        return {}
    cert = x509.load_pem_x509_certificate(matches[0].encode())
    san = []
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    pubkey_bytes = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "san_dns": san,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "spki_sha256": hashlib.sha256(pubkey_bytes).hexdigest(),
    }


def _reason(result_text: str, success: bool):
    if success:
        return "VALID"
    low = result_text.lower()
    for code, phrases in ERROR_PATTERNS:
        if any(phrase in low for phrase in phrases):
            return code
    if "certificate verify failed" in low:
        return "VERIFY_FAILED_OTHER"
    return "HANDSHAKE_FAILED"


def inspect_tls(host: str, port: int, servername: str, version: str,
                ca_file: str | None, approved_spki_sha256: str | None = None) -> dict:
    if version not in PROTOCOL_FLAGS:
        raise ValueError("Invalid TLS version")
    base = _client_args(host, port, servername, version)
    # One strict handshake for both identity verification and leaf observation.
    # OpenSSL emits the server-sent leaf in -showcerts even on chain/hostname failure.
    strict_args = base + ["-showcerts", "-verify_hostname", servername,
                          "-purpose", "sslserver", "-verify_return_error"]
    if ca_file:
        strict_args += ["-CAfile", ca_file]
    strict = _execute(strict_args)
    strict_text = "TIMEOUT" if strict is None else strict.stdout + "\n" + strict.stderr
    cert = _parse_leaf(strict_text)
    version_match = re.search(
        r"(?:Protocol\s*:\s*|Protocol version:\s*)(TLSv1\.[123])", strict_text
    )
    observed_version = version_match.group(1) if version_match else None
    authenticated = (
        strict is not None
        and strict.returncode == 0
        and "Verification: OK" in strict_text
    )
    reason = _reason(strict_text, authenticated)
    spki_authorized = None
    if authenticated and approved_spki_sha256 is not None:
        actual_spki = cert.get("spki_sha256")
        spki_authorized = actual_spki is not None and actual_spki.lower() == approved_spki_sha256.lower()
        if not spki_authorized:
            reason = "KEY_NOT_APPROVED"
    return {
        "host": host,
        "port": port,
        "servername": servername,
        "requested_tls": f"TLSv{version}",
        "negotiated_tls": observed_version,
        "certificate_status": reason,
        "certificate_authenticated": bool(authenticated),
        "spki_authorized": spki_authorized,
        "protocol_policy": "DEPRECATED" if version == "1.1" else "ALLOWED",
        "overall_accept": bool(authenticated and (spki_authorized is not False) and version != "1.1"),
        "leaf": cert,
        "verify_excerpt": strict_text.strip()[-1800:],
    }
