# TLS Certificate Authenticity & Protocol Validation Lab

An **offline-first, two-service, non-production** security training lab for TLS 1.1 / 1.2 / 1.3 handshake compatibility, X.509 chain authentication and detection effectiveness.

**Important:** X.509 certificates are not version-specific to TLS 1.1/1.2/1.3. Treat the negotiated protocol version and the certificate authentication outcome as *separate* control objectives. TLS 1.1 was deprecated in RFC 8996 and is enabled only inside an isolated Docker network for detection testing.

## 1. Architecture and isolation

```
                           Docker internal: true network
  +-------------------------------------------------------------+
  | SVC1 (fixture server)                                       |
  |   generates one explicitly trusted local CA + one rogue CA  |
  |   8 certificate cases x 3 TLS protocol versions             |
  |   24 HTTPS/TLS listeners; no published host ports           |
  |                                                             |
  |  (TLS handshake)                                            |
  |         |                                                   |
  |         v                                                   |
  | SVC2 (certificate detector)                                 |
  |   one strict s_client handshake -> leaf, protocol, verdict   |
  |   no insecure verification fallback or second probe        |
  |   root anchor: only the trusted lab CA certificate          |
  |         |                                                   |
  |         v                                                   |
  | Evaluation harness (separate from detector.py)              |
  |   known ground truth -> TP / TN / FP / FN + reason accuracy  |
  +-------------------------------------------------------------+
```

- Only the **authorized public root certificate and approved SPKI hash** are mounted into SVC2. SVC2 is NOT given the SVC1 leaf private keys or rogue root certificate. The detector module never receives scenario labels; the evaluation harness has a separate ground-truth table.
- SVC1 uses the `LAB_DOMAIN` only for SAN, SNI and hostname matching. The default `tls-lab.example.test` needs no public DNS. You may replace it with a subdomain under a domain you own.
- The lab does **not** add any CA to the host OS, browser, or application trust stores.
- Docker Compose does **not** publish ports. `internal: true` isolates the network from external access. Keep this setting.
- Fixture private keys exist only in the SVC1 container's ephemeral `/state`. Never use live production private keys in this lab.

## 2. Requirements

- Docker Engine with Docker Compose v2
- Ability to build a Python 3.12-slim image and install Python dependencies once. Runtime is offline.
- OpenSSL 3.x capable of TLS 1.1 at security level 0. Some distro/OpenSSL builds may disable TLS 1.1 entirely; in that case treat the inability to establish TLS 1.1 as an environment limitation, not a detection PASS.

## 3. Start and evaluate

```bash
cp .env.example .env
# Optional: edit LAB_DOMAIN=tls-lab.<YOUR-OWN-DOMAIN>
# Linux/macOS: set HOST_UID=$(id -u), HOST_GID=$(id -g) inside .env
# Windows Docker Desktop: start with the defaults and adjust only if needed.
docker compose up --build --abort-on-container-exit --exit-code-from svc2

# Results
cat reports/report.json
cat reports/report.csv

# Shutdown
docker compose down
```

To reset the trusted CA and test fixtures:

```bash
docker compose down --volumes
```

Do not use `docker compose down --volumes` on an unrelated Compose project.

## 4. Scenario matrix and ports

Each scenario has three protocol-version endpoints (TLS 1.1 / TLS 1.2 / TLS 1.3):

| Scenario | TLS 1.1 | TLS 1.2 | TLS 1.3 | Expected certificate result |
|---|---:|---:|---:|---|
| `good` | 15111 | 15112 | 15113 | `VALID` |
| `self_signed` | 15211 | 15212 | 15213 | `SELF_SIGNED` |
| `rogue_ca` | 15311 | 15312 | 15313 | `UNKNOWN_ISSUER` |
| `wrong_san` | 15411 | 15412 | 15413 | `HOSTNAME_MISMATCH` |
| `expired` | 15511 | 15512 | 15513 | `EXPIRED` |
| `future` | 15611 | 15612 | 15613 | `NOT_YET_VALID` |
| `wrong_eku` | 15711 | 15712 | 15713 | `INVALID_PURPOSE` |
| `unapproved_leaf` | 15811 | 15812 | 15813 | `KEY_NOT_APPROVED` |

The certificate validly issued by the trusted **lab** CA is the local positive control, not a certificate publicly issued by a commercial CA. `unapproved_leaf` deliberately has a **valid trusted CA chain, valid SAN, valid dates, and correct EKU**, but a different public key from the approved SPKI baseline. It is rejected by **authorization policy**, not by ordinary X.509 validation. The rogue root is valid cryptographically but deliberately **not trusted by SVC2**. A certificate cannot be judged rogue solely from its X.509 bytes if a client has already accepted its rogue root as trusted.

## 5. Expected detection results

- Certificate reason accuracy: **24 / 24** when all protocols are supported.
- Binary (authorized vs non-authorized under the lab policy): `TP=21`, `TN=3`, `FP=0`, `FN=0`.
- Protocol policy: **all eight TLS 1.1 tests** are `DEPRECATED`, including the good leaf certificate. TLS 1.2/1.3 are `ALLOWED` by this protocol-only policy.
- `overall_accept` is true *only* if the certificate validates and the protocol version is allowed; therefore `good` TLS 1.1 has `certificate_status=VALID`, `protocol_policy=DEPRECATED` and `overall_accept=false`.

`TP` refers to detected certificate anomalies, not proven malicious intent. `TN` is the three good-certificate endpoints.

## 6. Separate live public-domain baseline

Do not move a production TLS private key into SVC1. Instead run SVC2-style checks directly against the real authorized HTTPS endpoint. Example:

```bash
openssl s_client \
  -connect app.yourdomain.com:443 \
  -servername app.yourdomain.com \
  -verify_hostname app.yourdomain.com \
  -purpose sslserver \
  -verify_return_error \
  -tls1_3 -brief </dev/null
```

You can use the provided independent host-side probe (requires `pip install -r requirements.txt` and an installed `openssl` executable):

```bash
python src/public_probe.py --host app.yourdomain.com --tls 1.3
python src/public_probe.py --host app.yourdomain.com --tls 1.2
```

Both methods use the system's normal public trust source rather than the lab CA. You can repeat with `-tls1_2` to check protocol support; many public endpoints have disabled TLS 1.1, as they should. Compare live-domain certificate fingerprint, issuing CA and SAN with your approved configuration, without downloading any private keys.

## 7. Limits and future tests

1. `VALID` means *cryptographically verifiable under the configured trust anchor and hostname policy*; it does not prove legal ownership or absence of a compromised trusted CA.
2. Revocation (OCSP/CRL), CT log auditing, CAA, certificate-policy checks, weak signature checks and **production-grade SPKI rotation management** are **not yet implemented**. Do not mistake the MVP results for full PKI assurance.
3. `s_client -showcerts -verify_return_error` reads peer certificate and verifies the same connection. An additional SPKI allowlist check applies only after successful chain validation. SPKI mismatches may also be legitimate key rotations; do not enable automatic blocking in production without rotation support.
4. TLS 1.1 needs OpenSSL `@SECLEVEL=0` and is restricted to local tests. Do not use that setting for live production TLS validation.
5. Certificate chain metadata is parsed from the same strict OpenSSL handshake that performs chain validation, hostname verification and intended TLS server purpose checks.
6. This is not a test of encryption downgrade resistance, certificate transparency policy or TLS interception detection. Those require additional scenarios and/or externally controlled observations.

## 8. Relevant standards

- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) — X.509 certificate and CRL profile
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3
- [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) — TLS 1.0/1.1 deprecation
- [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525) — Service identity (SAN) verification
- [OpenSSL s_client](https://docs.openssl.org/3.0/man1/openssl-s_client/) — CLI verification

## 9. Optional demonstration: a rogue root can make an unauthorized chain verify

The **SVC2** detector purposely trusts only the authorized lab root. For an isolated trust-injection demonstration, execute a command *inside SVC1* with a **different, explicitly supplied CAfile**:

```bash
docker compose exec svc1 openssl s_client \
  -connect 127.0.0.1:15312 -servername tls-lab.example.test \
  -verify_hostname tls-lab.example.test -purpose sslserver \
  -verify_return_error -CAfile /state/rogue_root.pem \
  -tls1_2 -brief </dev/null
```

Use the `LAB_DOMAIN` value from `.env` for `-servername` and `-verify_hostname` if you changed it. This check is expected to verify successfully because you explicitly trust the rogue CA for that *single OpenSSL process*. The SVC2 baseline must still reject it. This is why a successful normal chain check **alone** cannot prove authorization when the trusted roots themselves are compromised. Do not import the rogue CA into the host trust store.
