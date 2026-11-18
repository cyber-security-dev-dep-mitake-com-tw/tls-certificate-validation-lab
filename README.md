# TLS Certificate Authenticity & Impersonation Lab

Isolated two-service lab. SVC1 serves fixtures. SVC2 judges only the handshake, the certificate, and the operator policy. It does not receive scenario labels or private keys.

Outcomes are one of `INVALID_CERTIFICATE`, `WEAK_CRYPTOGRAPHY`, or `VALID_BUT_UNAUTHORIZED`. A failed handshake may be the expected `HANDSHAKE_REJECTED`, with no risk class.

## Languages

- **Rust** issues certificates, serves TLS 1.1 / 1.2 / 1.3, harvests public certificates, detects, scores, and hosts the REA / LLM boundary.
- **Zig** serves `possession_failed`: a public certificate only, then a fatal alert after ClientHello. There is no signing key.
- **Julia** generates synthetic weak parameters and analyzes public moduli. `analyze.jl` never returns factors. `oracle.jl` accepts only `origin=synthetic` at or below 512 bits and does not echo primes or exponents.
- The old `src/*.py` files are not started by Compose and are not imported by this path.

## Start

```bash
cp .env.example .env
# Linux/macOS: set HOST_UID and HOST_GID from id -u and id -g
docker compose up --build --abort-on-container-exit --exit-code-from svc2
cat reports/report.json
docker compose down
```

The Compose network stays `internal: true`. No host ports are published.

Read-only harvest from the host, at the default OpenSSL security level:

```bash
cargo run --manifest-path rust/Cargo.toml -p harvester -- --host app.example.com --out baseline
```

`possible_cdn_edge` is a hint. A CDN front usually presents its edge certificate, not the origin certificate.

## What SVC2 is scored on

- Authorized lab certificate: `VALID`.
- Self-signed, unknown issuer, bad SAN, bad dates, bad EKU: `INVALID_CERTIFICATE`.
- Trusted chain with an unapproved SPKI: `KEY_NOT_APPROVED` / `VALID_BUT_UNAUTHORIZED`.
- Copied certificate without the private key: `HANDSHAKE_REJECTED`. The harness separately checks that the public PEM still chains.
- Same valid certificate on a port outside the asset binding: `UNAUTHORIZED_ENDPOINT`.
- 512-bit RSA, oversized public exponent, ROCA fingerprint, shared prime, SHA-1, or a repeated ECDSA `r`: `WEAK_CRYPTOGRAPHY`.

TLS 1.1 is always `DEPRECATED`. TLS 1.3 rejects the 512-bit RSA authentication keys with `HANDSHAKE_REJECTED`. A SHA-1 certificate that still completes the handshake is `WEAK_SIGNATURE`. The Fermat fixture is publicly a short key; the oracle confirms the close primes on the synthetic sample and that confirmation is not given to SVC2.

Batch GCD skips moduli above 1024 bits and does not return the factor. Reports do not contain private keys or prime factors. Weak parameters are generated only for the lab and only at or below 512 bits.

## REA / LLM

`DeterministicRea` recommends detectors from public features and maps the existing verdict to a threat event. `LlmProvider` is disabled unless `LAB_LLM_PROVIDER=scripted` (tests). Extra fields such as a private key are rejected. Advice cannot replace `certificate_status` or `risk_class`.

## Not in this lab

OCSP/CRL, live CT queries, and CAA. Embedded SCTs are recorded only. MD5 signatures are unsupported; the lab does not disable extra digest bans to mint them.

## Limits

- Do not place a production private key in SVC1.
- `SECLEVEL=0` is used only for in-lab handshakes so weak certificates can be observed and then rejected by SVC2.
- A successful PKI check does not prove the server is authorized. Authorization is the SPKI set, issuance log, and endpoint binding.
- This is not a public-CA forger, an intercept proxy, or a general factoring tool.

References: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) · [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) · [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) · [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525)
