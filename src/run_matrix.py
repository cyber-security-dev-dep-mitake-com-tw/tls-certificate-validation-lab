"""Ground-truth harness. Only this file contains expected classifications."""
from __future__ import annotations

import csv
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from config import CASES, TLS_VERSIONS, port
from detector import inspect_tls

GROUND_TRUTH = {
    "good": "VALID",
    "self_signed": "SELF_SIGNED",
    "rogue_ca": "UNKNOWN_ISSUER",
    "wrong_san": "HOSTNAME_MISMATCH",
    "expired": "EXPIRED",
    "future": "NOT_YET_VALID",
    "wrong_eku": "INVALID_PURPOSE",
    "unapproved_leaf": "KEY_NOT_APPROVED",
}


def run():
    hostname = os.getenv("LAB_DOMAIN", "tls-lab.example.test")
    target = os.getenv("LAB_HOST", "127.0.0.1")
    ca_file = os.getenv("LAB_TRUST_FILE", "/trust/trusted_root_ca.pem")
    pin_path = os.getenv("APPROVED_SPKI_FILE", "/trust/approved_spki_sha256.txt")
    approved_spki = Path(pin_path).read_text().strip()
    output_dir = Path(os.getenv("REPORT_DIR", "./reports"))
    output_dir.mkdir(parents=True, exist_ok=True)
    cases = []
    for case in CASES:
        for ver in TLS_VERSIONS:
            result = inspect_tls(target, port(case, ver), hostname, ver, ca_file, approved_spki)
            result["scenario"] = case
            result["expected_certificate_status"] = GROUND_TRUTH[case]
            result["reason_correct"] = result["certificate_status"] == GROUND_TRUTH[case]
            result["protocol_correct"] = result["protocol_policy"] == (
                "DEPRECATED" if ver == "1.1" else "ALLOWED"
            )
            result["transport_correct"] = result["negotiated_tls"] == f"TLSv{ver}"
            actual_bad = result["certificate_status"] != "VALID"
            expected_bad = GROUND_TRUTH[case] != "VALID"
            result["binary_correct"] = actual_bad == expected_bad
            cases.append(result)
            print(f"{case:12s} TLS{ver} -> {result['certificate_status']:20s} "
                  f"proto={result['negotiated_tls']} policy={result['protocol_policy']} "
                  f"reason={'PASS' if result['reason_correct'] else 'FAIL'}", flush=True)
    cm = Counter()
    for r in cases:
        actual_bad = r["certificate_status"] != "VALID"
        expected_bad = r["expected_certificate_status"] != "VALID"
        cm[("TP" if expected_bad else "FP") if actual_bad else ("FN" if expected_bad else "TN")] += 1
    summary = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "test_count": len(cases),
        "binary_correct": sum(c["binary_correct"] for c in cases),
        "reason_correct": sum(c["reason_correct"] for c in cases),
        "protocol_correct": sum(c["protocol_correct"] for c in cases),
        "transport_correct": sum(c["transport_correct"] for c in cases),
        "confusion_matrix": {name: cm[name] for name in ("TP", "TN", "FP", "FN")},
        "cases": cases,
    }
    (output_dir / "report.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    with (output_dir / "report.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=(
            "scenario", "requested_tls", "negotiated_tls", "certificate_status",
            "expected_certificate_status", "protocol_policy", "overall_accept",
            "binary_correct", "reason_correct", "transport_correct", "certificate_authenticated", "spki_authorized",
        ))
        writer.writeheader()
        for r in cases:
            writer.writerow({field: r.get(field) for field in writer.fieldnames})
    print("\nSUMMARY", json.dumps({k: v for k, v in summary.items() if k != "cases"}, indent=2))
    # Fail CI if any test fails. An unavailable TLS1.1 handshake is a test infrastructure
    # issue, not a certificate forgery detection success.
    ok = all(c["reason_correct"] and c["transport_correct"] and c["protocol_correct"] for c in cases)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(run())
