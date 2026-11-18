"""Port mapping is public; ground truth is intentionally outside detector.py."""
from dataclasses import dataclass

TLS_VERSIONS = ("1.1", "1.2", "1.3")
CASES = (
    "good",
    "self_signed",
    "rogue_ca",
    "wrong_san",
    "expired",
    "future",
    "wrong_eku",
    "unapproved_leaf",
)
PORT_BASE = {
    "good": 15100,
    "self_signed": 15200,
    "rogue_ca": 15300,
    "wrong_san": 15400,
    "expired": 15500,
    "future": 15600,
    "wrong_eku": 15700,
    "unapproved_leaf": 15800,
}
PORT_SUFFIX = {"1.1": 11, "1.2": 12, "1.3": 13}


def port(case: str, tls_version: str) -> int:
    return PORT_BASE[case] + PORT_SUFFIX[tls_version]
