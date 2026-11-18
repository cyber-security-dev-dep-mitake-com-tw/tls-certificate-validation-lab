"""Run against a *real* HTTPS endpoint without copying its TLS private key.

Run on the host (outside the isolated Docker network):
  python src/public_probe.py --host www.example.com --tls 1.3
"""
from __future__ import annotations

import argparse
import json

from detector import inspect_tls


def main():
    parser = argparse.ArgumentParser(description="Validate public TLS endpoint using normal trust")
    parser.add_argument("--host", required=True, help="DNS name you control or may assess")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--servername", help="SNI and hostname verification; defaults to --host")
    parser.add_argument("--tls", choices=("1.1", "1.2", "1.3"), default="1.3")
    parser.add_argument("--ca-file", help="Custom CA trust anchor; default: system CA bundle")
    parser.add_argument("--approved-spki", help="Optional approved SHA256 SPKI hex digest")
    args = parser.parse_args()
    result = inspect_tls(args.host, args.port, args.servername or args.host, args.tls, args.ca_file, args.approved_spki)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["overall_accept"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
