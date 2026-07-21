"""Command-line entry point."""

import argparse
import json
from pathlib import Path

from .engine import audit_bundle


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit a JSON configuration bundle for exposed secrets")
    parser.add_argument("input", type=Path)
    parser.add_argument("--fail-on-findings", action="store_true")
    args = parser.parse_args()
    report = audit_bundle(json.loads(args.input.read_text(encoding="utf-8")))
    print(json.dumps(report, indent=2))
    if args.fail_on_findings and report["decision"] == "BLOCK":
        raise SystemExit(2)


if __name__ == "__main__":
    main()

