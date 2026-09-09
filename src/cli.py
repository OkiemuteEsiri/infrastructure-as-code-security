from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.analyzer import analyze, should_fail


def load_plan(path: str) -> list[dict]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    resources = data.get("resources") if isinstance(data, dict) else None
    if not isinstance(resources, list):
        raise ValueError("Plan must be an object containing a resources array")
    return resources


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze normalized IaC plan data")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"])
    args = parser.parse_args()

    findings = analyze(load_plan(args.plan))
    for finding in findings:
        print(f"{finding.severity.upper():8} {finding.control_id} {finding.resource}: {finding.message}")

    if args.fail_on and should_fail(findings, args.fail_on):
        sys.exit(2)


if __name__ == "__main__":
    main()
