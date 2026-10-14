#!/usr/bin/env python3
"""Convert bandit JSON output to SARIF 2.1.0 for GitHub Code Scanning.

Usage:
    python3 bandit_to_sarif.py <input.json> <output.sarif>

Produces a valid SARIF file that can be uploaded via
github/codeql-action/upload-sarif@v4.

Maps bandit fields:
  test_id (B###) -> ruleId
  issue_text    -> message.text
  filename      -> result.locations[0].physicalLocation.artifactLocation.uri
  line_number   -> result.locations[0].physicalLocation.region.startLine
  issue_severity -> security-severity score (HIGH=9.0, MEDIUM=5.0, LOW=3.0)
  more_info     -> helpUri
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

SEVERITY_TO_SCORE = {
    "HIGH": 9.0,
    "MEDIUM": 5.0,
    "LOW": 3.0,
}


def bandit_to_sarif(input_path: Path, output_path: Path) -> None:
    raw = json.loads(input_path.read_text())

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in raw.get("results", []):
        test_id = finding.get("test_id", "UNKNOWN")
        severity = (finding.get("issue_severity") or "MEDIUM").upper()
        score = SEVERITY_TO_SCORE.get(severity, 5.0)

        # Build rule once per test_id (avoid duplicate hashing)
        if test_id not in rules:
            rules[test_id] = {
                "id": test_id,
                "name": finding.get("test_name", "bandit-finding"),
                "shortDescription": {
                    "text": finding.get("test_name", "Bandit security finding"),
                },
                "fullDescription": {
                    "text": finding.get("issue_text", "Bandit finding"),
                },
                "helpUri": finding.get("more_info", "https://bandit.readthedocs.io/"),
                "properties": {
                    "security-severity": str(score),
                    "tags": ["security", "bandit", "sast"],
                },
            }

        results.append({
            "ruleId": test_id,
            "level": "error" if severity == "HIGH" else "warning",
            "message": {"text": finding.get("issue_text", "Bandit finding")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.get("filename", "")},
                    "region": {
                        "startLine": int(finding.get("line_number") or 1),
                        "endLine": int(
                            finding.get("line_range", [1])[-1] if finding.get("line_range") else 1
                        ),
                    },
                },
            }],
        })

    sarif = {
        "$schema": (
            "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "bandit",
                    "version": "1.7.10",
                    "informationUri": "https://bandit.readthedocs.io/",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sarif, indent=2))


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.json> <output.sarif>", file=sys.stderr)
        sys.exit(1)
    bandit_to_sarif(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"Wrote SARIF: {sys.argv[2]}")


if __name__ == "__main__":
    main()