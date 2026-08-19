from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import ijson

import _bootstrap  # noqa: F401

TERMS = ("ip", "cve", "cvss", "remedi", "description", "provider", "os",
         "port", "protocol", "date", "seen", "service")
EXPECTED = ("IP", "CVE", "CVSS", "remediation", "description", "provider",
            "OS", "port", "protocol", "dates")

def walk(value: Any, path: str, fields: dict[str, dict[str, Any]]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else key
            entry = fields.setdefault(child_path, {"types": Counter(), "examples": []})
            entry["types"][type(child).__name__] += 1
            if child is not None and not isinstance(child, (dict, list)) and len(entry["examples"]) < 3:
                entry["examples"].append(str(child)[:300])
            walk(child, child_path, fields)
    elif isinstance(value, list):
        for child in value[:10]:
            walk(child, f"{path}[]", fields)

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", nargs="?", default="hackuity_all_open_findings.json")
    parser.add_argument("--assets", type=int, default=5)
    parser.add_argument("--output", default="output/diagnostics/export_schema_report.json")
    args = parser.parse_args()
    fields: dict[str, dict[str, Any]] = {}
    asset_keys: set[str] = set()
    finding_keys: set[str] = set()
    findings_seen = 0
    first_finding: dict[str, Any] | None = None
    with Path(args.source).open("rb") as stream:
        for index, asset in enumerate(ijson.items(stream, "item")):
            asset_keys.update(asset)
            walk(asset, "", fields)
            container = asset.get("findings")
            rows = container.get("searchFindings") if isinstance(container, dict) else None
            if isinstance(rows, list):
                for finding in rows[:100]:
                    if isinstance(finding, dict):
                        finding_keys.update(finding)
                        findings_seen += 1
                        first_finding = first_finding or finding
            if index + 1 >= args.assets:
                break
    candidates = {
        term: sorted(path for path in fields if term.lower() in path.lower())
        for term in TERMS
    }
    report = {
        "sample": {"assets": args.assets, "findings": findings_seen},
        "assetKeys": sorted(asset_keys),
        "findingKeys": sorted(finding_keys),
        "searchFindingsPath": "item.findings.searchFindings",
        "fields": {
            path: {"types": dict(data["types"]), "examples": data["examples"],
                   "nested": "[]" in path or "." in path}
            for path, data in sorted(fields.items())
        },
        "candidateFields": candidates,
        "missingConcepts": [
            concept for concept in EXPECTED
            if not any(concept.lower() in path.lower() for path in fields)
        ],
        "entirelyNullInSample": sorted(
            path for path, data in fields.items()
            if data["types"] and set(data["types"]) == {"NoneType"}
        ),
        "firstFinding": first_finding,
        "warning": "Présence dans l'échantillon uniquement; valider le mapping sur le détail API.",
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"Rapport: {output}")
    print(f"Asset keys: {sorted(asset_keys)}")
    print(f"Finding keys: {sorted(finding_keys)}")

if __name__ == "__main__":
    main()
