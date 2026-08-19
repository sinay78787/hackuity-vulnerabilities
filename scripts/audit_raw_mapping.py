from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import pyarrow.parquet as pq

import _bootstrap  # noqa: F401
from hackuity_pipeline.evidence.parser import extract_technical_evidence
from hackuity_pipeline.finding_details import cache_is_valid, normalize_provider_observations


def scalar_paths(value: Any, path: str = "data") -> Counter[str]:
    result: Counter[str] = Counter()
    if isinstance(value, Mapping):
        for key, child in value.items():
            result.update(scalar_paths(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for child in value:
            result.update(scalar_paths(child, f"{path}[]"))
    elif value not in (None, ""):
        result[path] += 1
    return result


def keys(rows: Iterable[Mapping[str, Any]], fields: tuple[str, ...]) -> set[tuple[str, ...]]:
    def canonical(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return str(value)
    return {tuple(canonical(row.get(field)) for field in fields) for row in rows}


def parquet_rows(path: Path) -> list[dict[str, Any]]:
    return pq.read_table(path).to_pylist() if path.exists() else []


def metric(name: str, expected: set[tuple[str, ...]], actual: set[tuple[str, ...]]) -> dict[str, Any]:
    missing, unexpected = sorted(expected - actual), sorted(actual - expected)
    matched = len(expected & actual)
    return {
        "domain": name, "availableRaw": len(expected), "structured": len(actual),
        "matched": matched, "missing": len(missing), "unexpected": len(unexpected),
        "coveragePct": round(100.0 * matched / len(expected), 2) if expected else 100.0,
        "missingExamples": [list(item) for item in missing[:10]],
        "unexpectedExamples": [list(item) for item in unexpected[:10]],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Prouve la couverture RAW vers Silver des détails Hackuity.")
    parser.add_argument("--input-dir", default="output/bronze/finding_details")
    parser.add_argument("--silver-dir", default="output/silver")
    parser.add_argument("--output-dir", default="output/diagnostics")
    args = parser.parse_args()
    source, silver, output = Path(args.input_dir), Path(args.silver_dir), Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    expected_details: list[dict[str, Any]] = []
    expected_providers: list[dict[str, Any]] = []
    expected_refs: list[dict[str, Any]] = []
    expected_components: list[dict[str, Any]] = []
    expected_occurrences: list[dict[str, Any]] = []
    expected_events: list[dict[str, Any]] = []
    inventory: Counter[str] = Counter(); invalid: list[str] = []
    files = [path for path in sorted(source.glob("*.json")) if not path.name.startswith("_")]
    for path in files:
        if not cache_is_valid(path):
            invalid.append(str(path)); continue
        cache = json.loads(path.read_text(encoding="utf-8"))
        inventory.update(scalar_paths(cache))
        detail = cache.get("data") if isinstance(cache.get("data"), Mapping) else {}
        expected_details.append({"findingId": cache.get("findingId") or detail.get("findingId") or detail.get("id"),
                                 "assetId": cache.get("assetId") or detail.get("assetId")})
        providers, refs = normalize_provider_observations(cache)
        expected_providers.extend(providers); expected_refs.extend(refs)
        evidence = extract_technical_evidence(cache, str(path))
        expected_components.extend(evidence["components"])
        expected_occurrences.extend(evidence["occurrences"])
        expected_events.extend(evidence["events"])

    checks = [
        metric("finding_details", keys(expected_details, ("findingId", "assetId")),
               keys(parquet_rows(silver / "finding_details.parquet"), ("findingId", "assetId"))),
        metric("provider_observations", keys(expected_providers, ("findingId", "assetId", "providerId", "assessmentId")),
               keys(parquet_rows(silver / "finding_providers.parquet"), ("findingId", "assetId", "providerId", "assessmentId"))),
        metric("cvss_base_values", keys(expected_providers, ("findingId", "providerId", "assessmentId", "baseScore")),
               keys(parquet_rows(silver / "finding_providers.parquet"), ("findingId", "providerId", "assessmentId", "baseScore"))),
        metric("first_detections", keys(expected_providers, ("findingId", "providerId", "assessmentId", "firstDetection")),
               keys(parquet_rows(silver / "finding_providers.parquet"), ("findingId", "providerId", "assessmentId", "firstDetection"))),
        metric("scanner_references", keys(expected_refs, ("findingId", "providerId", "assessmentId", "referenceType", "referenceValue")),
               keys(parquet_rows(silver / "finding_scanner_references.parquet"), ("findingId", "providerId", "assessmentId", "referenceType", "referenceValue"))),
        metric("components", keys(expected_components, ("finding_id", "asset_id", "component_id", "scanner", "installed_version", "required_version")),
               keys(parquet_rows(silver / "finding_components.parquet"), ("findingId", "assetId", "componentId", "scanner", "installedVersion", "requiredVersion"))),
        metric("component_occurrences", keys(expected_occurrences, ("finding_id", "asset_id", "occurrence_id", "install_path")),
               keys(parquet_rows(silver / "finding_component_occurrences.parquet"), ("findingId", "assetId", "occurrenceId", "installPath"))),
        metric("history_events", keys(expected_events, ("finding_id", "asset_id", "event_id", "event_timestamp", "event_type")),
               keys(parquet_rows(silver / "finding_events.parquet"), ("findingId", "assetId", "eventId", "eventTimestamp", "eventType"))),
    ]
    complete = not invalid and all(item["missing"] == 0 for item in checks)
    report = {
        "status": "COMPLETE" if complete else "INCOMPLETE", "rawFiles": len(files),
        "validRawFiles": len(files) - len(invalid), "invalidRawFiles": invalid,
        "checks": checks,
        "scopeStatement": "La complétude est prouvée pour les domaines explicitement mappés; le payload RAW intégral reste conservé en Bronze.",
        "rawScalarPathCount": len(inventory),
        "rawScalarPaths": [{"path": path, "populatedValues": count} for path, count in sorted(inventory.items())],
    }
    (output / "raw_mapping_completeness.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    with (output / "raw_mapping_completeness.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["domain", "availableRaw", "structured", "matched", "missing", "unexpected", "coveragePct"])
        writer.writeheader(); writer.writerows({key: row[key] for key in writer.fieldnames} for row in checks)
    print(f"Audit mapping: {report['status']} - {len(files) - len(invalid)}/{len(files)} caches valides")
    for row in checks:
        print(f"  {row['domain']}: {row['coveragePct']:.2f}% ({row['matched']}/{row['availableRaw']}), manquants={row['missing']}")
    raise SystemExit(0 if complete else 2)


if __name__ == "__main__":
    main()
