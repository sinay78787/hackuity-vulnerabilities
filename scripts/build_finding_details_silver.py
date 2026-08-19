from __future__ import annotations

import argparse
import json
from pathlib import Path

import _bootstrap  # noqa: F401
from hackuity_pipeline.core import load_environment, write_rows
from hackuity_pipeline.finding_details import (
    FINDING_COMPONENT_SCHEMA, FINDING_CVE_SCHEMA, FINDING_DETAIL_SCHEMA, FINDING_EVENT_SCHEMA,
    FINDING_OCCURRENCE_SCHEMA, FINDING_PATH_SCHEMA, FINDING_PROVIDER_SCHEMA,
    FINDING_REFERENCE_SCHEMA, FINDING_SCANNER_REFERENCE_SCHEMA, FINDING_VERSION_SCHEMA,
    cache_is_valid, normalize_detail, normalize_provider_observations,
)
from hackuity_pipeline.evidence.parser import extract_technical_evidence

def main() -> None:
    parser = argparse.ArgumentParser(description="Normalise le cache de détails Hackuity.")
    parser.add_argument("--input-dir", default="output/bronze/finding_details")
    parser.add_argument("--output-dir", default="output/silver")
    args = parser.parse_args()
    config = load_environment(require_api_key=False)
    source, output = Path(args.input_dir), Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    details: list[dict] = []; cves: list[dict] = []; references: list[dict] = []
    paths: list[dict] = []; versions: list[dict] = []; invalid = 0
    providers: list[dict] = []; scanner_refs: list[dict] = []
    components: list[dict] = []; occurrences: list[dict] = []; events: list[dict] = []
    for cache_path in sorted(source.glob("*.json")):
        if cache_path.name.startswith("_"):
            continue
        if not cache_is_valid(cache_path):
            invalid += 1; continue
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
        provider_rows, reference_rows = normalize_provider_observations(cache)
        providers.extend(provider_rows); scanner_refs.extend(reference_rows)
        technical = extract_technical_evidence(cache, str(cache_path))
        components.extend({
            "findingId": item.get("finding_id"), "assetId": item.get("asset_id"), "hostname": item.get("hostname"),
            "componentId": item.get("component_id"), "scanner": item.get("scanner"), "package": item.get("package"),
            "component": item.get("component"), "vendor": item.get("vendor"), "product": item.get("product"),
            "ecosystem": item.get("ecosystem"), "language": item.get("language"),
            "installedVersion": item.get("installed_version"), "requiredVersion": item.get("required_version"),
            "installPath": item.get("install_path"), "scannerReferencesJson": item.get("scanner_references"),
            "sourcePath": item.get("source_path"), "sourcePayloadReference": item.get("source_payload_reference"),
            "sourceHash": item.get("source_hash"), "retrievedAt": item.get("retrieved_at"),
        } for item in technical["components"])
        occurrences.extend({
            "findingId": item.get("finding_id"), "assetId": item.get("asset_id"), "hostname": item.get("hostname"),
            "componentId": item.get("component_id"), "occurrenceId": item.get("occurrence_id"),
            "scanner": item.get("scanner"), "package": item.get("package"),
            "installedVersion": item.get("installed_version"), "requiredVersion": item.get("required_version"),
            "installPath": item.get("install_path"), "scannerReferencesJson": item.get("scanner_references"),
            "sourcePayloadReference": item.get("source_payload_reference"), "sourceHash": item.get("source_hash"),
            "retrievedAt": item.get("retrieved_at"),
        } for item in technical["occurrences"])
        events.extend({"findingId": item.get("finding_id"), "assetId": item.get("asset_id"),
                       "hostname": item.get("hostname"), "eventId": item.get("event_id"),
                       "eventTimestamp": item.get("event_timestamp"), "eventType": item.get("event_type"),
                       "eventLabel": item.get("event_label"), "eventSource": item.get("event_source"),
                       "previousStatus": item.get("previous_status"), "newStatus": item.get("new_status"),
                       "actor": item.get("actor"), "scanner": item.get("scanner"),
                       "rawEventReference": item.get("raw_event_reference")} for item in technical["events"])
        row = normalize_detail(cache, config["app_url"], config["namespace"])
        finding_id, asset_id, provider = row["findingId"], row["assetId"], row["providerId"]
        for cve in row.pop("_cves"):
            cves.append({"findingId": finding_id, "assetId": asset_id, "cve": cve["cve"], "description": cve["description"]})
        for reference in row.pop("_references"):
            references.append({"findingId": finding_id, "cve": reference["cve"], "referenceName": reference["name"], "referenceUrl": reference["url"]})
        evidence = row.pop("_parsedEvidence")
        for path_type, key in (("FILE", "filePaths"), ("REGISTRY", "registryPaths")):
            for value in evidence[key]:
                paths.append({"findingId": finding_id, "assetId": asset_id, "pathType": path_type, "path": value, "providerId": provider})
        detected, expected = evidence["detectedVersions"], evidence["expectedVersions"]
        for index in range(max(len(detected), len(expected), 1)):
            if detected or expected:
                versions.append({
                    "findingId": finding_id, "assetId": asset_id,
                    "component": evidence.get("component"),
                    "detectedVersion": detected[index] if index < len(detected) else None,
                    "expectedVersion": expected[index] if index < len(expected) else None,
                    "sourceText": row["providerEvidenceRaw"],
                })
        details.append(row)
    write_rows(details, output / "finding_details.parquet", FINDING_DETAIL_SCHEMA)
    write_rows(cves, output / "finding_cves.parquet", FINDING_CVE_SCHEMA)
    write_rows(references, output / "finding_references.parquet", FINDING_REFERENCE_SCHEMA)
    write_rows(paths, output / "finding_evidence_paths.parquet", FINDING_PATH_SCHEMA)
    write_rows(versions, output / "finding_versions.parquet", FINDING_VERSION_SCHEMA)
    write_rows(providers, output / "finding_providers.parquet", FINDING_PROVIDER_SCHEMA)
    write_rows(scanner_refs, output / "finding_scanner_references.parquet", FINDING_SCANNER_REFERENCE_SCHEMA)
    write_rows(components, output / "finding_components.parquet", FINDING_COMPONENT_SCHEMA)
    write_rows(occurrences, output / "finding_component_occurrences.parquet", FINDING_OCCURRENCE_SCHEMA)
    write_rows(events, output / "finding_events.parquet", FINDING_EVENT_SCHEMA)
    report = {
        "details": len(details), "cves": len(cves), "references": len(references),
        "paths": len(paths), "versions": len(versions), "providers": len(providers),
        "scannerReferences": len(scanner_refs), "components": len(components),
        "occurrences": len(occurrences), "historyEvents": len(events), "invalidCaches": invalid,
    }
    Path("output/diagnostics").mkdir(parents=True, exist_ok=True)
    Path("output/diagnostics/finding_details_silver_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(f"Silver détails: {len(details)} findings, {len(cves)} CVE, {len(paths)} chemins")

if __name__ == "__main__":
    main()
