from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

FILES = [
    "output/silver/assets.parquet", "output/silver/findings.parquet",
    "output/silver/asset_findings.parquet", "output/silver/cves.parquet",
    "output/silver/finding_cves.parquet", "output/gold/asset_summary.parquet",
    "output/gold/critical_findings.parquet", "output/gold/cve_summary.parquet",
    "output/gold/remediation_summary.parquet",
]
DETAIL_FILES = [
    "output/silver/finding_details.parquet",
    "output/silver/finding_references.parquet",
    "output/silver/finding_evidence_paths.parquet",
    "output/silver/finding_versions.parquet",
    "output/gold/remediation_findings.parquet",
]

def complex_type(value: pa.DataType) -> bool:
    return any(test(value) for test in (pa.types.is_null, pa.types.is_list,
        pa.types.is_large_list, pa.types.is_struct, pa.types.is_map, pa.types.is_union))

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-missing", action="store_true")
    args = parser.parse_args()
    report: dict = {"files": {}, "checks": [], "blockingErrors": []}
    con = duckdb.connect()
    for name in [*FILES, *DETAIL_FILES]:
        path = Path(name)
        if not path.exists():
            report["blockingErrors"].append(f"Fichier absent: {name}")
            continue
        schema = pq.read_schema(path)
        bad = [field.name for field in schema if complex_type(field.type)]
        count = con.execute("SELECT count(*) FROM read_parquet(?)", [name]).fetchone()[0]
        nulls = {}
        for column in schema.names:
            escaped = column.replace('"', '""')
            nulls[column] = con.execute(
                f'SELECT round(100.0*count(*) FILTER("{escaped}" IS NULL)/nullif(count(*),0),2) FROM read_parquet(?)',
                [name],
            ).fetchone()[0]
        report["files"][name] = {
            "sizeBytes": path.stat().st_size, "rows": count,
            "schema": str(schema), "nullRatesPct": nulls, "complexColumns": bad,
        }
        if bad:
            report["blockingErrors"].append(f"Types Power BI incompatibles dans {name}: {bad}")
    checks = [
        ("assets.assetId unique", "SELECT count(*)=count(DISTINCT assetId) FROM read_parquet('output/silver/assets.parquet')"),
        ("findings.findingId unique", "SELECT count(*)=count(DISTINCT findingId) FROM read_parquet('output/silver/findings.parquet')"),
        ("asset_findings pair unique", "SELECT count(*)=count(DISTINCT (assetId,findingId)) FROM read_parquet('output/silver/asset_findings.parquet')"),
    ]
    detail_path = Path("output/silver/finding_details.parquet")
    if detail_path.exists():
        detail_sql = "read_parquet('output/silver/finding_details.parquet')"
        total = con.execute(f"SELECT count(*) FROM {detail_sql}").fetchone()[0]
        def coverage(column: str) -> float:
            if not total:
                return 0.0
            return float(con.execute(
                f'SELECT round(100.0*count(*) FILTER("{column}" IS NOT NULL AND cast("{column}" as varchar) NOT IN (\'\',\'[]\',\'{{}}\'))/count(*),2) FROM {detail_sql}'
            ).fetchone()[0] or 0)
        enrichment_report_path = Path("output/bronze/finding_details/_enrichment_report.json")
        enrichment_report = json.loads(enrichment_report_path.read_text(encoding="utf-8")) if enrichment_report_path.exists() else {}
        report["enrichment"] = {
            "findingDetailsDownloaded": len([
                path for path in Path("output/bronze/finding_details").glob("*.json")
                if not path.name.startswith("_")
            ]),
            "apiErrors": int(enrichment_report.get("errors", 0)),
            "historicalErrorLogRows": sum(1 for _ in Path("logs/enrich_finding_details_errors.jsonl").open(encoding="utf-8")) if Path("logs/enrich_finding_details_errors.jsonl").exists() else 0,
            "silverRows": total,
            "goldRows": con.execute("SELECT count(*) FROM read_parquet('output/gold/remediation_findings.parquet')").fetchone()[0] if Path("output/gold/remediation_findings.parquet").exists() else 0,
            "cvssCoveragePct": coverage("cvssScore"),
            "cveCoveragePct": coverage("cvesJson"),
            "providerEvidenceCoveragePct": coverage("providerEvidenceRaw"),
            "filePathCoveragePct": coverage("filePathsJson"),
            "registryPathCoveragePct": coverage("registryPathsJson"),
            "detectedVersionCoveragePct": coverage("detectedVersionsJson"),
            "expectedVersionCoveragePct": coverage("expectedVersionsJson"),
        }
        json_columns = ["cvesJson", "cveDescriptionsJson", "referencesJson", "registryPathsJson",
                        "filePathsJson", "detectedVersionsJson", "expectedVersionsJson", "vulnerableSoftwareJson"]
        for column in json_columns:
            invalid = con.execute(
                f'SELECT count(*) FROM {detail_sql} WHERE "{column}" IS NOT NULL AND NOT json_valid("{column}")'
            ).fetchone()[0]
            passed = invalid == 0
            report["checks"].append({"name": f"{column} JSON valide", "passed": passed})
            if not passed:
                report["blockingErrors"].append(f"{column}: {invalid} JSON invalides")
        invalid_urls = con.execute(
            f"SELECT count(*) FROM {detail_sql} WHERE hackuityHistoryUrl IS NOT NULL "
            "AND hackuityHistoryUrl NOT LIKE 'https://%/assets/live-report/%/vuln-management/findings/finding/%/history'"
        ).fetchone()[0]
        if invalid_urls:
            report["blockingErrors"].append(f"URLs History invalides: {invalid_urls}")
        secret_hits = con.execute(
            f"""SELECT count(*) FROM {detail_sql} WHERE
            lower(coalesce(providerEvidenceRaw,'')) LIKE '%authorization:%'
            OR lower(coalesce(providerEvidenceRaw,'')) LIKE '%bearer %'
            OR lower(coalesce(providerEvidenceRaw,'')) LIKE '%hackuity_api_key%'"""
        ).fetchone()[0]
        if secret_hits:
            report["blockingErrors"].append(f"Secrets potentiels dans les sorties: {secret_hits}")
    for label, sql in checks:
        try:
            passed = bool(con.execute(sql).fetchone()[0])
            report["checks"].append({"name": label, "passed": passed})
            if not passed:
                report["blockingErrors"].append(label)
        except duckdb.Error as exc:
            report["blockingErrors"].append(f"{label}: {exc}")
    if args.allow_missing:
        report["blockingErrors"] = [x for x in report["blockingErrors"] if not x.startswith("Fichier absent")]
    output = Path("output/diagnostics"); output.mkdir(parents=True, exist_ok=True)
    (output / "data_quality_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    with (output / "data_quality_report.csv").open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.writer(stream); writer.writerow(["file", "rows", "sizeBytes", "complexColumns"])
        for name, data in report["files"].items():
            writer.writerow([name, data["rows"], data["sizeBytes"], "|".join(data["complexColumns"])])
    print(f"Erreurs bloquantes: {len(report['blockingErrors'])}")
    if report.get("enrichment"):
        metrics = report["enrichment"]
        print(f"Finding details downloaded: {metrics['findingDetailsDownloaded']}")
        print(f"API errors: {metrics['apiErrors']}")
        print(f"CVSS coverage: {metrics['cvssCoveragePct']}%")
        print(f"CVE coverage: {metrics['cveCoveragePct']}%")
        print(f"Provider evidence coverage: {metrics['providerEvidenceCoveragePct']}%")
    raise SystemExit(1 if report["blockingErrors"] else 0)

if __name__ == "__main__":
    main()
