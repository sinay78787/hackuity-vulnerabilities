from __future__ import annotations

import argparse
import json
from pathlib import Path

import duckdb

def exists_glob(pattern: str) -> bool:
    return bool(list(Path().glob(pattern)))

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="output/silver")
    args = parser.parse_args()
    root = Path(args.root)
    con = duckdb.connect()
    con.execute("SET preserve_insertion_order=false")
    assets_src = str(root / "assets" / "*.parquet")
    af_src = str(root / "asset_findings" / "*.parquet")
    detail_src = str(root / "finding_details" / "*.parquet")
    if not list((root / "assets").glob("*.parquet")) or not list((root / "asset_findings").glob("*.parquet")):
        raise SystemExit("Exécutez convert_existing_export.py avant ce script")
    q = lambda value: value.replace("\\", "/").replace("'", "''")
    con.execute(f"CREATE VIEW raw_assets AS SELECT * FROM read_parquet('{q(assets_src)}')")
    con.execute(f"CREATE VIEW search_f AS SELECT * FROM read_parquet('{q(af_src)}')")
    has_details = bool(list((root / "finding_details").glob("*.parquet")))
    if has_details:
        con.execute(f"CREATE VIEW details AS SELECT * FROM read_parquet('{q(detail_src)}')")
        join = """SELECT s.assetId, s.hostname, s.findingId,
        coalesce(d.findingName,s.findingName) findingName,
        coalesce(d.status,s.status) status,
        coalesce(d.vulnerabilityTypeId,s.vulnerabilityTypeId) vulnerabilityTypeId,
        coalesce(d.hyScoreV2,s.hyScoreV2) hyScoreV2,
        coalesce(d.cve,s.cve) cve, coalesce(d.cvssScore,s.cvssScore) cvssScore,
        coalesce(d.cvssVector,s.cvssVector) cvssVector,
        coalesce(d.severity,s.severity) severity,
        coalesce(d.description,s.description) description,
        coalesce(d.remediation,s.remediation) remediation,
        coalesce(d.port,s.port) port, coalesce(d.protocol,s.protocol) protocol,
        coalesce(d.service,s.service) service, coalesce(d.provider,s.provider) provider,
        coalesce(d.firstSeen,s.firstSeen) firstSeen, coalesce(d.lastSeen,s.lastSeen) lastSeen,
        coalesce(d.ignored,s.ignored) ignored, coalesce(d.deactivated,s.deactivated) deactivated,
        coalesce(d.expired,s.expired) expired
        ,s.cisaKev cisaKev
        FROM search_f s LEFT JOIN details d USING(findingId)
        QUALIFY row_number() OVER(PARTITION BY s.assetId,s.findingId ORDER BY d.lastSeen DESC NULLS LAST)=1"""
    else:
        join = """SELECT assetId,hostname,findingId,findingName,status,vulnerabilityTypeId,
        hyScoreV2,cve,cvssScore,cvssVector,severity,description,remediation,port,protocol,
        service,provider,firstSeen,lastSeen,ignored,deactivated,expired,cisaKev FROM search_f
        QUALIFY row_number() OVER(PARTITION BY assetId,findingId ORDER BY lastSeen DESC NULLS LAST)=1"""
    con.execute(f"CREATE TABLE merged AS {join}")
    root.mkdir(parents=True, exist_ok=True)
    con.execute(f"COPY (SELECT * FROM raw_assets QUALIFY row_number() OVER(PARTITION BY assetId ORDER BY lastSeen DESC NULLS LAST)=1) TO '{q(str(root / 'assets.parquet'))}' (FORMAT PARQUET, COMPRESSION SNAPPY)")
    con.execute(f"COPY (SELECT * EXCLUDE(assetId,hostname) FROM merged QUALIFY row_number() OVER(PARTITION BY findingId ORDER BY lastSeen DESC NULLS LAST)=1) TO '{q(str(root / 'findings.parquet'))}' (FORMAT PARQUET, COMPRESSION SNAPPY)")
    con.execute(f"COPY (SELECT assetId,findingId,hostname FROM merged) TO '{q(str(root / 'asset_findings.parquet'))}' (FORMAT PARQUET, COMPRESSION SNAPPY)")
    con.execute(f"COPY (SELECT DISTINCT findingId, upper(trim(cve)) cveId FROM merged WHERE cve IS NOT NULL AND cve <> '') TO '{q(str(root / 'finding_cves.parquet'))}' (FORMAT PARQUET, COMPRESSION SNAPPY)")
    con.execute(f"COPY (SELECT cveId FROM read_parquet('{q(str(root / 'finding_cves.parquet'))}') GROUP BY cveId) TO '{q(str(root / 'cves.parquet'))}' (FORMAT PARQUET, COMPRESSION SNAPPY)")
    quality = {
        "assets": con.execute("SELECT count(*) FROM raw_assets").fetchone()[0],
        "relationsBeforeDedup": con.execute("SELECT count(*) FROM search_f").fetchone()[0],
        "relationsAfterDedup": con.execute("SELECT count(*) FROM merged").fetchone()[0],
        "detailEnrichmentUsed": has_details,
    }
    diagnostics = Path("output/diagnostics"); diagnostics.mkdir(parents=True, exist_ok=True)
    (diagnostics / "silver_build_report.json").write_text(json.dumps(quality, indent=2), encoding="utf-8")
    print("Modèle Silver construit")

if __name__ == "__main__":
    main()
