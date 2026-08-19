from __future__ import annotations

import argparse
from pathlib import Path

import duckdb

def quote(path: Path) -> str:
    return str(path).replace("\\", "/").replace("'", "''")

def main() -> None:
    parser = argparse.ArgumentParser(description="Construit les tables Gold de remédiation.")
    parser.add_argument("--silver", default="output/silver")
    parser.add_argument("--gold", default="output/gold")
    args = parser.parse_args()
    silver, gold = Path(args.silver), Path(args.gold)
    required = ["finding_details.parquet", "finding_cves.parquet", "finding_evidence_paths.parquet", "finding_versions.parquet"]
    missing = [name for name in required if not (silver / name).exists()]
    if missing:
        raise SystemExit("Tables Silver de détail absentes: " + ", ".join(missing))
    gold.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    for view, name in (("d", "finding_details.parquet"), ("fc", "finding_cves.parquet"),
                       ("ep", "finding_evidence_paths.parquet"), ("v", "finding_versions.parquet")):
        con.execute(f"CREATE VIEW {view} AS SELECT * FROM read_parquet('{quote(silver / name)}')")
    if (silver / "assets.parquet").exists():
        con.execute(f"CREATE VIEW a AS SELECT * FROM read_parquet('{quote(silver / 'assets.parquet')}')")
    else:
        con.execute("CREATE VIEW a AS SELECT NULL::VARCHAR assetId, NULL::VARCHAR assetOsPrimary WHERE false")
    sql = """SELECT d.findingId,d.assetId,d.hostname,d.ipAddress,a.assetOsPrimary,
        d.findingName,d.status,d.providerId,d.assessmentName,fc.cve,fc.description cveDescription,
        d.cvssScore,d.cvssVector,d.hyScoreV2,d.epssScore,d.cisaKev,
        max(CASE WHEN ep.pathType='REGISTRY' THEN ep.path END)
          OVER(PARTITION BY d.findingId,fc.cve,coalesce(v.component,'')) registryPath,
        max(CASE WHEN ep.pathType='FILE' THEN ep.path END)
          OVER(PARTITION BY d.findingId,fc.cve,coalesce(v.component,'')) filePath,
        v.component,v.detectedVersion,v.expectedVersion,d.providerEvidenceTitle,
        d.providerEvidenceRaw,d.remediation,d.firstSeen,d.lastSeen,
        d.hackuityHistoryUrl,d.extractedAt
        FROM d LEFT JOIN a USING(assetId) LEFT JOIN fc USING(findingId,assetId)
        LEFT JOIN ep USING(findingId,assetId) LEFT JOIN v USING(findingId,assetId)
        QUALIFY row_number() OVER(
          PARTITION BY d.findingId,coalesce(fc.cve,''),coalesce(ep.pathType,''),
          coalesce(ep.path,''),coalesce(v.component,''),coalesce(v.detectedVersion,''),
          coalesce(v.expectedVersion,'') ORDER BY d.extractedAt DESC)=1"""
    con.execute(f"COPY ({sql}) TO '{quote(gold / 'remediation_findings.parquet')}' (FORMAT PARQUET, COMPRESSION SNAPPY)")
    summary = """SELECT
        substr(sha256(concat_ws('|',coalesce(remediation,''),coalesce(providerId,''),
          coalesce(findingName,''),coalesce(component,''),coalesce(expectedVersion,''))),1,24) remediationKey,
        remediation,providerId,component,expectedVersion,
        count(DISTINCT assetId) affectedAssets,count(DISTINCT findingId) affectedFindings,
        count(DISTINCT cve) distinctCves,max(cvssScore) maxCvss,max(hyScoreV2) maxHyScore,
        count(DISTINCT findingId) FILTER(cisaKev) cisaKevFindings,
        to_json(list(DISTINCT cve) FILTER(cve IS NOT NULL)) topCvesJson,
        to_json(list(DISTINCT hostname) FILTER(hostname IS NOT NULL)) topAssetsJson
        FROM read_parquet(?) GROUP BY remediation,providerId,findingName,component,expectedVersion"""
    table = con.execute(summary, [str(gold / "remediation_findings.parquet")]).to_arrow_table()
    import pyarrow.parquet as pq
    pq.write_table(table, gold / "remediation_summary.parquet", compression="snappy")
    count = con.execute("SELECT count(*) FROM read_parquet(?)", [str(gold / "remediation_findings.parquet")]).fetchone()[0]
    print(f"Gold remédiation: {count} lignes")

if __name__ == "__main__":
    main()
