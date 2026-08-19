from __future__ import annotations

import argparse
from pathlib import Path

import duckdb

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--silver", default="output/silver")
    parser.add_argument("--gold", default="output/gold")
    parser.add_argument("--critical-trs", type=float, default=900)
    args = parser.parse_args()
    silver, gold = Path(args.silver), Path(args.gold)
    gold.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    q = lambda value: str(value).replace("\\", "/").replace("'", "''")
    con.execute(f"CREATE VIEW assets AS SELECT * FROM read_parquet('{q(silver / 'assets.parquet')}')")
    con.execute(f"CREATE VIEW findings AS SELECT * FROM read_parquet('{q(silver / 'findings.parquet')}')")
    con.execute(f"CREATE VIEW af AS SELECT * FROM read_parquet('{q(silver / 'asset_findings.parquet')}')")
    con.execute("CREATE VIEW instances AS SELECT a.*, f.* EXCLUDE(findingId), af.findingId FROM af JOIN assets a USING(assetId) JOIN findings f USING(findingId)")
    def copy(sql: str, name: str) -> None:
        con.execute(f"COPY ({sql}) TO '{q(gold / name)}' (FORMAT PARQUET, COMPRESSION SNAPPY)")
    copy("""SELECT assetId, any_value(hostname) hostname, any_value(ipAddress) ipAddress,
        any_value(assetOsPrimary) assetOsPrimary, string_agg(DISTINCT provider, ', ') FILTER(provider IS NOT NULL) provider,
        any_value(country) country, any_value(businessUnit) businessUnit,
        max(assetHyScoreV2) assetHyScoreV2, count(*) openFindings,
        count(*) FILTER(hyScoreV2>=900 OR upper(severity)='CRITICAL') criticalFindings,
        count(*) FILTER(upper(severity)='HIGH') highFindings, max(hyScoreV2) maxFindingTrs,
        max(cvssScore) maxCvss, arg_max(cve,hyScoreV2) topCve,
        max(date_diff('day',firstSeen,current_date)) oldestFindingDays, max(lastSeen) lastSeen
        FROM instances GROUP BY assetId""", "asset_summary.parquet")
    copy(f"""SELECT assetId,hostname,ipAddress,assetOsPrimary,findingId,findingName,status,
        hyScoreV2,cve,cvssScore,cvssVector,severity,provider,port,protocol,service,
        description,remediation,firstSeen,lastSeen FROM instances
        WHERE hyScoreV2>={float(args.critical_trs)} OR upper(severity)='CRITICAL'""", "critical_findings.parquet")
    copy("""SELECT cve cveId,count(DISTINCT assetId) affectedAssets,count(*) openInstances,
        max(hyScoreV2) maxTrs,max(cvssScore) maxCvss,arg_max(severity,cvssScore) severity,
        string_agg(DISTINCT provider, ', ') FILTER(provider IS NOT NULL) providers,
        string_agg(DISTINCT assetOsPrimary, ', ') FILTER(assetOsPrimary IS NOT NULL) operatingSystems,
        string_agg(DISTINCT country, ', ') FILTER(country IS NOT NULL) countries,
        arg_max(remediation,hyScoreV2) remediation FROM instances
        WHERE cve IS NOT NULL GROUP BY cve""", "cve_summary.parquet")
    copy("""SELECT substr(sha256(lower(trim(remediation))),1,24) remediationKey,
        any_value(remediation) remediation,count(DISTINCT assetId) affectedAssets,
        count(*) findingCount,count(DISTINCT cve) cveCount,max(hyScoreV2) maxTrs,
        max(cvssScore) maxCvss,string_agg(DISTINCT provider, ', ') FILTER(provider IS NOT NULL) providers,
        CASE WHEN max(hyScoreV2)>=900 OR max(cvssScore)>=9 THEN 'P1'
             WHEN max(hyScoreV2)>=700 OR max(cvssScore)>=7 THEN 'P2' ELSE 'P3' END priority
        FROM instances WHERE remediation IS NOT NULL AND trim(remediation)<>''
        GROUP BY lower(trim(remediation))""", "remediation_summary.parquet")
    print(f"Gold construit dans {gold}")

if __name__ == "__main__":
    main()
