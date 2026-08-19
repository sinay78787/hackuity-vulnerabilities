from __future__ import annotations

import argparse
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb
import requests

import _bootstrap  # noqa: F401
from hackuity_pipeline.api import HackuityClient
from hackuity_pipeline.core import load_environment
from hackuity_pipeline.finding_details import cache_is_valid
from hackuity_pipeline.evidence import extract_technical_evidence

DETAIL_PARAMS = (
    "?withActiveProviderInfos=true&withSearchInfo=true"
    "&withAssessmentInfos=true&withTagsClearValues=true"
)

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def configure_logs() -> tuple[logging.Logger, Path]:
    root = Path("logs"); root.mkdir(parents=True, exist_ok=True)
    log = logging.getLogger("hackuity.enrich")
    log.setLevel(logging.INFO); log.handlers.clear()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    for handler in (logging.StreamHandler(), logging.FileHandler(root / "enrich_finding_details.log", encoding="utf-8")):
        handler.setFormatter(formatter); log.addHandler(handler)
    return log, root / "enrich_finding_details_errors.jsonl"

def error_type(status: int | None) -> str:
    return {
        401: "authentication", 403: "forbidden", 404: "not_found",
        408: "timeout", 429: "rate_limit", 500: "server_error",
        502: "bad_gateway", 503: "unavailable", 504: "gateway_timeout",
    }.get(status, "http_error" if status else "network_error")

def log_error(path: Path, row: dict[str, Any], exc: Exception, retries: int) -> None:
    response = exc.response if isinstance(exc, requests.HTTPError) else None
    status = response.status_code if response is not None else None
    payload = {
        "findingId": row.get("findingId"), "assetId": row.get("assetId"),
        "timestamp": utc_now(), "httpStatus": status,
        "errorType": error_type(status), "message": type(exc).__name__,
        "retryCount": retries,
    }
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False) + "\n")

def candidates(input_path: str, args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.finding_id:
        return [{
            "findingId": args.finding_id, "assetId": None, "hostname": None,
            "status": args.status, "hyScoreV2": None, "cisaKev": False,
        }]
    con = duckdb.connect()
    columns = {row[0] for row in con.execute("DESCRIBE SELECT * FROM read_parquet(?)", [input_path]).fetchall()}
    if "findingId" not in columns:
        raise SystemExit("La source doit contenir findingId")
    def col(name: str, fallback: str) -> str:
        return f'"{name}"' if name in columns else fallback
    sql = f"""SELECT findingId,
        any_value({col('assetId', 'NULL::VARCHAR')}) assetId,
        any_value({col('hostname', 'NULL::VARCHAR')}) hostname,
        any_value({col('status', 'NULL::VARCHAR')}) status,
        max({col('hyScoreV2', 'NULL::DOUBLE')}) hyScoreV2,
        bool_or(coalesce({col('cisaKev', 'false')}, false)) cisaKev
        FROM read_parquet(?) GROUP BY findingId"""
    params: list[Any] = [input_path]
    filters: list[str] = []
    if not args.all_findings:
        if args.status:
            filters.append("(status = ? OR status IS NULL)"); params.append(args.status)
        filters.append("(coalesce(hyScoreV2,0) >= ? OR cisaKev)")
        params.append(args.min_hyscore)
        if args.only_cisa_kev:
            filters.append("cisaKev")
    query = f"SELECT * FROM ({sql})"
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY cisaKev DESC, hyScoreV2 DESC NULLS LAST"
    query += f" LIMIT {int(args.limit)}" if args.limit is not None else ""
    query += f" OFFSET {int(args.offset)}" if args.offset else ""
    return [dict(zip([d[0] for d in con.description], row)) for row in con.execute(query, params).fetchall()]

def main() -> None:
    parser = argparse.ArgumentParser(description="Cache les détails Hackuity prioritaires.")
    parser.add_argument("--input", default="output/silver/finding_ids.parquet")
    parser.add_argument("--output-dir", default="output/bronze/finding_details")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--min-hyscore", "--min-trs", dest="min_hyscore", type=float,
                        default=float(os.environ.get("HACKUITY_DEFAULT_MIN_HYSCORE", "900")))
    parser.add_argument("--status", default="OPEN")
    parser.add_argument("--only-cisa-kev", action="store_true")
    parser.add_argument("--finding-id")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--all-findings", "--all", dest="all_findings", action="store_true",
                        help="Désactive volontairement la sélection prioritaire.")
    parser.add_argument("--diagnostic", action="store_true",
                        help="Limite à 5 findings et affiche les preuves techniques détectées.")
    parser.add_argument("--sleep", "--delay", dest="sleep", type=float, default=0.1)
    parser.add_argument("--max-retries", type=int, default=6)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--verify-ssl", action=argparse.BooleanOptionalAction)
    args = parser.parse_args()
    if args.diagnostic:
        args.limit = min(args.limit or 5, 5)
    log, error_log = configure_logs()
    config = load_environment()
    if args.verify_ssl is not None:
        config["verify_ssl"] = args.verify_ssl
    selected = candidates(args.input, args)
    if not args.finding_id and args.limit is None and not args.all_findings:
        log.warning("%d findings prioritaires sélectionnés; utilisez --limit pour un premier essai.", len(selected))
    client = HackuityClient(config, timeout=args.timeout, max_attempts=args.max_retries)
    output = Path(args.output_dir); output.mkdir(parents=True, exist_ok=True)
    stats = {"selected": len(selected), "downloaded": 0, "skipped": 0, "invalidCache": 0, "errors": 0}
    for index, row in enumerate(selected, start=1):
        finding_id = str(row["findingId"])
        cache = output / f"{finding_id}.json"
        valid = cache_is_valid(cache)
        if cache.exists() and not valid:
            stats["invalidCache"] += 1
        if valid and not args.force:
            stats["skipped"] += 1
            log.info("[%d/%d] cache %s", index, len(selected), finding_id)
            continue
        try:
            detail = client.finding_detail(finding_id)
            endpoint = f"/api/v1/namespaces/{config['namespace']}/findings/{finding_id}{DETAIL_PARAMS}"
            payload = {
                "findingId": finding_id, "assetId": row.get("assetId"),
                "hostname": row.get("hostname"), "status": row.get("status"),
                "hyScoreV2": row.get("hyScoreV2"), "cisaKev": row.get("cisaKev"),
                "extractedAt": utc_now(), "sourceEndpoint": endpoint, "data": detail,
            }
            temporary = cache.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(payload, ensure_ascii=False, default=str), encoding="utf-8")
            temporary.replace(cache)
            stats["downloaded"] += 1
            log.info("[%d/%d] téléchargé %s", index, len(selected), finding_id)
            if args.sleep:
                time.sleep(args.sleep)
        except Exception as exc:
            stats["errors"] += 1
            log_error(error_log, row, exc, args.max_retries)
            log.error("[%d/%d] échec %s (%s)", index, len(selected), finding_id, type(exc).__name__)
    report = {**stats, "apiCalls": client.api_calls, "finishedAt": utc_now()}
    if args.diagnostic:
        diagnostic = {"endpoint": DETAIL_PARAMS, "findings": 0, "components": 0,
                      "versions": 0, "paths": 0, "scannerReferences": 0, "historyEvents": 0}
        for row in selected:
            cache_path = output / f"{row['findingId']}.json"
            if not cache_is_valid(cache_path):
                continue
            evidence = extract_technical_evidence(
                json.loads(cache_path.read_text(encoding="utf-8")), cache_path.as_posix())
            diagnostic["findings"] += 1
            diagnostic["components"] += len(evidence["components"])
            diagnostic["versions"] += sum(bool(item.get("installed_version") or item.get("required_version"))
                                          for item in evidence["components"])
            diagnostic["paths"] += len(evidence["occurrences"])
            diagnostic["scannerReferences"] += sum(len(item["references"]) for item in evidence["scanner_evidence"])
            diagnostic["historyEvents"] += len(evidence["events"])
        report["diagnostic"] = diagnostic
        print(json.dumps(diagnostic, ensure_ascii=False, indent=2))
    (output / "_enrichment_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    log.info("Terminé: téléchargés=%d cache=%d erreurs=%d", stats["downloaded"], stats["skipped"], stats["errors"])
    raise SystemExit(1 if stats["errors"] else 0)

if __name__ == "__main__":
    main()
