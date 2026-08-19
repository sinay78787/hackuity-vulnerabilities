from __future__ import annotations

import argparse
import gzip
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import _bootstrap  # noqa: F401
from hackuity_pipeline.api import HackuityClient
from hackuity_pipeline.core import configure_logging, load_environment

def now() -> str:
    return datetime.now(timezone.utc).isoformat()

def atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    temporary.replace(path)


def normalize_hostname(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def asset_hostnames(asset: dict[str, Any]) -> list[str]:
    values = [
        asset.get("hostname"), asset.get("fqdn"),
        asset.get("assetEffectiveName"), asset.get("assetAbsoluteName"),
        asset.get("name"),
    ]
    return sorted({normalized for value in values if (normalized := normalize_hostname(value))})


def hostname_matches(asset: dict[str, Any], requested: str | None) -> bool:
    if not requested:
        return True
    target = normalize_hostname(requested)
    names = asset_hostnames(asset)
    if "." in target:
        return target in names
    return any(name.split(".", 1)[0] == target for name in names)


def asset_payload(offset: int, limit: int, hostname: str | None, asset_id: str | None) -> dict:
    rules = [{"type": "rule", "properties": {"field": "asset.state", "fieldSrc": "field",
        "operator": "multiselect_in", "value": [["DEFAULT"]], "valueSrc": ["value"],
        "valueType": ["multiselect"]}}]
    # Le Query Engine de search/assets rejette l'opérateur "like".
    # La requête globale est conservée et le hostname est filtré côté Python.
    if asset_id:
        rules.append({"type": "rule", "properties": {"field": "asset.id", "fieldSrc": "field",
            "operator": "equal", "value": [asset_id], "valueSrc": ["value"], "valueType": ["text"]}})
    return {"query": {"type": "group", "children1": rules, "properties": {"conjunction": "AND", "not": False}},
            "searchCriteriaType": "QUERY_ENGINE", "offset": offset, "limit": limit}

def finding_payload(asset_id: str, offset: int, limit: int) -> dict:
    return {"assetIds": [asset_id], "query": {"type": "group", "children1": [],
        "properties": {"conjunction": "AND", "not": False}},
        "searchCriteriaType": "QUERY_ENGINE", "offset": offset, "limit": limit,
        "sortFields": [{"fieldName": "findingStatus.score.hyScoreV2", "desc": True}]}

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hostname")
    parser.add_argument("--asset-id")
    parser.add_argument("--max-assets", type=int)
    parser.add_argument("--include-details", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--output-dir", default="output/bronze/incremental")
    parser.add_argument("--verify-ssl", action=argparse.BooleanOptionalAction)
    parser.add_argument("--page-size", type=int, default=500)
    args = parser.parse_args()
    log = configure_logging()
    config = load_environment()
    if args.verify_ssl is not None:
        config["verify_ssl"] = args.verify_ssl
    client = HackuityClient(config)
    root = Path(args.output_dir); raw = root / "raw"; checkpoints = root / "checkpoints"
    raw.mkdir(parents=True, exist_ok=True); checkpoints.mkdir(parents=True, exist_ok=True)
    manifest_path = root / "manifest.json"
    manifest = {
        "runId": str(uuid.uuid4()), "startedAt": now(), "finishedAt": None,
        "status": "running", "assetsProcessed": 0, "findingsProcessed": 0,
        "detailsProcessed": 0, "failedAssets": [], "failedFindings": [],
        "apiCalls": 0, "outputFiles": [], "errors": [],
    }
    if args.resume and manifest_path.exists():
        previous = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["runId"] = previous.get("runId", manifest["runId"])
        manifest["startedAt"] = previous.get("startedAt", manifest["startedAt"])
    atomic_json(manifest_path, manifest)
    hostname_not_found = False
    hostname_matches_seen = 0
    try:
        offset = 0
        while True:
            data = client.request("POST", f"/api/v1/namespaces/{config['namespace']}/search/assets",
                                  json=asset_payload(offset, args.page_size, args.hostname, args.asset_id))
            assets = data.get("searchAssets", [])
            if not assets:
                break
            api_page_size = len(assets)
            if args.hostname:
                matching_assets = [asset for asset in assets if hostname_matches(asset, args.hostname)]
                log.info(
                    "Recherche hostname %s: page offset=%d, %d/%d asset(s) correspondant(s)",
                    args.hostname, offset, len(matching_assets), len(assets),
                )
                hostname_matches_seen += len(matching_assets)
                assets = matching_assets
            for asset in assets:
                asset_id = asset.get("assetId")
                if not asset_id:
                    continue
                checkpoint = checkpoints / f"{asset_id}.done"
                if args.resume and checkpoint.exists():
                    continue
                asset_findings: list[dict] = []
                finding_offset = 0
                try:
                    while True:
                        result = client.request("POST", f"/api/v1/namespaces/{config['namespace']}/search/findings",
                                                json=finding_payload(asset_id, finding_offset, args.page_size))
                        page = result.get("searchFindings", [])
                        asset_findings.extend(page)
                        manifest["findingsProcessed"] += len(page)
                        if len(page) < args.page_size:
                            break
                        finding_offset += args.page_size
                    target = raw / f"{asset_id}.json.gz"
                    with gzip.open(target, "wt", encoding="utf-8") as stream:
                        json.dump({"asset": asset, "findings": asset_findings}, stream, ensure_ascii=False)
                    checkpoint.write_text(now(), encoding="utf-8")
                    manifest["outputFiles"].append(str(target))
                    manifest["assetsProcessed"] += 1
                except Exception as exc:
                    manifest["failedAssets"].append(asset_id)
                    manifest["errors"].append({"assetId": asset_id, "error": type(exc).__name__})
                atomic_json(manifest_path, manifest)
                if args.max_assets and manifest["assetsProcessed"] >= args.max_assets:
                    break
            if args.max_assets and manifest["assetsProcessed"] >= args.max_assets:
                break
            if api_page_size < args.page_size:
                break
            offset += args.page_size
        if args.hostname and hostname_matches_seen == 0:
            log.warning("Aucun asset Hackuity ne correspond au hostname %s", args.hostname)
            hostname_not_found = True
        if args.include_details:
            log.warning("--include-details est volontairement différé: lancez enrich_finding_details.py avec une limite explicite.")
        manifest["status"] = (
            "not_found" if hostname_not_found else
            "completed" if not manifest["failedAssets"] else "completed_with_errors"
        )
    except Exception as exc:
        manifest["status"] = "failed"; manifest["errors"].append({"error": type(exc).__name__})
        raise
    finally:
        manifest["finishedAt"] = now(); manifest["apiCalls"] = client.api_calls
        atomic_json(manifest_path, manifest)
    if hostname_not_found:
        raise SystemExit(f"Asset Hackuity introuvable: {args.hostname}")

if __name__ == "__main__":
    main()
