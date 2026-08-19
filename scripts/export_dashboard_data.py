from __future__ import annotations

import argparse
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
import ijson


def catalog_entry(path: Path, root: Path) -> dict[str, Any]:
    """Décrit un fichier de données sans charger son contenu complet en mémoire."""
    path = path.resolve()
    root = root.resolve()
    relative = path.relative_to(root).as_posix()
    suffix = path.suffix.lower().lstrip(".") or "file"
    layer = next((part for part in ("bronze", "silver", "gold", "exports") if part in relative.lower().split("/")), "source")
    entry: dict[str, Any] = {
        "name": path.name, "path": relative, "format": suffix.upper(),
        "layer": layer, "sizeBytes": path.stat().st_size, "rows": None, "fields": [],
    }
    if suffix == "parquet":
        parquet = pq.ParquetFile(path)
        entry["rows"] = parquet.metadata.num_rows
        entry["fields"] = [
            {"name": field.name, "type": str(field.type), "nullable": field.nullable}
            for field in parquet.schema_arrow
        ]
    return entry


def build_catalog(root: Path, output: Path) -> list[dict[str, Any]]:
    candidates = [
        root / "hackuity_all_open_findings.json",
        root / "hackuity_findings_asset.json",
        root / "hackuity_target_assets.json",
    ]
    for directory in (root / "output", root / "exports"):
        if directory.exists():
            candidates.extend(path for path in directory.rglob("*") if path.is_file())
    if output.exists():
        candidates.append(output)
    return [catalog_entry(path, root) for path in sorted(set(candidates)) if path.exists()]


def json_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if hasattr(value, "item"):
        return value.item()
    return value


def read_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        {key: json_value(value) for key, value in row.items()}
        for row in pq.read_table(path).to_pylist()
    ]


def score_severity(cvss: Any, trs: Any, source: Any = None) -> str:
    if source:
        return str(source).upper()
    cvss_value, trs_value = float(cvss or 0), float(trs or 0)
    if cvss_value >= 9 or trs_value >= 900:
        return "CRITICAL"
    if cvss_value >= 7 or trs_value >= 700:
        return "HIGH"
    if cvss_value >= 4 or trs_value >= 400:
        return "MEDIUM"
    return "LOW"


def age_days(value: Any) -> int | None:
    if not value:
        return None
    try:
        observed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - observed).days)
    except (TypeError, ValueError):
        return None


def priority_for(trs: Any, cvss: Any, kev: Any = False, age: Any = 0) -> tuple[str, int, int]:
    trs_value, cvss_value, age_value = float(trs or 0), float(cvss or 0), int(age or 0)
    score = min(100, round(trs_value / 10 * .5 + cvss_value * 10 * .3 + min(age_value, 365) / 365 * 10 + (10 if kev else 0)))
    if kev or trs_value >= 900 or cvss_value >= 9:
        return "P1", score, 7
    if trs_value >= 700 or cvss_value >= 7 or age_value >= 180:
        return "P2", score, 30
    return "P3", score, 90


def fallback_action(row: dict[str, Any]) -> str:
    component = row.get("component")
    expected = row.get("expectedVersion")
    if component and expected:
        return f"Mettre à jour {component} vers la version {expected}, puis valider la disparition du finding."
    cve = row.get("cve") or row.get("cveId")
    if cve:
        return f"Appliquer le correctif éditeur associé à {cve}, redémarrer si requis, puis relancer un scan de validation."
    service = row.get("service")
    if service:
        return f"Corriger ou désactiver le service {service} s’il n’est pas nécessaire, puis relancer un contrôle."
    return "Analyser la preuve du provider, appliquer le correctif recommandé par l’éditeur, puis relancer un scan de validation."


def enrich_finding(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["severity"] = score_severity(result.get("cvssScore"), result.get("hyScoreV2"), result.get("severity"))
    result["ageDays"] = age_days(result.get("firstSeen"))
    result["staleDays"] = age_days(result.get("lastSeen"))
    priority, score, due = priority_for(result.get("hyScoreV2"), result.get("cvssScore"), result.get("cisaKev"), result["ageDays"])
    result.update({"priority": priority, "priorityScore": score, "dueInDays": due})
    result["remediationSource"] = "source" if result.get("remediation") else "derived"
    result["remediation"] = result.get("remediation") or fallback_action(result)
    result["priorityReason"] = (
        f"TRS {round(float(result.get('hyScoreV2') or 0))} · CVSS "
        f"{float(result.get('cvssScore') or 0):.1f} · exposition {result['ageDays'] if result['ageDays'] is not None else 'inconnue'} j"
    )
    return result


def enrich_cve(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["severity"] = score_severity(result.get("maxCvss"), result.get("maxTrs"), result.get("severity"))
    result["remediationSource"] = "source" if result.get("remediation") else "derived"
    result["remediation"] = result.get("remediation") or fallback_action(result)
    result["priority"], result["priorityScore"], result["dueInDays"] = priority_for(result.get("maxTrs"), result.get("maxCvss"))
    return result


def enrich_remediation(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["maxTrs"] = result.get("maxTrs") if result.get("maxTrs") is not None else result.get("maxHyScore")
    result["findingCount"] = result.get("findingCount") if result.get("findingCount") is not None else result.get("affectedFindings")
    result["cveCount"] = result.get("cveCount") if result.get("cveCount") is not None else result.get("distinctCves")
    age = result.get("oldestFindingDays") or 0
    result["priority"], result["priorityScore"], result["dueInDays"] = priority_for(
        result.get("maxTrs"), result.get("maxCvss"), int(result.get("cisaKevFindings") or 0) > 0, age
    )
    result["remediationSource"] = "source" if result.get("remediation") else "derived"
    result["remediation"] = result.get("remediation") or fallback_action(result)
    signals = [f"TRS max {round(float(result.get('maxTrs') or 0))}", f"CVSS max {float(result.get('maxCvss') or 0):.1f}"]
    if result.get("cisaKevFindings"):
        signals.append(f"{result['cisaKevFindings']} CISA KEV")
    if result.get("expectedVersion"):
        signals.append(f"cible {result['expectedVersion']}")
    result["priorityReason"] = " · ".join(signals)
    return result

def values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [str(item) for item in value.keys()]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            if isinstance(item, dict):
                candidate = item.get("name") or item.get("value") or item.get("id") or item.get("key")
                if candidate is not None:
                    result.append(str(candidate))
            elif item is not None:
                result.append(str(item))
        return result
    return [str(value)]


def enrich_asset_dimensions(source: Path, asset_ids: set[str]) -> dict[str, dict[str, Any]]:
    """Agrège les dimensions de filtrage directement depuis le JSON en streaming."""
    dimensions: dict[str, dict[str, Any]] = {}
    if not source.exists() or not asset_ids:
        return dimensions
    with source.open("rb") as stream:
        for asset in ijson.items(stream, "item"):
            asset_id = str(asset.get("assetId") or "")
            if asset_id not in asset_ids:
                continue
            result: dict[str, Any] = {
                "assetId": asset_id,
                "perimeterIds": set(),
                "leafPerimeterIds": set(),
                "providerIds": set(),
                "assetStates": set(),
                "assetTypes": set(),
                "cisaKevFindings": 0,
                "internetFacingSignals": 0,
                "findingCountObserved": 0,
            }
            container = asset.get("findings")
            findings = container.get("searchFindings", []) if isinstance(container, dict) else []
            for finding in findings if isinstance(findings, list) else []:
                if not isinstance(finding, dict):
                    continue
                result["findingCountObserved"] += 1
                result["perimeterIds"].update(values(finding.get("perimeterIds")))
                result["leafPerimeterIds"].update(values(finding.get("leafPerimeterIds")))
                result["providerIds"].update(values(finding.get("providerIds")))
                result["providerIds"].update(values(finding.get("assetProviderIds")))
                result["assetStates"].update(values(finding.get("assetState")))
                result["assetTypes"].update(values(finding.get("assetType")))
                if finding.get("cisaKev") is True:
                    result["cisaKevFindings"] += 1
                tags = finding.get("tags")
                if isinstance(tags, dict) and any(
                    marker in str(key).upper()
                    for key in tags
                    for marker in ("EXTERNAL_IP", "PUBLIC_IP", "INTERNET")
                ):
                    result["internetFacingSignals"] += 1
            for key in ("perimeterIds", "leafPerimeterIds", "providerIds", "assetStates", "assetTypes"):
                result[key] = sorted(result[key])
            dimensions[asset_id] = result
            if len(dimensions) == len(asset_ids):
                break
    return dimensions


def main() -> None:
    parser = argparse.ArgumentParser(description="Prépare les données de la démo HTML locale.")
    parser.add_argument("--gold-dir", default="output/gold")
    parser.add_argument("--output", default="webapp/data/dashboard-data.js")
    parser.add_argument("--source", default="hackuity_all_open_findings.json")
    args = parser.parse_args()

    gold = Path(args.gold_dir)
    assets = read_rows(gold / "asset_summary.parquet")
    dimensions = enrich_asset_dimensions(
        Path(args.source),
        {str(asset.get("assetId")) for asset in assets if asset.get("assetId")},
    )
    for asset in assets:
        asset.update(dimensions.get(str(asset.get("assetId")), {}))
    output = Path(args.output)
    critical_findings = [enrich_finding(row) for row in read_rows(gold / "critical_findings.parquet")]
    cves = [enrich_cve(row) for row in read_rows(gold / "cve_summary.parquet")]
    remediations = [enrich_remediation(row) for row in read_rows(gold / "remediation_summary.parquet")]
    payload = {
        "generatedAt": datetime.now().isoformat(timespec="seconds"),
        "source": str(gold),
        "assets": assets,
        "criticalFindings": critical_findings,
        "cves": cves,
        "remediations": remediations,
        "catalog": build_catalog(Path.cwd(), output),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "window.HACKUITY_DATA = "
        + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        + ";\n",
        encoding="utf-8",
    )
    print(
        f"Dashboard exporté: {len(payload['assets'])} assets, "
        f"{len(payload['criticalFindings'])} findings critiques, "
        f"{len(payload['cves'])} CVE."
    )


if __name__ == "__main__":
    main()
