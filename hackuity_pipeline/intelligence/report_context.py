from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from .history import classify_history, observation_count
from .models import (SCHEMA_VERSION, json_safe, normalize_cve, normalize_hostname,
                     normalize_scanner, normalize_severity, normalize_timestamp, short_hostname)
from .remediation import build_actions
from .risk import concentration, finding_risk
from .quality import component_quality
from hackuity_pipeline.evidence import extract_technical_evidence


def _rows(connection: duckdb.DuckDBPyConnection, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
    result = connection.execute(sql, params or [])
    names = [item[0] for item in result.description]
    return [{name: json_safe(value) for name, value in zip(names, row)} for row in result.fetchall()]


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if not value:
        return []
    try:
        parsed = json.loads(str(value))
        return parsed if isinstance(parsed, list) else [parsed]
    except (ValueError, TypeError):
        return [str(value)]


def _asset_query() -> str:
    return """SELECT * FROM read_parquet(?) WHERE
        lower(hostname)=lower(?) OR lower(split_part(hostname,'.',1))=lower(split_part(?,'.',1))
        ORDER BY lastSeen DESC NULLS LAST"""


def load_asset_data(hostname: str, silver: Path, gold: Path) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    con = duckdb.connect()
    assets = _rows(con, _asset_query(), [str(silver / "assets.parquet"), hostname, hostname])
    if not assets:
        raise ValueError(f"Asset introuvable: {hostname}")
    asset = assets[0]
    findings = _rows(con, """SELECT af.assetId,af.hostname,f.*
        FROM read_parquet(?) af JOIN read_parquet(?) f USING(findingId)
        WHERE af.assetId=? ORDER BY f.hyScoreV2 DESC NULLS LAST,f.findingId""",
        [str(silver / "asset_findings.parquet"), str(silver / "findings.parquet"), asset["assetId"]])
    details: dict[str, dict[str, Any]] = {}
    detail_path = silver / "finding_details.parquet"
    if detail_path.exists():
        for row in _rows(con, "SELECT * FROM read_parquet(?) WHERE assetId=?", [str(detail_path), asset["assetId"]]):
            details[row["findingId"]] = row
    return asset, findings, details


def _history(first_seen: str | None, last_seen: str | None) -> tuple[list[dict[str, Any]], str]:
    observations = []
    if first_seen:
        observations.append({"observation_date": first_seen, "detected": True, "is_first_observation": True})
    if last_seen and last_seen != first_seen:
        observations.append({"observation_date": last_seen, "detected": True, "is_first_observation": False})
    return observations, classify_history(observations)


@lru_cache(maxsize=4)
def _cached_evidence(directory: str) -> dict[str, dict[str, Any]]:
    result = {}
    for path in Path(directory).glob("*.json"):
        try:
            cache = json.loads(path.read_text(encoding="utf-8"))
            finding_id = str(cache.get("findingId") or "")
            if finding_id:
                result[finding_id] = extract_technical_evidence(cache, path.as_posix())
        except (OSError, ValueError, TypeError):
            continue
    return result


def _finding(row: dict[str, Any], detail: dict[str, Any] | None,
             evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    detail = detail or {}
    first_seen = normalize_timestamp(detail.get("firstSeen") or row.get("firstSeen"))
    last_seen = normalize_timestamp(detail.get("lastSeen") or row.get("lastSeen"))
    observations, state = _history(first_seen, last_seen)
    cves = sorted({item for item in [normalize_cve(row.get("cve"))]
                   + [normalize_cve(x) for x in _json_list(detail.get("cvesJson"))] if item})
    scanner = normalize_scanner(detail.get("providerId") or row.get("provider"))
    evidence = evidence or {"components": [], "occurrences": [], "scanner_evidence": [], "events": [],
                            "raw_reference": None, "mitre_attack": []}
    result = {
        "asset_id": row["assetId"], "finding_id": row["findingId"],
        "source": {"scanner": scanner, "reference": detail.get("providerEvidenceTitle")},
        "cves": cves, "title": detail.get("findingName") or row.get("findingName"),
        "description": detail.get("cveDescriptionsJson") or row.get("description"),
        "severity": normalize_severity(row.get("severity"), row.get("hyScoreV2"), row.get("cvssScore")),
        "trs": row.get("hyScoreV2"), "cvss": detail.get("cvssScore") or row.get("cvssScore"),
        "status": detail.get("status") or row.get("status") or "UNKNOWN",
        "first_seen": first_seen, "last_seen": last_seen,
        "age_days": None, "observation_count": observation_count(first_seen, last_seen),
        "history_state": state, "history": observations,
        "affected_product": (detail.get("vulnerableSoftwareJson") or None),
        "detected_version": next(iter(_json_list(detail.get("detectedVersionsJson"))), None),
        "target_version": next(iter(_json_list(detail.get("expectedVersionsJson"))), None),
        "recommendation": detail.get("remediation") or row.get("remediation"),
        "cisa_kev": detail.get("cisaKev"), "epss": detail.get("epssScore"),
        "raw_source_fields": {"vulnerability_type_id": row.get("vulnerabilityTypeId"),
                              "port": row.get("port"), "protocol": row.get("protocol"),
                              "service": row.get("service"), "history_url": detail.get("hackuityHistoryUrl")},
        "technical_evidence": {"components": evidence["components"], "versions": sorted({
                                  value for component in evidence["components"]
                                  for value in (component.get("installed_version"), component.get("required_version")) if value}),
                               "paths": sorted({item["install_path"] for item in evidence["occurrences"] if item.get("install_path")}),
                               "scanner_details": evidence["scanner_evidence"],
                               "mitre_attack": evidence.get("mitre_attack", []),
                               "raw_evidence": None, "raw_reference": evidence["raw_reference"]},
        "events": evidence["events"],
    }
    if first_seen:
        first = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        result["age_days"] = max(0, (datetime.now(timezone.utc) - first).days)
    result["priority"], result["risk_drivers"] = finding_risk(result)
    return result


def _vulnerabilities(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        for cve in finding["cves"]:
            grouped[cve].append(finding)
    result = []
    for cve, rows in sorted(grouped.items()):
        sources = sorted({row["source"]["scanner"] for row in rows})
        first = sorted(row["first_seen"] for row in rows if row["first_seen"])
        last = sorted(row["last_seen"] for row in rows if row["last_seen"])
        states = {row["history_state"] for row in rows}
        state = "REOPENED" if "REOPENED" in states else "PERSISTENT" if "PERSISTENT" in states else "UNKNOWN"
        result.append({
            "cve": cve, "title": next((row["title"] for row in rows if row["title"]), None),
            "severity": max((row["severity"] for row in rows), key=lambda x: {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(x, 0)),
            "hackuity": {"max_trs": max(float(row["trs"] or 0) for row in rows), "finding_count": len(rows)},
            "scores": {"cvss_v3": max((float(row["cvss"] or 0) for row in rows), default=0) or None,
                       "cvss_v2": None, "epss": max((float(row["epss"] or 0) for row in rows), default=0) or None},
            "exploitation": {"cisa_kev": True if any(row["cisa_kev"] is True for row in rows) else None,
                             "known_exploited": None, "public_exploit": None},
            "technical": {"attack_vector": None, "impact": None, "cwe": None},
            "affected_products": sorted({str(row["affected_product"]) for row in rows if row["affected_product"]}),
            "detection_sources": sources,
            "scanner_correlation": {"source_count": len(sources), "sources": sources,
                                    "type": "multi_source_confirmed" if len(sources) > 1 else "single_source",
                                    "confidence": "HIGH" if len(sources) > 1 else "STANDARD"},
            "history": {"first_seen": first[0] if first else None, "last_seen": last[-1] if last else None,
                        "age_days": max((row["age_days"] or 0 for row in rows), default=0) or None,
                        "observation_count": sum(row["observation_count"] for row in rows), "state": state},
            "finding_ids": sorted(row["finding_id"] for row in rows),
        })
    return result


def _scan_history(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in findings:
        for observation in row["history"]:
            grouped[(observation["observation_date"][:10], row["source"]["scanner"])].append(row)
    output = []
    for (date, scanner), rows in sorted(grouped.items()):
        counts = Counter(row["severity"] for row in rows)
        output.append({"hostname": None, "scan_date": date, "scanner": scanner,
                       "open_findings": len(rows), "critical_count": counts["CRITICAL"],
                       "high_count": counts["HIGH"], "medium_count": counts["MEDIUM"], "low_count": counts["LOW"],
                       "new_count": sum(row["history_state"] == "NEW" for row in rows),
                       "resolved_count": 0, "reopened_count": sum(row["history_state"] == "REOPENED" for row in rows),
                       "method": "reconstructed_observation_bounds"})
    return output


def build_report_context(hostname: str, silver_dir: Path = Path("output/silver"),
                         gold_dir: Path = Path("output/gold"),
                         detail_cache_dir: Path = Path("output/bronze/finding_details")) -> dict[str, Any]:
    asset, source_findings, details = load_asset_data(hostname, silver_dir, gold_dir)
    evidence_by_finding = _cached_evidence(str(detail_cache_dir.resolve()))
    findings = sorted((_finding(row, details.get(row["findingId"]), evidence_by_finding.get(row["findingId"]))
                       for row in source_findings),
                      key=lambda row: (-float(row["trs"] or 0), row["finding_id"]))
    vulnerabilities = _vulnerabilities(findings)
    components_by_id: dict[str, dict[str, Any]] = {}
    occurrences = []
    events = []
    for finding in findings:
        events.extend(finding["events"])
        occurrences.extend(evidence_by_finding.get(finding["finding_id"], {}).get("occurrences", []))
        for component in finding["technical_evidence"]["components"]:
            target = components_by_id.setdefault(component["component_id"], {
                "component_id": component["component_id"], "vendor": component.get("vendor"),
                "product": component.get("product"), "component": component.get("component"),
                "package": component.get("package"), "ecosystem": component.get("ecosystem"),
                "language": component.get("language"), "installed_versions": set(),
                "required_versions": set(), "occurrences": [], "findings": [],
                "source_payload_references": set()})
            if component.get("installed_version"): target["installed_versions"].add(component["installed_version"])
            if component.get("required_version"): target["required_versions"].add(component["required_version"])
            if component.get("source_payload_reference"): target["source_payload_references"].add(component["source_payload_reference"])
            target["findings"].append({"finding_id": finding["finding_id"],
                                       "scanner": component.get("scanner"),
                                       "scanner_references": component.get("scanner_references", []),
                                       "cves": finding["cves"], "cvss": finding["cvss"],
                                       "priority": finding["priority"], "recommendation": finding["recommendation"]})
    for occurrence in occurrences:
        if occurrence["component_id"] in components_by_id:
            components_by_id[occurrence["component_id"]]["occurrences"].append(
                {"occurrence_id": occurrence["occurrence_id"], "path": occurrence.get("install_path")})
    components = []
    component_summary = []
    for component in sorted(components_by_id.values(), key=lambda row: row["component_id"]):
        component["installed_versions"] = sorted(component["installed_versions"])
        component["required_versions"] = sorted(component["required_versions"])
        component["source_payload_references"] = sorted(component["source_payload_references"])
        component["findings"] = sorted(component["findings"], key=lambda row: row["finding_id"])
        component["occurrences"] = sorted(component["occurrences"], key=lambda row: row["occurrence_id"])
        components.append(component)
        priorities = Counter(row["priority"] for row in component["findings"])
        component_summary.append({"component_id": component["component_id"],
                                  "component": component.get("component") or component.get("package") or component.get("product"),
                                  "installed_versions": component["installed_versions"],
                                  "finding_count": len(component["findings"]),
                                  "cve_count": len({cve for row in component["findings"] for cve in row["cves"]}),
                                  "p1_count": priorities["P1"], "p2_count": priorities["P2"], "p3_count": priorities["P3"]})
    actions, campaigns = build_actions(findings)
    scan_history = _scan_history(findings)
    for row in scan_history:
        row["hostname"] = asset["hostname"]
    severity = Counter(row["severity"] for row in findings)
    priorities = Counter(row["priority"] for row in findings)
    states = Counter(row["history_state"] for row in findings)
    missing = []
    if not asset.get("assetOsPrimary"): missing.append("asset.os")
    if not asset.get("businessUnit"): missing.append("asset.business.owner")
    tracked = {
        "findings.first_seen": sum(not row.get("first_seen") for row in findings),
        "findings.scanner": sum(row["source"]["scanner"] == "UNKNOWN" for row in findings),
        "findings.title": sum(not row.get("title") for row in findings),
        "findings.cvss": sum(row.get("cvss") is None for row in findings),
        "findings.recommendation": sum(not row.get("recommendation") for row in findings),
    }
    missing.extend(f"{field} ({count}/{len(findings)})" for field, count in tracked.items() if count)
    conflicts = [f"{row['finding_id']}: first_seen > last_seen" for row in findings
                 if row.get("first_seen") and row.get("last_seen") and row["first_seen"] > row["last_seen"]]
    warnings = ["L’historique de scan est reconstruit depuis firstSeen/lastSeen; ces bornes ne constituent pas des scans exhaustifs."]
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    latest = max((row["last_seen"] for row in findings if row["last_seen"]), default=normalize_timestamp(asset.get("lastSeen")))
    drivers = [dict(driver, finding_id=row["finding_id"]) for row in findings for driver in row["risk_drivers"]]
    context = {
        "metadata": {"schema_version": SCHEMA_VERSION, "generated_at": now,
                     "hostname": short_hostname(asset["hostname"]).upper(), "fqdn": normalize_hostname(asset["hostname"]),
                     "source_system": "Hackuity", "pipeline_version": "intelligence-1.0",
                     "data_freshness": {"latest_observation": latest, "age_hours": None}},
        "asset": {"asset_id": asset["assetId"], "hostname": short_hostname(asset["hostname"]),
                  "fqdn": normalize_hostname(asset["hostname"]), "ip_addresses": _json_list(asset.get("ipAddress")),
                  "os": {"vendor": None, "name": asset.get("assetOsPrimary"), "version": None, "build": None},
                  "environment": None, "location": {"country": asset.get("country"), "city": None, "region": None},
                  "tags": [], "business": {"criticality": None, "owner": asset.get("businessUnit"),
                                            "application": None}},
        "current_posture": {"total_findings": len(findings), "unique_cves": len(vulnerabilities),
                            "critical": severity["CRITICAL"], "high": severity["HIGH"],
                            "medium": severity["MEDIUM"], "low": severity["LOW"],
                            "p1": priorities["P1"], "p2": priorities["P2"], "p3": priorities["P3"],
                            "oldest_open_finding_days": max((row["age_days"] or 0 for row in findings), default=0) or None,
                            "persistent_findings": states["PERSISTENT"], "reopened_findings": states["REOPENED"],
                            "confirmed_by_multiple_sources": sum(v["scanner_correlation"]["source_count"] > 1 for v in vulnerabilities)},
        "components": components, "component_occurrences": occurrences,
        "component_risk_summary": component_summary,
        "scan_history": scan_history, "finding_history": [
            {"hostname": asset["hostname"], "finding_id": row["finding_id"], "cves": row["cves"],
             "scanner": row["source"]["scanner"], "first_seen": row["first_seen"], "last_seen": row["last_seen"],
             "observations": row["history"], "status": row["status"], "trs": row["trs"],
             "severity": row["severity"], "state": row["history_state"]} for row in findings],
        "findings": findings, "vulnerabilities": vulnerabilities,
        "history": {"finding_history": [], "events": sorted(events, key=lambda row: (row.get("event_timestamp") or "", row["event_id"])),
                    "asset_history": {"first_vulnerability_seen": min((row["first_seen"] for row in findings if row["first_seen"]), default=None),
                                      "latest_event": max((row["event_timestamp"] for row in events if row.get("event_timestamp")), default=None),
                                      "total_events": len(events)}},
        "risk_analysis": {"overall_priority": min((row["priority"] for row in findings), default="P3",
                                                   key=lambda value: int(value[1])),
                          "risk_score": None, "likelihood": None, "impact": None,
                          "drivers": drivers, "risk_concentration": concentration(findings)},
        "risk_history": {"available": bool(scan_history), "method": "observation_bounds",
                         "warning": warnings[0]},
        "remediation": {"strategy": "PATCH_UPGRADE_OR_INVESTIGATE", "actions": actions, "campaigns": campaigns},
        "validation": {"technical_checks": [
            {"id": f"VAL-{i:03d}", "check": "Vérifier la version puis relancer le scan source",
             "status": "PENDING", "related_findings": action["related_findings"]} for i, action in enumerate(actions, 1)],
            "scanner_checks": [{"scanner": scanner, "reference": None, "expected_result": "NOT_DETECTED"}
                               for scanner in sorted({row["source"]["scanner"] for row in findings})]},
        "sources": [{"type": "HACKUITY", "name": "Hackuity Silver/Gold", "reference": "output/silver",
                     "retrieved_at": latest}] + [{"type": "SCANNER", "name": scanner, "reference": None,
                                                  "retrieved_at": latest}
                                                 for scanner in sorted({row["source"]["scanner"] for row in findings})],
        "data_quality": {"completeness_score": round(100 * (
                            sum(bool(row.get(field)) for row in findings
                                for field in ("title", "first_seen", "last_seen", "recommendation"))
                            / max(1, len(findings) * 4)), 1),
                         "warnings": warnings, "missing_fields": missing, "conflicts": conflicts},
    }
    context["ai_context"] = {"facts": context["current_posture"],
                             "top_risks": context["risk_analysis"]["risk_concentration"]["top_finding_ids"],
                             "historical_signals": {"persistent": states["PERSISTENT"], "reopened": states["REOPENED"]},
                             "remediation_actions": [action["id"] for action in actions],
                             "constraints": ["No inferred CVE, score, date or scanner status"]}
    context["history"]["finding_history"] = context["finding_history"]
    context["data_quality"]["component_warnings"] = component_quality(components, occurrences)
    return context


def _write_rows(rows: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        pq.write_table(pa.table({"_empty": pa.array([], type=pa.bool_())}), path, compression="snappy")
        return
    safe = [{key: json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else value
             for key, value in row.items()} for row in rows]
    pq.write_table(pa.Table.from_pylist(safe), path, compression="snappy")


def write_intelligence_dataset(contexts: list[dict[str, Any]], output_dir: Path, pretty: bool = False) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_dir = output_dir / "report_context"
    report_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for context in contexts:
        target = report_dir / f"{context['metadata']['hostname']}.json"
        target.write_text(json.dumps(context, ensure_ascii=False, indent=2 if pretty else None,
                                     sort_keys=True), encoding="utf-8")
        written.append(target)
    _write_rows([ctx["asset"] for ctx in contexts], output_dir / "assets.parquet")
    _write_rows([row for ctx in contexts for row in ctx["findings"]], output_dir / "findings.parquet")
    _write_rows([row for ctx in contexts for row in ctx["vulnerabilities"]], output_dir / "vulnerabilities.parquet")
    _write_rows([row for ctx in contexts for row in ctx["components"]], output_dir / "components.parquet")
    _write_rows([row for ctx in contexts for row in ctx["component_occurrences"]], output_dir / "component_occurrences.parquet")
    _write_rows([row for ctx in contexts for row in ctx["scan_history"]], output_dir / "scan_history.parquet")
    _write_rows([row for ctx in contexts for row in ctx["finding_history"]], output_dir / "finding_history.parquet")
    _write_rows([row for ctx in contexts for row in ctx["history"]["events"]], output_dir / "finding_events.parquet")
    _write_rows([{"hostname": ctx["metadata"]["hostname"], **ctx["risk_history"]} for ctx in contexts],
                output_dir / "asset_risk_history.parquet")
    _write_rows([row for ctx in contexts for row in ctx["remediation"]["actions"]], output_dir / "remediation.parquet")
    _write_rows([row for ctx in contexts for row in ctx["sources"]], output_dir / "sources.parquet")
    return written
