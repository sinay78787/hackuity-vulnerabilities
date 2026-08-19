from __future__ import annotations

from typing import Any

from .models import normalize_priority


def finding_risk(finding: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    trs, cvss, kev = finding.get("trs"), finding.get("cvss"), bool(finding.get("cisa_kev"))
    priority = normalize_priority(None, trs, cvss, kev)
    drivers: list[dict[str, Any]] = []
    if float(trs or 0) >= 700:
        drivers.append({"type": "HIGH_TRS", "evidence": {"trs": trs}})
    if finding.get("severity") == "CRITICAL":
        drivers.append({"type": "CRITICAL_SEVERITY", "evidence": {"severity": "CRITICAL"}})
    if finding.get("history_state") == "PERSISTENT":
        drivers.append({"type": "PERSISTENT", "evidence": {"first_seen": finding.get("first_seen"),
                                                            "last_seen": finding.get("last_seen"),
                                                            "observation_count": finding.get("observation_count")}})
    if kev:
        drivers.append({"type": "CISA_KEV", "evidence": {"cisa_kev": True}})
    return priority, drivers


def concentration(findings: list[dict[str, Any]]) -> dict[str, Any]:
    ranked = sorted(findings, key=lambda row: float(row.get("trs") or 0), reverse=True)
    total = sum(float(row.get("trs") or 0) for row in ranked)
    top = sum(float(row.get("trs") or 0) for row in ranked[:5])
    p1p2 = [row for row in ranked if row.get("priority") in {"P1", "P2"}]
    return {"total_p1_p2": len(p1p2), "top_5_p1_p2": min(5, len(p1p2)),
            "top_5_share": round(top / total, 4) if total else None,
            "top_finding_ids": [row["finding_id"] for row in ranked[:5]]}
