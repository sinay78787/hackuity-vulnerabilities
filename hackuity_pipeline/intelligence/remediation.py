from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any


def action_type(row: dict[str, Any]) -> str:
    text = str(row.get("recommendation") or "").lower()
    if row.get("target_version") or any(word in text for word in ("update", "upgrade", "patch", "kb")):
        return "UPGRADE" if row.get("target_version") else "PATCH"
    if any(word in text for word in ("configure", "disable")):
        return "CONFIG_CHANGE"
    return "INVESTIGATE"


def build_actions(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in findings:
        recommendation = str(row.get("recommendation") or "").strip()
        key = (recommendation, str(row.get("target_version") or ""))
        groups[key].append(row)
    actions, campaigns = [], []
    for index, (key, rows) in enumerate(sorted(groups.items()), 1):
        recommendation, target = key
        related_findings = sorted(row["finding_id"] for row in rows)
        related_cves = sorted({cve for row in rows for cve in row.get("cves", [])})
        priority = min((row["priority"] for row in rows), key=lambda value: int(value[1]))
        action = recommendation or "Analyser la preuve scanner et définir le correctif éditeur applicable."
        action_id = f"REM-{index:03d}"
        actions.append({"id": action_id, "priority": priority, "order": index,
                        "type": action_type(rows[0]), "action": action,
                        "reason": f"{len(rows)} finding(s), {len(related_cves)} CVE, TRS max {max(float(r.get('trs') or 0) for r in rows):.0f}",
                        "owner": "Local IT", "owner_source": "reporting_policy",
                        "evidence_required": ["Version installée après traitement", "Résultat du scan de validation"],
                        "exit_criteria": ["Findings associés non détectés par le scanner source"],
                        "related_cves": related_cves, "related_findings": related_findings})
        if recommendation and len(rows) > 1:
            digest = hashlib.sha256(("|".join(key)).encode()).hexdigest()[:10].upper()
            campaigns.append({"campaign_id": f"RC-{digest}", "title": action.splitlines()[0][:120],
                              "vendor": None, "product": rows[0].get("affected_product"),
                              "affected_findings": related_findings, "affected_cves": related_cves,
                              "affected_assets": sorted({row["asset_id"] for row in rows}),
                              "priority": priority, "estimated_findings_closed": len(rows),
                              "reason": "Regroupement exact sur la recommandation et la version cible."})
    return actions, campaigns
