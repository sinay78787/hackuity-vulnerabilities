from __future__ import annotations

from datetime import datetime
from typing import Any

from .models import HISTORY_STATES, PRIORITIES


def component_quality(components: list[dict[str, Any]], occurrences: list[dict[str, Any]]) -> list[str]:
    warnings = []
    by_id = {row.get("component_id"): row for row in components}
    for row in components:
        label = row.get("package") or row.get("component") or row.get("product")
        if not row.get("installed_versions") and not row.get("installed_version"):
            warnings.append(f"component_without_version:{row.get('component_id')}")
        if (row.get("required_versions") or row.get("required_version")) and not (
                row.get("installed_versions") or row.get("installed_version")):
            warnings.append(f"required_version_without_installed_version:{row.get('component_id')}")
        if not label:
            warnings.append(f"installed_version_without_product:{row.get('component_id')}")
    for row in occurrences:
        if row.get("install_path") and row.get("component_id") not in by_id:
            warnings.append(f"path_without_component:{row.get('occurrence_id')}")
    return sorted(set(warnings))


def validate_context(context: dict[str, Any], strict: bool = False) -> list[str]:
    errors: list[str] = []
    required = {"metadata", "asset", "current_posture", "findings", "vulnerabilities",
                "risk_analysis", "remediation", "validation", "sources", "data_quality"}
    errors.extend(f"Bloc requis absent: {key}" for key in sorted(required - context.keys()))
    if errors:
        return errors
    if not context["metadata"].get("schema_version"):
        errors.append("metadata.schema_version absent")
    if not context["asset"].get("hostname"):
        errors.append("asset.hostname absent")
    finding_ids = [row.get("finding_id") for row in context["findings"]]
    if len(finding_ids) != len(set(finding_ids)):
        errors.append("Finding dupliqué")
    cves = {row.get("cve") for row in context["vulnerabilities"]}
    for row in context["findings"]:
        if row.get("priority") not in PRIORITIES:
            errors.append(f"Priorité invalide: {row.get('finding_id')}")
        if row.get("history_state") not in HISTORY_STATES:
            errors.append(f"État historique invalide: {row.get('finding_id')}")
        first, last = row.get("first_seen"), row.get("last_seen")
        if first and last and datetime.fromisoformat(first.replace("Z", "+00:00")) > datetime.fromisoformat(last.replace("Z", "+00:00")):
            errors.append(f"first_seen > last_seen: {row.get('finding_id')}")
        for cve in row.get("cves", []):
            if cve not in cves:
                errors.append(f"CVE non consolidée: {cve}")
    for action in context["remediation"].get("actions", []):
        unknown = set(action.get("related_findings", [])) - set(finding_ids)
        if unknown:
            errors.append(f"Référence remediation inconnue {action.get('id')}: {sorted(unknown)}")
    errors.extend(f"Composant dupliqué: {key}" for key, count in __import__("collections").Counter(
        row.get("component_id") for row in context.get("components", [])).items() if count > 1)
    source_names = {row.get("name") for row in context["sources"]}
    for row in context["findings"]:
        scanner = row.get("source", {}).get("scanner")
        if scanner and scanner not in source_names:
            errors.append(f"Source scanner non référencée: {scanner}")
    if strict and context["data_quality"].get("missing_fields"):
        errors.append("Mode strict: champs manquants présents")
    return sorted(set(errors))
