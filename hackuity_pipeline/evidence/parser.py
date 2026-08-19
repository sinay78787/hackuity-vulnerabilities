from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from hackuity_pipeline.core import nested_get
from hackuity_pipeline.intelligence.models import normalize_cve, normalize_scanner, normalize_timestamp

FIELD_ALIASES = {
    "package": ("package", "packageName", "package_name", "artifact", "dependency", "module"),
    "component": ("component", "componentName", "component_name", "library"),
    "vendor": ("vendor", "publisher"),
    "product": ("product", "software", "productName", "product_name"),
    "ecosystem": ("ecosystem",),
    "language": ("language",),
    "installed_version": ("installedVersion", "installed_version", "detectedVersion", "detected_version"),
    "required_version": ("requiredVersion", "required_version", "targetVersion", "target_version",
                         "fixedVersion", "fixed_version", "expectedVersion", "expected_version"),
    "install_path": ("installPath", "install_path", "path", "location", "filePath", "file_path"),
}
REFERENCE_KEYS = {"qid": "QID", "pluginid": "PLUGIN_ID", "plugin_id": "PLUGIN_ID",
                  "ruleid": "RULE_ID", "rule_id": "RULE_ID", "checkid": "CHECK_ID",
                  "check_id": "CHECK_ID", "detectionid": "DETECTION_ID", "detection_id": "DETECTION_ID"}
_LABELS = {
    "package": r"Package\s*:\s*([^\r\n]+)",
    "installed_version": r"Installed\s+Version\s*:\s*([^\r\n]+)",
    "required_version": r"(?:Required|Target|Fixed)\s+Version\s*:\s*([^\r\n]+)",
    "language": r"Language\s*:\s*([^\r\n]+)",
    "install_path": r"(?:Install\s+Path|Path)\s*:\s*([^\r\n]+)",
}


def _first(row: Mapping[str, Any], names: tuple[str, ...]) -> Any:
    return next((row.get(name) for name in names if row.get(name) not in (None, "")), None)


def _component_candidate(row: Mapping[str, Any], source_path: str) -> dict[str, Any] | None:
    result = {target: _first(row, aliases) for target, aliases in FIELD_ALIASES.items()}
    if not any(result.values()) or not any(result[key] for key in ("package", "component", "product")):
        return None
    result["source_path"] = source_path
    return result


def _walk_components(value: Any, path: str = "data") -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    if isinstance(value, Mapping):
        candidate = _component_candidate(value, path)
        if candidate:
            output.append(candidate)
        for key, child in value.items():
            output.extend(_walk_components(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            output.extend(_walk_components(child, f"{path}[{index}]"))
    return output


def _text_components(text: str, source_path: str) -> list[dict[str, Any]]:
    if not text:
        return []
    values = {key: (match.group(1).strip() if (match := re.search(pattern, text, re.I)) else None)
              for key, pattern in _LABELS.items()}
    if not values.get("package"):
        title = re.search(r"for\s+([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+)", text, re.I)
        values["package"] = title.group(1) if title else None
    if not any(values.values()):
        return []
    values.update({"component": values.get("package"), "vendor": None, "product": None,
                   "ecosystem": values.get("language"), "source_path": source_path})
    return [values]


def _references(value: Any) -> list[dict[str, str]]:
    found: set[tuple[str, str]] = set()
    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                normalized = key.lower().replace("-", "_")
                compact = normalized.replace("_", "")
                kind = REFERENCE_KEYS.get(normalized) or REFERENCE_KEYS.get(compact)
                if kind and child not in (None, "") and not isinstance(child, (dict, list)):
                    found.add((kind, str(child)))
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
    visit(value)
    return [{"type": kind, "value": value} for kind, value in sorted(found)]


def normalize_event_type(trigger: Any, status: Any = None) -> str:
    text = f"{trigger or ''} {status or ''}".upper()
    if "REOPEN" in text:
        return "FINDING_REOPENED"
    if any(value in text for value in ("RESOLV", "CLOSED", "FIXED")):
        return "FINDING_RESOLVED"
    if any(value in text for value in ("NEW_ASSESSMENT", "CREAT")):
        return "FINDING_CREATED"
    if any(value in text for value in ("CONFIRM", "DECLARED")):
        return "FINDING_CONFIRMED"
    if "ASSET" in text and any(value in text for value in ("INDICATOR", "SCORE")):
        return "ASSET_INDICATORS_CHANGED"
    if "RISK" in text:
        return "RISK_STATUS_CHANGED"
    if "REMEDIATION" in text:
        return "REMEDIATION_UPDATED"
    if any(value in text for value in ("UPDATE", "THREAT_INTEL")):
        return "FINDING_UPDATED"
    return "UNKNOWN"


def extract_technical_evidence(cache: Mapping[str, Any], raw_reference: str | None = None) -> dict[str, Any]:
    detail = cache.get("data") if isinstance(cache.get("data"), Mapping) else cache
    finding_id = str(cache.get("findingId") or detail.get("findingId") or detail.get("id") or "")
    asset_id = str(cache.get("assetId") or detail.get("assetId") or "")
    search = detail.get("searchFinding") if isinstance(detail.get("searchFinding"), Mapping) else {}
    hostname = search.get("assetEffectiveName") or search.get("assetAbsoluteName")
    source_hash = hashlib.sha256(json.dumps(cache, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()
    retrieved_at = normalize_timestamp(cache.get("extractedAt"))
    providers = nested_get(detail, "assessmentsRelated.activeFindingProviderInfos", [])
    providers = providers if isinstance(providers, list) else []
    components, occurrences, scanner_evidence = [], [], []
    for provider in providers:
        if not isinstance(provider, Mapping):
            continue
        scanner = normalize_scanner(provider.get("providerId"))
        refs = _references(provider.get("extendedAttributesList"))
        scanner_evidence.append({"aggregation_platform": "Hackuity", "scanner": scanner,
                                 "references": refs, "assessment_id": provider.get("assessmentId")})
        structured = []
        for key in ("technicalDetails", "details", "evidence", "components", "packages"):
            if provider.get(key) is not None:
                structured.extend(_walk_components(provider[key], f"activeProviderInfos.{provider.get('providerId')}.{key}"))
        shared = provider.get("sharedDetailsLocal") if isinstance(provider.get("sharedDetailsLocal"), Mapping) else {}
        texts: list[str] = []
        def collect_text(item: Any) -> None:
            if isinstance(item, Mapping):
                for key, child in item.items():
                    if key == "text" and isinstance(child, str):
                        texts.append(child)
                    else:
                        collect_text(child)
            elif isinstance(item, list):
                for child in item: collect_text(child)
        collect_text(shared.get("i18n"))
        for index, text in enumerate(texts):
            structured.extend(_text_components(text, f"activeProviderInfos.{provider.get('providerId')}.i18n[{index}]"))
        paths = [str(value) for value in provider.get("vulnerableFilePaths", []) if value]
        for candidate in structured:
            identity = candidate.get("package") or candidate.get("component") or candidate.get("product")
            digest = hashlib.sha256(f"{asset_id}|{str(identity).lower()}|{candidate.get('installed_version') or ''}".encode()).hexdigest()[:16]
            component_id = f"cmp-{digest}"
            component = {**candidate, "asset_id": asset_id, "hostname": hostname, "finding_id": finding_id,
                         "component_id": component_id, "scanner": scanner,
                         "scanner_references": refs, "source_type": "HACKUITY_FINDING_DETAIL",
                         "source_payload_reference": raw_reference, "source_hash": source_hash,
                         "retrieved_at": retrieved_at}
            components.append(component)
            candidate_paths = ([candidate.get("install_path")] if candidate.get("install_path")
                               else paths if len(structured) == 1 else [])
            for path in candidate_paths:
                occurrence_digest = hashlib.sha256(f"{component_id}|{path}".encode()).hexdigest()[:16]
                occurrences.append({"asset_id": asset_id, "hostname": hostname, "finding_id": finding_id,
                                    "component_id": component_id, "occurrence_id": f"occ-{occurrence_digest}",
                                    "package": candidate.get("package"), "installed_version": candidate.get("installed_version"),
                                    "required_version": candidate.get("required_version"), "install_path": path,
                                    "scanner": scanner, "scanner_references": refs,
                                    "source_payload_reference": raw_reference, "source_hash": source_hash,
                                    "retrieved_at": retrieved_at})
        if paths and len(structured) != 1:
            for path in paths:
                occurrence_digest = hashlib.sha256(f"{asset_id}|{finding_id}|unassigned|{path}".encode()).hexdigest()[:16]
                occurrences.append({"asset_id": asset_id, "hostname": hostname, "finding_id": finding_id,
                                    "component_id": None, "occurrence_id": f"occ-{occurrence_digest}",
                                    "package": None, "installed_version": None, "required_version": None,
                                    "install_path": path, "scanner": scanner, "scanner_references": refs,
                                    "source_payload_reference": raw_reference, "source_hash": source_hash,
                                    "retrieved_at": retrieved_at})
    atoms = nested_get(detail, "assessmentsRelated.findingAuditHistory.info.atomInfos", [])
    events = []
    for atom in atoms if isinstance(atoms, list) else []:
        if not isinstance(atom, Mapping):
            continue
        status = nested_get(atom, "declaredFindingStatus.subState")
        timestamp = normalize_timestamp(atom.get("at"))
        event_id = atom.get("auditId") or hashlib.sha256(f"{finding_id}|{timestamp}|{atom.get('trigger')}".encode()).hexdigest()[:16]
        events.append({"asset_id": asset_id, "hostname": hostname, "finding_id": finding_id,
                       "event_id": str(event_id), "event_timestamp": timestamp,
                       "event_type": normalize_event_type(atom.get("trigger"), status),
                       "event_label": atom.get("trigger"), "event_source": atom.get("assessmentType"),
                       "previous_status": None, "new_status": status, "actor": atom.get("userId"),
                       "scanner": normalize_scanner(atom.get("providerId")),
                       "raw_event_reference": raw_reference})
    dedup_components = {(row["component_id"], row["scanner"]): row for row in components}
    dedup_occurrences = {row["occurrence_id"]: row for row in occurrences}
    return {"components": sorted(dedup_components.values(), key=lambda row: (row["component_id"], row["scanner"])),
            "occurrences": sorted(dedup_occurrences.values(), key=lambda row: row["occurrence_id"]),
            "scanner_evidence": scanner_evidence,
            "events": sorted(events, key=lambda row: (row.get("event_timestamp") or "", row["event_id"])),
            "raw_reference": raw_reference, "mitre_attack": sorted(search.get("mitreAttackTtps") or [])}
