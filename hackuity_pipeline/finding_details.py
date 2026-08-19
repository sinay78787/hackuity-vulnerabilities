from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import pyarrow as pa

from .core import as_float, first_not_none, nested_get, parse_timestamp, serialize_json

FINDING_DETAIL_SCHEMA = pa.schema([
    ("findingId", pa.string()), ("assetId", pa.string()), ("hostname", pa.string()),
    ("ipAddress", pa.string()), ("findingName", pa.string()), ("status", pa.string()),
    ("providerId", pa.string()), ("assessmentName", pa.string()),
    ("cvssScore", pa.float64()),
    ("environmentalScore", pa.float64()), ("temporalScore", pa.float64()),
    ("hyScoreV2", pa.float64()), ("cvssVersion", pa.string()),
    ("cvssVector", pa.string()), ("cvssAttackVector", pa.string()),
    ("cvssAttackComplexity", pa.string()), ("cvssPrivilegesRequired", pa.string()),
    ("cvssUserInteraction", pa.string()), ("cvssScope", pa.string()),
    ("cvssConfidentiality", pa.string()), ("cvssIntegrity", pa.string()),
    ("cvssAvailability", pa.string()), ("cvssExploitCodeMaturity", pa.string()),
    ("epssScore", pa.float64()), ("exploitabilityScore", pa.float64()),
    ("exploitMaturityScore", pa.float64()), ("threatIntensityScore", pa.float64()),
    ("cisaKev", pa.bool_()), ("cvesJson", pa.string()),
    ("cveDescriptionsJson", pa.string()), ("referencesJson", pa.string()),
    ("providerEvidenceTitle", pa.string()), ("providerEvidenceRaw", pa.string()),
    ("registryPathsJson", pa.string()), ("filePathsJson", pa.string()),
    ("detectedVersionsJson", pa.string()), ("expectedVersionsJson", pa.string()),
    ("vulnerableSoftwareJson", pa.string()), ("remediation", pa.string()),
    ("firstSeen", pa.timestamp("us")), ("lastSeen", pa.timestamp("us")),
    ("hackuityHistoryUrl", pa.string()), ("sourceEndpoint", pa.string()),
    ("extractedAt", pa.timestamp("us")),
])
FINDING_CVE_SCHEMA = pa.schema([
    ("findingId", pa.string()), ("assetId", pa.string()), ("cve", pa.string()),
    ("description", pa.string()),
])
FINDING_REFERENCE_SCHEMA = pa.schema([
    ("findingId", pa.string()), ("cve", pa.string()),
    ("referenceName", pa.string()), ("referenceUrl", pa.string()),
])
FINDING_PATH_SCHEMA = pa.schema([
    ("findingId", pa.string()), ("assetId", pa.string()), ("pathType", pa.string()),
    ("path", pa.string()), ("providerId", pa.string()),
])
FINDING_VERSION_SCHEMA = pa.schema([
    ("findingId", pa.string()), ("assetId", pa.string()), ("component", pa.string()),
    ("detectedVersion", pa.string()), ("expectedVersion", pa.string()),
    ("sourceText", pa.string()),
])
FINDING_PROVIDER_SCHEMA = pa.schema([
    ("findingId", pa.string()), ("assetId", pa.string()), ("providerId", pa.string()),
    ("assessmentId", pa.string()), ("assessmentType", pa.string()),
    ("assessmentName", pa.string()), ("firstDetection", pa.timestamp("us")),
    ("baseScore", pa.float64()), ("environmentalScore", pa.float64()),
    ("temporalScore", pa.float64()), ("hyScoreV2", pa.float64()),
    ("cvssVersion", pa.string()), ("rawProviderJson", pa.string()),
    ("sourceEndpoint", pa.string()), ("extractedAt", pa.timestamp("us")),
])
FINDING_SCANNER_REFERENCE_SCHEMA = pa.schema([
    ("findingId", pa.string()), ("assetId", pa.string()), ("providerId", pa.string()),
    ("assessmentId", pa.string()), ("referenceType", pa.string()),
    ("referenceValue", pa.string()), ("sourcePath", pa.string()),
])
FINDING_COMPONENT_SCHEMA = pa.schema([
    ("findingId", pa.string()), ("assetId", pa.string()), ("hostname", pa.string()),
    ("componentId", pa.string()), ("scanner", pa.string()), ("package", pa.string()),
    ("component", pa.string()), ("vendor", pa.string()), ("product", pa.string()),
    ("ecosystem", pa.string()), ("language", pa.string()),
    ("installedVersion", pa.string()), ("requiredVersion", pa.string()),
    ("installPath", pa.string()), ("scannerReferencesJson", pa.string()),
    ("sourcePath", pa.string()), ("sourcePayloadReference", pa.string()),
    ("sourceHash", pa.string()), ("retrievedAt", pa.timestamp("us")),
])
FINDING_OCCURRENCE_SCHEMA = pa.schema([
    ("findingId", pa.string()), ("assetId", pa.string()), ("hostname", pa.string()),
    ("componentId", pa.string()), ("occurrenceId", pa.string()), ("scanner", pa.string()),
    ("package", pa.string()), ("installedVersion", pa.string()),
    ("requiredVersion", pa.string()), ("installPath", pa.string()),
    ("scannerReferencesJson", pa.string()), ("sourcePayloadReference", pa.string()),
    ("sourceHash", pa.string()), ("retrievedAt", pa.timestamp("us")),
])
FINDING_EVENT_SCHEMA = pa.schema([
    ("findingId", pa.string()), ("assetId", pa.string()), ("hostname", pa.string()),
    ("eventId", pa.string()), ("eventTimestamp", pa.timestamp("us")),
    ("eventType", pa.string()), ("eventLabel", pa.string()),
    ("eventSource", pa.string()), ("previousStatus", pa.string()),
    ("newStatus", pa.string()), ("actor", pa.string()), ("scanner", pa.string()),
    ("rawEventReference", pa.string()),
])

def unique(values: Iterable[str | None]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        clean = str(value).strip() if value is not None else ""
        if clean and clean not in seen:
            seen.add(clean); result.append(clean)
    return result

def extract_text_nodes(value: object) -> list[str]:
    result: list[str] = []
    def visit(item: object) -> None:
        if isinstance(item, Mapping):
            text = item.get("text")
            if isinstance(text, str) and text.strip():
                result.append(text.strip())
            for key, child in item.items():
                if key != "text":
                    visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
    visit(value)
    return unique(result)

def parse_references(value: Any) -> tuple[list[dict[str, str | None]], str | None]:
    raw = value if isinstance(value, str) else None
    parsed = value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return [], raw
    if isinstance(parsed, Mapping):
        parsed = [parsed]
    references: list[dict[str, str | None]] = []
    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, Mapping):
                references.append({
                    "name": str(item.get("name") or item.get("title") or "") or None,
                    "url": str(item.get("url") or item.get("href") or "") or None,
                })
            elif isinstance(item, str):
                references.append({"name": None, "url": item})
    return references, raw

def parse_cves(detail: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = nested_get(detail, "sharedDetailsLocal.extendedAttributesList", [])
    result: list[dict[str, Any]] = []
    if not isinstance(rows, list):
        return result
    for item in rows:
        if not isinstance(item, Mapping) or str(item.get("type", "")).lower() != "commonvulnerabilityexposure":
            continue
        cve = str(item.get("id") or "").upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            continue
        references, raw = parse_references(item.get("references"))
        result.append({
            "cve": cve, "description": item.get("description"),
            "references": references, "referencesRaw": raw,
        })
    return result

def build_cvss_vector(metrics: Any, version: str = "3.1") -> str | None:
    if not isinstance(metrics, Mapping):
        return None
    order = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    parts = [f"{key}:{metrics[key]}" for key in order if metrics.get(key) not in (None, "")]
    return f"CVSS:{version}/" + "/".join(parts) if len(parts) == len(order) else None

def build_hackuity_history_url(app_url: str, namespace: str, asset_id: str | None, finding_id: str | None) -> str | None:
    if not asset_id or not finding_id:
        return None
    return f"{app_url.rstrip('/')}/{namespace}/assets/live-report/{asset_id}/vuln-management/findings/finding/{finding_id}/history"

_REGISTRY = re.compile(r"(?im)\b((?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\r\n=]+?)(?=\s+(?:LastProduct|Version|CurrentVersion)\b|\s*=|$)")
_WINDOWS_FILE = re.compile(r"(?im)((?:%[^%]+%|[A-Z]:)\\[^\r\n]*?\.(?:dll|exe|sys|ocx|jar|config|xml|json|ini|so))")
_LINUX_FILE = re.compile(r"(?im)(/(?:usr|opt|etc|var|lib|home)/[^\s,;]+)")
_VERSION = re.compile(r"(?i)\b(?:version\s+(?:is|=)?|installed(?:\s+version)?\s*[:=])\s*([0-9][\w.+~-]*(?:\.[\w.+~-]+)+)")
_EXPECTED = re.compile(r"(?i)\b(?:expected|required|fixed|target|lastproduct)(?:\s+version)?\s*[:=]\s*([0-9][\w.+~-]*(?:\.[\w.+~-]+)+)")
_QID = re.compile(r"(?i)\bQID\s*[:#]?\s*(\d+)\b")

def parse_generic_evidence(text: str) -> dict[str, Any]:
    return {
        "registryPaths": unique(_REGISTRY.findall(text)),
        "filePaths": unique([*_WINDOWS_FILE.findall(text), *_LINUX_FILE.findall(text)]),
        "detectedVersions": unique(_VERSION.findall(text)),
        "expectedVersions": unique(_EXPECTED.findall(text)),
        "qid": first_not_none(*_QID.findall(text)),
        "component": None,
    }

def parse_qualys_evidence(text: str) -> dict[str, Any]:
    result = parse_generic_evidence(text)
    # Qualys emploie souvent "LastProduct = x" pour la version attendue/référence.
    result["expectedVersions"] = unique([
        *result["expectedVersions"],
        *re.findall(r"(?i)\bLastProduct\s*=\s*([0-9][\w.+~-]*(?:\.[\w.+~-]+)+)", text),
    ])
    title = re.search(r'(?i)Qualys\s+VM\s+details\s+for\s+"([^"]+)"', text)
    result["component"] = title.group(1) if title else None
    return result

def parse_tenable_evidence(text: str) -> dict[str, Any]:
    return parse_generic_evidence(text)

def normalize_provider_observations(cache: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Conserve une ligne par observation scanner et une ligne par identifiant natif."""
    detail = cache.get("data") if isinstance(cache.get("data"), Mapping) else cache
    infos = nested_get(detail, "assessmentsRelated.activeFindingProviderInfos", [])
    infos = infos if isinstance(infos, list) else []
    finding_id = first_not_none(cache.get("findingId"), detail.get("findingId"), detail.get("id"))
    asset_id = first_not_none(cache.get("assetId"), detail.get("assetId"))
    providers, references = [], []
    reference_names = {"qid": "QID", "pluginid": "PLUGIN_ID", "plugin_id": "PLUGIN_ID",
                       "ruleid": "RULE_ID", "rule_id": "RULE_ID", "checkid": "CHECK_ID",
                       "check_id": "CHECK_ID", "detectionid": "DETECTION_ID", "detection_id": "DETECTION_ID"}
    for index, info in enumerate(infos):
        if not isinstance(info, Mapping):
            continue
        score = info.get("initialScore") if isinstance(info.get("initialScore"), Mapping) else {}
        shared = info.get("sharedDetailsLocal") if isinstance(info.get("sharedDetailsLocal"), Mapping) else {}
        provider_id, assessment_id = info.get("providerId"), info.get("assessmentId")
        providers.append({
            "findingId": finding_id, "assetId": asset_id, "providerId": provider_id,
            "assessmentId": assessment_id, "assessmentType": info.get("assessmentType"),
            "assessmentName": shared.get("assessmentName"),
            "firstDetection": parse_timestamp(info.get("firstDetection")),
            "baseScore": as_float(score.get("base")),
            "environmentalScore": as_float(score.get("environmental")),
            "temporalScore": as_float(score.get("temporal")),
            "hyScoreV2": as_float(score.get("hyScoreV2")), "cvssVersion": score.get("cvssVersion"),
            "rawProviderJson": serialize_json(info), "sourceEndpoint": cache.get("sourceEndpoint"),
            "extractedAt": parse_timestamp(cache.get("extractedAt")),
        })
        def visit(value: Any, path: str) -> None:
            if isinstance(value, Mapping):
                for key, child in value.items():
                    normalized = key.lower().replace("-", "_")
                    kind = reference_names.get(normalized) or reference_names.get(normalized.replace("_", ""))
                    if kind and child not in (None, "") and not isinstance(child, (Mapping, list)):
                        references.append({"findingId": finding_id, "assetId": asset_id,
                                           "providerId": provider_id, "assessmentId": assessment_id,
                                           "referenceType": kind, "referenceValue": str(child),
                                           "sourcePath": f"activeFindingProviderInfos[{index}].{path}.{key}"})
                    visit(child, f"{path}.{key}")
            elif isinstance(value, list):
                for child_index, child in enumerate(value):
                    visit(child, f"{path}[{child_index}]")
        visit(info.get("extendedAttributesList"), "extendedAttributesList")
    references = list({(r["findingId"], r["providerId"], r["assessmentId"], r["referenceType"], r["referenceValue"]): r
                       for r in references}.values())
    return providers, references

def normalize_detail(cache: Mapping[str, Any], app_url: str, namespace: str) -> dict[str, Any]:
    detail = cache.get("data") if isinstance(cache.get("data"), Mapping) else cache
    active_infos = nested_get(detail, "assessmentsRelated.activeFindingProviderInfos", [])
    providers = [item for item in active_infos if isinstance(item, Mapping)] if isinstance(active_infos, list) else []
    provider_info = next((item for item in providers if item.get("providerId") == "QUALYS_VM"), None)
    if provider_info is None and providers:
        provider_info = max(
            providers,
            key=lambda item: len(extract_text_nodes(nested_get(item, "sharedDetailsLocal.i18n", {}))),
        )
    provider_info = provider_info or {}
    score = provider_info.get("initialScore") if isinstance(provider_info.get("initialScore"), Mapping) else {}
    shared = provider_info.get("sharedDetailsLocal") if isinstance(provider_info.get("sharedDetailsLocal"), Mapping) else {}
    search = detail.get("searchFinding") if isinstance(detail.get("searchFinding"), Mapping) else {}
    finding_id = first_not_none(cache.get("findingId"), detail.get("findingId"), detail.get("id"), search.get("findingId"))
    asset_id = first_not_none(cache.get("assetId"), detail.get("assetId"))
    base = first_not_none(nested_get(score, "effectiveScoreInfo.cvss31Base"), nested_get(detail, "effectiveScoreInfo.cvss31Base"), {}) or {}
    temp = first_not_none(nested_get(score, "effectiveScoreInfo.cvss31Temp"), nested_get(detail, "effectiveScoreInfo.cvss31Temp"), {}) or {}
    metrics = first_not_none(nested_get(score, "effectiveScoreInfo.hyScoreMetrics"), nested_get(detail, "effectiveScoreInfo.hyScoreMetrics"), {}) or {}
    evidence_nodes = extract_text_nodes(first_not_none(shared.get("i18n"), nested_get(detail, "sharedDetailsLocal.i18n"), {}))
    evidence = "\n\n".join(evidence_nodes) or None
    provider = first_not_none(provider_info.get("providerId"), detail.get("providerId"), nested_get(detail, "activeProviderInfos.providerId"))
    parsed = parse_qualys_evidence(evidence or "") if provider == "QUALYS_VM" else (
        parse_tenable_evidence(evidence or "") if provider and "TENABLE" in str(provider).upper()
        else parse_generic_evidence(evidence or "")
    )
    cves = parse_cves({"sharedDetailsLocal": shared})
    if not cves:
        cves = parse_cves(detail)
    references = [reference | {"cve": cve["cve"]} for cve in cves for reference in cve["references"]]
    vector = first_not_none(detail.get("cvssVector"), build_cvss_vector(base))
    return {
        "findingId": finding_id, "assetId": asset_id,
        "hostname": first_not_none(search.get("assetEffectiveName"), search.get("assetAbsoluteName"), detail.get("hostname"), cache.get("hostname")),
        "ipAddress": first_not_none(nested_get(search, "dedupInfos.IP_ADDRESS"), detail.get("ipAddress")),
        "findingName": first_not_none(
            detail.get("findingName"), detail.get("name"), shared.get("title"),
            next(iter(nested_get(search, "assessmentsRelated.byExtendedAttributesTitles", []) or []), None),
        ),
        "status": first_not_none(search.get("status"), nested_get(search, "findingStatus.status"), detail.get("status"), cache.get("status")),
        "providerId": provider, "assessmentName": shared.get("assessmentName"),
        # Hackuity expose ici les vecteurs dans cvss31/effectiveCvss31, pas un
        # score numérique de base. On conserve donc le score environnemental
        # fourni comme score CVSS exploitable, sans recalcul local.
        "cvssScore": as_float(first_not_none(
            score.get("base"), detail.get("cvssScore"), detail.get("base"),
            nested_get(search, "findingStatus.score.cvss31.baseScore"),
        )),
        "environmentalScore": as_float(first_not_none(score.get("environmental"), detail.get("environmental"), nested_get(detail, "effectiveScoreInfo.environmental"))),
        "temporalScore": as_float(first_not_none(score.get("temporal"), detail.get("temporal"), nested_get(detail, "effectiveScoreInfo.temporal"))),
        "hyScoreV2": as_float(first_not_none(score.get("hyScoreV2"), nested_get(search, "findingStatus.score.hyScoreV2"), detail.get("hyScoreV2"), cache.get("hyScoreV2"))),
        "cvssVersion": first_not_none(score.get("cvssVersion"), "3.1" if vector and str(vector).startswith("CVSS:3.1") else None),
        "cvssVector": vector, "cvssAttackVector": base.get("AV"), "cvssAttackComplexity": base.get("AC"),
        "cvssPrivilegesRequired": base.get("PR"), "cvssUserInteraction": base.get("UI"),
        "cvssScope": base.get("S"), "cvssConfidentiality": base.get("C"),
        "cvssIntegrity": base.get("I"), "cvssAvailability": base.get("A"),
        "cvssExploitCodeMaturity": temp.get("E"),
        "epssScore": as_float(metrics.get("FINDING_EPSS")),
        "exploitabilityScore": as_float(metrics.get("FINDING_EXPLOITABILITY")),
        "exploitMaturityScore": as_float(metrics.get("FINDING_EXPLOIT_MATURITY")),
        "threatIntensityScore": as_float(metrics.get("FINDING_THREAT_INTENSITY")),
        "cisaKev": first_not_none(search.get("cisaKev"), detail.get("cisaKev"), cache.get("cisaKev")), "cvesJson": serialize_json([row["cve"] for row in cves]),
        "cveDescriptionsJson": serialize_json({row["cve"]: row["description"] for row in cves}),
        "referencesJson": serialize_json(references),
        "providerEvidenceTitle": evidence_nodes[0] if evidence_nodes else None,
        "providerEvidenceRaw": evidence,
        "registryPathsJson": serialize_json(parsed["registryPaths"]),
        "filePathsJson": serialize_json(parsed["filePaths"]),
        "detectedVersionsJson": serialize_json(parsed["detectedVersions"]),
        "expectedVersionsJson": serialize_json(parsed["expectedVersions"]),
        "vulnerableSoftwareJson": serialize_json(first_not_none(provider_info.get("vulnerableSoftwares"), search.get("vulnerableSoftwares"), detail.get("vulnerableSoftwares"), parsed.get("component"))),
        "remediation": first_not_none(
            detail.get("remediation"), shared.get("remediation"),
            next(iter(nested_get(search, "assessmentsRelated.byExtendedAttributesRemediations", []) or []), None),
        ),
        "firstSeen": min((value for value in [
            *(parse_timestamp(item.get("firstDetection")) for item in providers),
            parse_timestamp(detail.get("firstSeen")), parse_timestamp(nested_get(search, "detectionInfo.firstSeen")),
        ] if value is not None), default=None),
        "lastSeen": parse_timestamp(first_not_none(search.get("updatedAt"), detail.get("updatedAt"))),
        "hackuityHistoryUrl": build_hackuity_history_url(app_url, namespace, asset_id, finding_id),
        "sourceEndpoint": cache.get("sourceEndpoint"),
        "extractedAt": parse_timestamp(cache.get("extractedAt")) or datetime.now(timezone.utc).replace(tzinfo=None),
        "_cves": cves, "_references": references, "_parsedEvidence": parsed,
    }

def cache_is_valid(path: Path) -> bool:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return isinstance(value, Mapping) and isinstance(value.get("data"), Mapping) and bool(value.get("findingId"))
    except (OSError, json.JSONDecodeError):
        return False
