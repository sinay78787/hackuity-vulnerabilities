from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import pyarrow as pa
import pyarrow.parquet as pq

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = PROJECT_ROOT / "logs" / "hackuity_pipeline.log"

ASSET_SCHEMA = pa.schema([
    ("assetId", pa.string()), ("hostname", pa.string()),
    ("assetHyScoreV2", pa.float64()), ("ipAddress", pa.string()),
    ("assetOsPrimary", pa.string()), ("providerIdsJson", pa.string()),
    ("country", pa.string()), ("businessUnit", pa.string()),
    ("firstSeen", pa.timestamp("us")), ("lastSeen", pa.timestamp("us")),
])
ASSET_FINDING_SCHEMA = pa.schema([
    ("assetId", pa.string()), ("hostname", pa.string()),
    ("findingId", pa.string()), ("findingName", pa.string()),
    ("status", pa.string()), ("vulnerabilityTypeId", pa.string()),
    ("hyScoreV2", pa.float64()), ("cve", pa.string()),
    ("cvssScore", pa.float64()), ("cvssVector", pa.string()),
    ("severity", pa.string()), ("description", pa.string()),
    ("remediation", pa.string()), ("port", pa.int64()),
    ("protocol", pa.string()), ("service", pa.string()),
    ("provider", pa.string()), ("firstSeen", pa.timestamp("us")),
    ("lastSeen", pa.timestamp("us")), ("ignored", pa.bool_()),
    ("deactivated", pa.bool_()), ("expired", pa.bool_()), ("cisaKev", pa.bool_()),
    ("searchInfoJson", pa.string()), ("assessmentInfosJson", pa.string()),
    ("activeProviderInfosJson", pa.string()), ("rawFindingJson", pa.string()),
])

def configure_logging() -> logging.Logger:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    class BelowWarning(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return record.levelno < logging.WARNING
    stdout = logging.StreamHandler(sys.stdout)
    stdout.addFilter(BelowWarning())
    stderr = logging.StreamHandler(sys.stderr)
    stderr.setLevel(logging.WARNING)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[stdout, stderr, logging.FileHandler(LOG_FILE, encoding="utf-8")],
        force=True,
    )
    return logging.getLogger("hackuity")

def load_environment(require_api_key: bool = True) -> dict[str, Any]:
    try:
        from dotenv import load_dotenv
        load_dotenv(PROJECT_ROOT / ".env")
    except ImportError:
        pass
    required = ["HACKUITY_NAMESPACE", "HACKUITY_BASE_URL"]
    if require_api_key:
        required.append("HACKUITY_API_KEY")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise SystemExit("Configuration manquante: " + ", ".join(missing))
    value = os.environ.get("HACKUITY_VERIFY_SSL", "true").strip().lower()
    if value not in {"true", "false", "1", "0", "yes", "no"}:
        raise SystemExit("HACKUITY_VERIFY_SSL doit être true ou false")
    ca_bundle = os.environ.get("HACKUITY_CA_BUNDLE", "").strip()
    if ca_bundle and not Path(ca_bundle).is_file():
        raise SystemExit("HACKUITY_CA_BUNDLE ne pointe pas vers un fichier PEM valide")
    return {
        "api_key": os.environ.get("HACKUITY_API_KEY"),
        "namespace": os.environ["HACKUITY_NAMESPACE"],
        "base_url": os.environ["HACKUITY_BASE_URL"].rstrip("/"),
        "app_url": os.environ.get("HACKUITY_APP_URL", "https://app.hy.hackuity.io").rstrip("/"),
        "verify_ssl": ca_bundle or value in {"true", "1", "yes"},
    }

def nested_get(value: Any, path: str | Sequence[str], default: Any = None) -> Any:
    keys = path.split(".") if isinstance(path, str) else path
    current = value
    for key in keys:
        if not isinstance(current, Mapping) or key not in current:
            return default
        current = current[key]
    return current

def first_not_none(*values: Any) -> Any:
    return next((value for value in values if value is not None and value != ""), None)

def serialize_json(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"), sort_keys=True)

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

def extract_cves(value: Any) -> list[str]:
    found: set[str] = set()
    def visit(item: Any) -> None:
        if isinstance(item, str):
            found.update(match.upper() for match in _CVE.findall(item))
        elif isinstance(item, Mapping):
            for child in item.values():
                visit(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                visit(child)
    visit(value)
    return sorted(found)

def parse_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
    except (ValueError, TypeError, OSError):
        return None

def as_float(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None

def as_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None

def normalize_asset(asset: Mapping[str, Any]) -> dict[str, Any]:
    provider_ids = first_not_none(asset.get("assetProviderIds"), asset.get("providerIds"))
    return {
        "assetId": first_not_none(asset.get("assetId"), asset.get("id")),
        "hostname": first_not_none(asset.get("hostname"), asset.get("assetEffectiveName"), asset.get("assetAbsoluteName")),
        "assetHyScoreV2": as_float(first_not_none(asset.get("score"), nested_get(asset, "assetStatus.score.hyScoreV2"))),
        "ipAddress": first_not_none(asset.get("ipAddress"), asset.get("assetIp"), nested_get(asset, "dedupInfos.IP_ADDRESS"), nested_get(asset, "network.ipAddress")),
        "assetOsPrimary": _os_name(first_not_none(asset.get("assetOsPrimary"), nested_get(asset, "operatingSystem.primary"))),
        "providerIdsJson": serialize_json(provider_ids),
        "country": first_not_none(asset.get("country"), nested_get(asset, "location.country")),
        "businessUnit": first_not_none(asset.get("businessUnit"), nested_get(asset, "organization.businessUnit")),
        "firstSeen": parse_timestamp(first_not_none(asset.get("firstSeen"), asset.get("createdAt"))),
        "lastSeen": parse_timestamp(first_not_none(asset.get("lastSeen"), asset.get("updatedAt"))),
    }

def _os_name(value: Any) -> str | None:
    if isinstance(value, Mapping):
        return first_not_none(value.get("fullName"), value.get("name"), value.get("family"))
    return str(value) if value not in (None, "") else None

def _assessment_value(finding: Mapping[str, Any], field: str) -> Any:
    rows = nested_get(finding, "assessmentsRelated.byExtendedAttributes", [])
    if isinstance(rows, list):
        return first_not_none(*(row.get(field) for row in rows if isinstance(row, Mapping)))
    return None

def normalize_finding(finding: Mapping[str, Any], asset: Mapping[str, Any] | None = None) -> dict[str, Any]:
    asset = asset or {}
    cves = extract_cves(finding)
    location = first_not_none(finding.get("findingLocation"), {}) or {}
    return {
        "assetId": first_not_none(finding.get("assetId"), asset.get("assetId")),
        "hostname": first_not_none(finding.get("assetEffectiveName"), finding.get("assetAbsoluteName"), asset.get("hostname")),
        "findingId": first_not_none(finding.get("findingId"), finding.get("id")),
        "findingName": first_not_none(finding.get("name"), finding.get("findingName"), nested_get(finding, "vulnerability.name")),
        "status": first_not_none(finding.get("status"), nested_get(finding, "findingStatus.status")),
        "vulnerabilityTypeId": first_not_none(finding.get("vulnerabilityTypeId"), finding.get("vulnTypeId")),
        "hyScoreV2": as_float(first_not_none(finding.get("hyScoreV2"), nested_get(finding, "findingStatus.score.hyScoreV2"), nested_get(finding, "metrics.hyScoreV2"))),
        "cve": cves[0] if cves else None,
        "cvssScore": as_float(first_not_none(finding.get("cvssScore"), nested_get(finding, "findingStatus.score.cvss31.baseScore"), nested_get(finding, "findingStatus.score.cvss31.score"), nested_get(finding, "findingStatus.score.cvss4.baseScore"), nested_get(finding, "metrics.cvss.score"), nested_get(finding, "metrics.cvssScore"), nested_get(finding, "cvss.score"))),
        "cvssVector": first_not_none(finding.get("cvssVector"), nested_get(finding, "findingStatus.score.cvss31.vector"), nested_get(finding, "findingStatus.score.cvss4.vector"), nested_get(finding, "metrics.cvss.vector"), nested_get(finding, "cvss.vector")),
        "severity": first_not_none(finding.get("severity"), nested_get(finding, "metrics.severity")),
        "description": first_not_none(finding.get("description"), _assessment_value(finding, "description"), nested_get(finding, "vulnerability.description")),
        "remediation": first_not_none(finding.get("remediation"), finding.get("solution"), _assessment_value(finding, "remediation"), nested_get(finding, "vulnerability.remediation")),
        "port": as_int(first_not_none(finding.get("port"), location.get("port") if isinstance(location, Mapping) else None)),
        "protocol": first_not_none(finding.get("protocol"), location.get("protocol") if isinstance(location, Mapping) else None),
        "service": first_not_none(finding.get("service"), location.get("service") if isinstance(location, Mapping) else None),
        "provider": first_not_none(finding.get("provider"), nested_get(finding, "dedupInfos.CLOUD_PROVIDER_NAME"), nested_get(finding, "activeProviderInfos.name")),
        "firstSeen": parse_timestamp(first_not_none(finding.get("firstSeen"), finding.get("detectedAt"), nested_get(finding, "detectionInfo.firstSeen"))),
        "lastSeen": parse_timestamp(first_not_none(finding.get("lastSeen"), finding.get("updatedAt"), nested_get(finding, "detectionInfo.lastSeen"))),
        "ignored": finding.get("ignored"), "deactivated": finding.get("deactivated"), "expired": finding.get("expired"),
        "cisaKev": finding.get("cisaKev"),
        "searchInfoJson": serialize_json(finding.get("searchInfo")),
        "assessmentInfosJson": serialize_json(first_not_none(finding.get("assessmentInfos"), finding.get("assessmentIds"))),
        "activeProviderInfosJson": serialize_json(finding.get("activeProviderInfos")),
        "rawFindingJson": serialize_json(finding),
    }

normalize_finding_detail = normalize_finding

def write_rows(rows: Iterable[Mapping[str, Any]], path: Path, schema: pa.Schema) -> int:
    materialized = [
        {
            field.name: _coerce_arrow_value(row.get(field.name), field.type)
            for field in schema
        }
        for row in rows
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(materialized, schema=schema)
    pq.write_table(table, path, compression="snappy", use_dictionary=True)
    return len(materialized)

def _coerce_arrow_value(value: Any, arrow_type: pa.DataType) -> Any:
    """Aplatit et type une valeur avant sa conversion par Arrow.

    Les API peuvent renvoyer un scalaire, une liste ou un objet pour un même
    concept selon le provider. Les colonnes Power BI textuelles conservent les
    valeurs complexes sous forme de JSON, jamais en type Arrow imbriqué.
    """
    if value is None:
        return None
    if pa.types.is_string(arrow_type) or pa.types.is_large_string(arrow_type):
        if isinstance(value, (Mapping, list, tuple, set)):
            return serialize_json(value)
        return str(value)
    if pa.types.is_floating(arrow_type):
        return as_float(value)
    if pa.types.is_integer(arrow_type):
        return as_int(value)
    if pa.types.is_boolean(arrow_type):
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1", "yes"}:
                return True
            if normalized in {"false", "0", "no"}:
                return False
            return None
        return bool(value)
    if pa.types.is_timestamp(arrow_type):
        return parse_timestamp(value)
    return value

def stable_key(value: str | None) -> str:
    return hashlib.sha256((value or "").strip().lower().encode("utf-8")).hexdigest()[:24]
