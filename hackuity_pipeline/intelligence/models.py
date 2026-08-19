from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0"
PRIORITIES = {"P1", "P2", "P3"}
HISTORY_STATES = {"NEW", "PERSISTENT", "RESOLVED", "REOPENED", "REGRESSION", "UNKNOWN"}
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def normalize_hostname(value: Any) -> str | None:
    value = str(value or "").strip().lower().rstrip(".")
    return value or None


def short_hostname(value: Any) -> str | None:
    normalized = normalize_hostname(value)
    return normalized.split(".", 1)[0] if normalized else None


def normalize_cve(value: Any) -> str | None:
    candidate = str(value or "").strip().upper()
    return candidate if _CVE.match(candidate) else None


def normalize_scanner(value: Any) -> str:
    candidate = str(value or "").strip()
    key = re.sub(r"[^a-z0-9]", "", candidate.lower())
    aliases = {"qualys": "Qualys VM", "qualysvm": "Qualys VM", "crowdstrike": "CrowdStrike Falcon",
               "crowdstrikefalcon": "CrowdStrike Falcon", "azure": "Microsoft Azure"}
    return aliases.get(key, candidate or "UNKNOWN")


def normalize_timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        result = value
    else:
        try:
            result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_severity(value: Any, trs: Any = None, cvss: Any = None) -> str:
    candidate = str(value or "").strip().upper()
    if candidate in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return candidate
    score, cvss_score = float(trs or 0), float(cvss or 0)
    if score >= 900 or cvss_score >= 9:
        return "CRITICAL"
    if score >= 700 or cvss_score >= 7:
        return "HIGH"
    if score >= 400 or cvss_score >= 4:
        return "MEDIUM"
    return "LOW"


def normalize_priority(value: Any, trs: Any = None, cvss: Any = None, kev: bool = False) -> str:
    candidate = str(value or "").strip().upper()
    if candidate in PRIORITIES:
        return candidate
    if kev or float(trs or 0) >= 900 or float(cvss or 0) >= 9:
        return "P1"
    if float(trs or 0) >= 700 or float(cvss or 0) >= 7:
        return "P2"
    return "P3"


def json_safe(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, datetime):
        return normalize_timestamp(value)
    if hasattr(value, "item"):
        return value.item()
    return value
