from __future__ import annotations

from collections.abc import Sequence
from typing import Any


def classify_history(observations: Sequence[dict[str, Any]]) -> str:
    """Classify ordered detection observations without inferring missing scans."""
    rows = sorted(observations, key=lambda row: str(row.get("observation_date") or ""))
    if not rows:
        return "UNKNOWN"
    detected = [bool(row.get("detected")) for row in rows]
    if len(rows) == 1:
        return "NEW" if detected[0] and rows[0].get("is_first_observation") else "UNKNOWN"
    if detected[-1] and any(not item for item in detected[:-1]):
        return "REOPENED"
    if not detected[-1] and any(detected[:-1]):
        return "RESOLVED"
    if detected[-1] and all(detected):
        return "PERSISTENT"
    return "UNKNOWN"


def observation_count(first_seen: str | None, last_seen: str | None) -> int:
    # Bounds are not scans. Return one evidence point unless two distinct dates exist.
    if not first_seen and not last_seen:
        return 0
    return 2 if first_seen and last_seen and first_seen != last_seen else 1
