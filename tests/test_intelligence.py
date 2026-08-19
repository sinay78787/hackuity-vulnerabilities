from __future__ import annotations

from hackuity_pipeline.intelligence.history import classify_history
from hackuity_pipeline.intelligence.models import normalize_cve, normalize_scanner
from hackuity_pipeline.intelligence.quality import validate_context
from hackuity_pipeline.intelligence.remediation import build_actions
from hackuity_pipeline.intelligence.report_context import _vulnerabilities


def obs(*detected: bool):
    return [{"observation_date": f"2026-01-{index:02d}T00:00:00Z", "detected": value,
             "is_first_observation": index == 1} for index, value in enumerate(detected, 1)]


def test_new_finding() -> None:
    assert classify_history(obs(True)) == "NEW"


def test_persistent_finding() -> None:
    assert classify_history(obs(True, True)) == "PERSISTENT"


def test_resolved_finding() -> None:
    assert classify_history(obs(True, False)) == "RESOLVED"


def test_reopened_finding() -> None:
    assert classify_history(obs(True, False, True)) == "REOPENED"


def finding(fid: str, scanner: str, cve: str = "CVE-2025-1234") -> dict:
    return {"asset_id": "a", "finding_id": fid, "source": {"scanner": scanner},
            "cves": [cve], "title": "Test", "severity": "HIGH", "trs": 750,
            "cvss": 8.0, "epss": None, "cisa_kev": None, "affected_product": None,
            "first_seen": None, "last_seen": None, "age_days": None,
            "observation_count": 1, "history_state": "UNKNOWN", "priority": "P2",
            "target_version": None, "recommendation": "Install KB1"}


def test_multi_scanner_correlation() -> None:
    vuln = _vulnerabilities([finding("f1", "Qualys VM"), finding("f2", "CrowdStrike Falcon")])[0]
    assert vuln["scanner_correlation"]["type"] == "multi_source_confirmed"
    assert vuln["scanner_correlation"]["confidence"] == "HIGH"


def test_cve_aggregation_and_normalization() -> None:
    assert normalize_cve("cve-2025-1234") == "CVE-2025-1234"
    assert len(_vulnerabilities([finding("f1", "Qualys VM"), finding("f2", "Qualys VM")])) == 1


def test_remediation_reference_integrity() -> None:
    actions, campaigns = build_actions([finding("f1", "Qualys VM"), finding("f2", "Qualys VM")])
    assert actions[0]["related_findings"] == ["f1", "f2"]
    assert campaigns[0]["estimated_findings_closed"] == 2


def test_missing_data() -> None:
    assert normalize_scanner(None) == "UNKNOWN"
    assert normalize_cve(None) is None


def test_history_date_validation() -> None:
    context = minimal_context()
    context["findings"][0]["first_seen"] = "2026-02-01T00:00:00Z"
    context["findings"][0]["last_seen"] = "2026-01-01T00:00:00Z"
    assert any("first_seen > last_seen" in error for error in validate_context(context))


def minimal_context() -> dict:
    return {"metadata": {"schema_version": "1.0"}, "asset": {"hostname": "host"},
            "current_posture": {}, "findings": [{"finding_id": "f1", "priority": "P2",
                "history_state": "UNKNOWN", "first_seen": None, "last_seen": None,
                "cves": ["CVE-2025-1234"], "source": {"scanner": "Qualys VM"}}],
            "vulnerabilities": [{"cve": "CVE-2025-1234"}], "risk_analysis": {},
            "remediation": {"actions": [{"id": "REM-001", "related_findings": ["f1"]}]},
            "validation": {}, "sources": [{"name": "Qualys VM"}], "data_quality": {"missing_fields": []}}


def test_report_context_validation() -> None:
    assert validate_context(minimal_context()) == []
