from __future__ import annotations

import json
from pathlib import Path

from hackuity_pipeline.evidence import extract_technical_evidence, normalize_event_type
from hackuity_pipeline.intelligence.quality import component_quality
from hackuity_pipeline.intelligence.report_context import write_intelligence_dataset

FIXTURE = Path("tests/fixtures/finding_technical_details.json")


def evidence():
    return extract_technical_evidence(json.loads(FIXTURE.read_text(encoding="utf-8")), FIXTURE.as_posix())


def test_component_extraction() -> None:
    component = evidence()["components"][0]
    assert component["package"] == "com.fasterxml.jackson.core:jackson-databind"
    assert component["language"] == "Java"


def test_multiple_component_occurrences() -> None:
    result = evidence()
    assert len(result["components"]) == 1
    assert len(result["occurrences"]) == 2
    assert len({row["install_path"] for row in result["occurrences"]}) == 2


def test_installed_required_version() -> None:
    component = evidence()["components"][0]
    assert component["installed_version"] == "2.9.5"
    assert component["required_version"] == "2.9.10.1"


def test_scanner_reference_qid() -> None:
    assert {"type": "QID", "value": "981964"} in evidence()["scanner_evidence"][0]["references"]


def test_generic_scanner_reference() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    provider = fixture["data"]["assessmentsRelated"]["activeFindingProviderInfos"][0]
    provider["providerId"] = "NESSUS"
    provider["extendedAttributesList"] = [{"pluginId": "12345"}]
    result = extract_technical_evidence(fixture)
    assert result["scanner_evidence"][0]["references"] == [{"type": "PLUGIN_ID", "value": "12345"}]


def test_finding_event_parsing() -> None:
    events = evidence()["events"]
    assert events[0]["event_type"] == "FINDING_CREATED"
    assert events[1]["event_type"] == "ASSET_INDICATORS_CHANGED"


def test_event_timestamp() -> None:
    assert evidence()["events"][0]["event_timestamp"] == "2026-01-28T06:17:00Z"


def test_multi_scanner_component() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    second = json.loads(json.dumps(fixture["data"]["assessmentsRelated"]["activeFindingProviderInfos"][0]))
    second["providerId"] = "CROWDSTRIKE_FALCON"
    fixture["data"]["assessmentsRelated"]["activeFindingProviderInfos"].append(second)
    scanners = {row["scanner"] for row in extract_technical_evidence(fixture)["components"]}
    assert scanners == {"Qualys VM", "CrowdStrike Falcon"}


def test_component_cve_link() -> None:
    refs = evidence()["scanner_evidence"][0]["references"]
    assert any(row["type"] == "QID" for row in refs)


def test_component_remediation_link() -> None:
    component = evidence()["components"][0]
    assert component["required_version"] == "2.9.10.1"


def test_component_data_quality() -> None:
    incomplete = [{"component_id": "cmp-1", "package": "pkg", "installed_versions": [], "required_versions": ["2"]}]
    warnings = component_quality(incomplete, [])
    assert "component_without_version:cmp-1" in warnings
    assert "required_version_without_installed_version:cmp-1" in warnings


def test_all_assets_generation() -> None:
    base = {"metadata": {"hostname": "A"}, "asset": {"asset_id": "1"}, "findings": [],
            "vulnerabilities": [], "components": [], "component_occurrences": [],
            "scan_history": [], "finding_history": [], "history": {"events": []},
            "risk_history": {}, "remediation": {"actions": []}, "sources": []}
    second = json.loads(json.dumps(base)); second["metadata"]["hostname"] = "B"
    target = Path("output/smoke/tests/intelligence-all")
    paths = write_intelligence_dataset([base, second], target)
    assert [path.name for path in paths] == ["A.json", "B.json"]
