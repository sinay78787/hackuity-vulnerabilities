import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from hackuity_pipeline.core import write_rows
from hackuity_pipeline.finding_details import (
    FINDING_DETAIL_SCHEMA, build_cvss_vector, build_hackuity_history_url,
    cache_is_valid, extract_text_nodes, normalize_detail, parse_cves,
    normalize_provider_observations, parse_qualys_evidence, parse_references,
)

FIXTURE = Path("tests/fixtures/finding_detail_cache.json")

def fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))

def test_extract_text_nodes_order_and_deduplication() -> None:
    value = {"children": [{"text": " A "}, [{"text": "B"}, {"text": "A"}], {"unexpected": 1}]}
    assert extract_text_nodes(value) == ["A", "B"]
    assert extract_text_nodes({}) == []

def test_parse_qualys_evidence() -> None:
    text = r"""Qualys VM details for "Office component" (QID 110261)
HKLM\SOFTWARE\Vendor\Product LastProduct = 12.0.6612.1000
%ProgramFiles(x86)%\Vendor\MSO.dll Version is 12.0.6607.1000"""
    parsed = parse_qualys_evidence(text)
    assert parsed["registryPaths"] == [r"HKLM\SOFTWARE\Vendor\Product"]
    assert parsed["filePaths"] == [r"%ProgramFiles(x86)%\Vendor\MSO.dll"]
    assert "12.0.6607.1000" in parsed["detectedVersions"]
    assert "12.0.6612.1000" in parsed["expectedVersions"]
    assert parsed["qid"] == "110261"

def test_parse_references_valid_and_invalid() -> None:
    valid, raw = parse_references('[{"name":"NVD","url":"https://example.test"}]')
    assert valid[0]["name"] == "NVD" and raw is not None
    invalid, raw = parse_references("not-json")
    assert invalid == [] and raw == "not-json"

def test_parse_multiple_and_missing_cves() -> None:
    assert [item["cve"] for item in parse_cves(fixture()["data"])] == ["CVE-2025-12345", "CVE-2024-9999"]
    assert parse_cves({}) == []

def test_build_cvss_vector() -> None:
    metrics = {"AV":"N","AC":"H","PR":"N","UI":"N","S":"C","C":"H","I":"H","A":"H"}
    assert build_cvss_vector(metrics) == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert build_cvss_vector({"AV": "N"}) is None

def test_history_url() -> None:
    assert build_hackuity_history_url("https://app.example", "N1", "a", "f") == "https://app.example/N1/assets/live-report/a/vuln-management/findings/finding/f/history"

def test_normalization_and_arrow_types() -> None:
    row = normalize_detail(fixture(), "https://app.example", "N1")
    row = {key: value for key, value in row.items() if not key.startswith("_")}
    target = Path("output/smoke/tests/finding-detail.parquet")
    write_rows([row], target, FINDING_DETAIL_SCHEMA)
    schema = pq.read_schema(target)
    assert not any(pa.types.is_null(field.type) or pa.types.is_nested(field.type) for field in schema)

def test_cache_validation_and_resume() -> None:
    assert cache_is_valid(FIXTURE)
    assert not cache_is_valid(Path("tests/fixtures/sample_export.json"))

def test_cvss_base_and_earliest_provider_detection() -> None:
    cache = fixture()
    infos = [{"providerId": "QUALYS_VM", "assessmentId": "first",
              "firstDetection": "2025-03-02T00:00:00Z",
              "initialScore": {"base": 8.8, "environmental": 6.1}},
             {"providerId": "CROWDSTRIKE_FALCON", "assessmentId": "second",
              "firstDetection": "2025-03-01T00:00:00Z", "initialScore": {"base": 7.2}}]
    cache["data"]["assessmentsRelated"] = {"activeFindingProviderInfos": infos}
    row = normalize_detail(cache, "https://app.example", "N1")
    assert row["cvssScore"] == 8.8
    assert row["environmentalScore"] == 6.1
    assert row["firstSeen"].isoformat() == "2025-03-01T00:00:00"

def test_provider_observations_preserve_qid() -> None:
    cache = fixture()
    info = {"providerId": "QUALYS_VM", "assessmentId": "first",
            "initialScore": {"base": 8.8}, "extendedAttributesList": [{"qid": 110261}]}
    cache["data"]["assessmentsRelated"] = {"activeFindingProviderInfos": [info]}
    providers, references = normalize_provider_observations(cache)
    assert len(providers) == 1
    assert providers[0]["baseScore"] == info["initialScore"].get("base")
    assert references[0]["referenceType"] == "QID"
    assert references[0]["referenceValue"] == "110261"
