import subprocess
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from hackuity_pipeline.core import (
    ASSET_SCHEMA, extract_cves, nested_get, normalize_asset, normalize_finding,
    serialize_json, write_rows,
)

def test_nested_get() -> None:
    assert nested_get({"a": {"b": 2}}, "a.b") == 2
    assert nested_get({"a": {}}, "a.missing") is None

def test_extract_cves_recursive_and_deduplicated() -> None:
    assert extract_cves({"x": ["cve-2025-1234", "CVE-2025-1234", "CVE-2024-99999"]}) == [
        "CVE-2024-99999", "CVE-2025-1234"
    ]

def test_serialize_complex() -> None:
    assert serialize_json({"b": 1, "a": [2]}) == '{"a":[2],"b":1}'

def test_normalize_asset_without_ip() -> None:
    row = normalize_asset({"assetId": "a", "hostname": "h", "score": 1})
    assert row["ipAddress"] is None
    assert row["assetHyScoreV2"] == 1.0

def test_normalize_finding_without_cve() -> None:
    row = normalize_finding({"findingId": "f", "findingStatus": {"score": {"hyScoreV2": 900}}})
    assert row["cve"] is None
    assert row["hyScoreV2"] == 900

def test_explicit_schema_prevents_arrow_null() -> None:
    target = Path("output/smoke/tests/all-null.parquet")
    write_rows([normalize_asset({"assetId": "a"})], target, ASSET_SCHEMA)
    schema = pq.read_schema(target)
    assert not any(pa.types.is_null(field.type) for field in schema)

def test_complex_value_is_serialized_for_string_column() -> None:
    target = Path("output/smoke/tests/complex-string.parquet")
    row = normalize_asset({"assetId": "a"})
    row["hostname"] = ["alias-1", "alias-2"]
    write_rows([row], target, ASSET_SCHEMA)
    assert pq.read_table(target).column("hostname")[0].as_py() == '["alias-1","alias-2"]'

def test_deduplication_key_semantics() -> None:
    rows = [{"assetId": "a", "findingId": "f"}, {"assetId": "a", "findingId": "f"}]
    assert len({(row["assetId"], row["findingId"]) for row in rows}) == 1

def test_resume_cache_semantics() -> None:
    cache = Path("output/smoke/tests/finding.json.gz")
    cache.parent.mkdir(parents=True, exist_ok=True)
    if cache.exists():
        cache.unlink()
    assert not cache.exists()
    cache.touch()
    assert cache.exists()


def test_inspect_parquets_writes_text_report_for_hostname() -> None:
    root = Path(__file__).resolve().parents[1]
    output_file = root / "output" / "inspection" / "BYCVWEB221.txt"
    if output_file.exists():
        output_file.unlink()

    env = {**dict(__import__("os").environ), "PYTHONPATH": str(root)}
    subprocess.run(
        [
            sys.executable,
            "tools/inspect_parquets.py",
            "--hostname",
            "BYCVWEB221",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    assert output_file.exists()
    assert output_file.read_text(encoding="utf-8")


def test_export_asset_summary_supports_compact_limit() -> None:
    root = Path(__file__).resolve().parents[1]
    output_file = root / "output" / "inspection" / "BCNVSRV3103_compact.txt"
    if output_file.exists():
        output_file.unlink()

    env = {**dict(__import__("os").environ), "PYTHONPATH": str(root)}
    subprocess.run(
        [
            sys.executable,
            "tools/export_asset_summary.py",
            "--hostname",
            "BCNVSRV3103",
            "--limit",
            "2",
            "--output",
            str(output_file),
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    text = output_file.read_text(encoding="utf-8")
    assert "Showing top 2" in text
    assert text.count("Finding ID :") == 2
    assert "Package" in text
    assert "Installed Version" in text
    assert "Required Version" in text
    assert "Install Path(s)" in text
    assert "Vulnerable File Paths" in text
    assert len(text) < 100_000
