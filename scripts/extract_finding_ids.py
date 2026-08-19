from __future__ import annotations

import argparse
from pathlib import Path

import duckdb
import ijson
import pyarrow as pa

import _bootstrap  # noqa: F401
from hackuity_pipeline.core import nested_get, write_rows

SCHEMA = pa.schema([
    ("assetId", pa.string()), ("hostname", pa.string()),
    ("findingId", pa.string()), ("hyScoreV2", pa.float64()),
    ("status", pa.string()), ("cisaKev", pa.bool_()),
])

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", nargs="?", default="hackuity_all_open_findings.json")
    parser.add_argument("--output", default="output/silver/finding_ids.parquet")
    parser.add_argument("--batch-size", type=int, default=100_000)
    parser.add_argument("--max-assets", type=int)
    args = parser.parse_args()
    output = Path(args.output)
    parts = output.parent / ".finding_id_parts"
    parts.mkdir(parents=True, exist_ok=True)
    buffer: list[dict] = []
    part = 0
    def flush() -> None:
        nonlocal part
        if buffer:
            write_rows(buffer, parts / f"part-{part:06d}.parquet", SCHEMA)
            buffer.clear(); part += 1
    with Path(args.source).open("rb") as stream:
        for index, asset in enumerate(ijson.items(stream, "item"), start=1):
            container = asset.get("findings")
            rows = container.get("searchFindings") if isinstance(container, dict) else None
            if isinstance(rows, list):
                for finding in rows:
                    finding_id = finding.get("findingId") if isinstance(finding, dict) else None
                    if not finding_id:
                        continue
                    buffer.append({
                        "assetId": asset.get("assetId"), "hostname": asset.get("hostname"),
                        "findingId": finding_id,
                        "hyScoreV2": nested_get(finding, "findingStatus.score.hyScoreV2"),
                        "status": finding.get("status") or nested_get(finding, "findingStatus.status"),
                        "cisaKev": finding.get("cisaKev"),
                    })
                    if len(buffer) >= args.batch_size:
                        flush()
            if args.max_assets and index >= args.max_assets:
                break
    flush()
    output.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    source_sql = str(parts / "*.parquet").replace("\\", "/").replace("'", "''")
    output_sql = str(output).replace("\\", "/").replace("'", "''")
    con.execute(
        "COPY (SELECT assetId, any_value(hostname) hostname, findingId, "
        "max(hyScoreV2) hyScoreV2, any_value(status) status, bool_or(coalesce(cisaKev,false)) cisaKev "
        f"FROM read_parquet('{source_sql}') GROUP BY assetId, findingId) "
        f"TO '{output_sql}' (FORMAT PARQUET, COMPRESSION SNAPPY)"
    )
    print(f"Écrit: {output}")

if __name__ == "__main__":
    main()
