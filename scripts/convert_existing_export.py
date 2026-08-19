from __future__ import annotations

import argparse
from pathlib import Path

import ijson

import _bootstrap  # noqa: F401
from hackuity_pipeline.core import ASSET_FINDING_SCHEMA, ASSET_SCHEMA, normalize_asset, normalize_finding, write_rows

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", nargs="?", default="hackuity_all_open_findings.json")
    parser.add_argument("--output-dir", default="output/silver")
    parser.add_argument("--batch-size", type=int, default=50_000)
    parser.add_argument("--max-assets", type=int)
    parser.add_argument("--include-raw", action="store_true")
    args = parser.parse_args()
    root = Path(args.output_dir)
    asset_buffer: list[dict] = []
    finding_buffer: list[dict] = []
    asset_part = finding_part = 0
    def flush_assets() -> None:
        nonlocal asset_part
        if asset_buffer:
            write_rows(asset_buffer, root / "assets" / f"part-{asset_part:06d}.parquet", ASSET_SCHEMA)
            asset_buffer.clear(); asset_part += 1
    def flush_findings() -> None:
        nonlocal finding_part
        if finding_buffer:
            write_rows(finding_buffer, root / "asset_findings" / f"part-{finding_part:06d}.parquet", ASSET_FINDING_SCHEMA)
            finding_buffer.clear(); finding_part += 1
    with Path(args.source).open("rb") as stream:
        for index, raw_asset in enumerate(ijson.items(stream, "item"), start=1):
            container = raw_asset.get("findings")
            rows = container.get("searchFindings") if isinstance(container, dict) else None
            asset_source = dict(raw_asset)
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                for key in ("assetOsPrimary", "assetProviderIds", "providerIds", "dedupInfos"):
                    if asset_source.get(key) is None:
                        asset_source[key] = rows[0].get(key)
            asset = normalize_asset(asset_source)
            asset_buffer.append(asset)
            if isinstance(rows, list):
                for raw_finding in rows:
                    if not isinstance(raw_finding, dict):
                        continue
                    row = normalize_finding(raw_finding, asset)
                    if not args.include_raw:
                        row["rawFindingJson"] = None
                    finding_buffer.append(row)
                    if len(finding_buffer) >= args.batch_size:
                        flush_findings()
            if len(asset_buffer) >= args.batch_size:
                flush_assets()
            if args.max_assets and index >= args.max_assets:
                break
    flush_assets(); flush_findings()
    print(f"Écrit: {asset_part} lots assets, {finding_part} lots asset_findings")

if __name__ == "__main__":
    main()
