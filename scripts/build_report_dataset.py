from __future__ import annotations

import argparse
import sys
from pathlib import Path

from _bootstrap import ROOT
from hackuity_pipeline.intelligence import build_report_context, write_intelligence_dataset
from hackuity_pipeline.intelligence.quality import validate_context


def main() -> None:
    parser = argparse.ArgumentParser(description="Construit le Report Intelligence Dataset Hackuity.")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--hostname")
    selection.add_argument("--all", action="store_true")
    parser.add_argument("--output-dir", default="output/intelligence")
    parser.add_argument("--pretty-json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    hostnames = [args.hostname]
    if args.all:
        import duckdb
        hostnames = [row[0] for row in duckdb.connect().execute(
            "SELECT hostname FROM read_parquet('output/silver/assets.parquet') ORDER BY hostname").fetchall()]
    contexts = []
    for hostname in hostnames:
        context = build_report_context(hostname)
        errors = validate_context(context, args.strict)
        if errors:
            raise SystemExit("\n".join(errors))
        contexts.append(context)
        posture = context["current_posture"]
        print("=============================================")
        print(" Hackuity Report Intelligence Builder")
        print("=============================================")
        print(f"\nAsset          : {context['metadata']['hostname']}\n")
        print("[OK] Gold/Silver data loaded")
        print("[OK] Asset resolved")
        print(f"[OK] Findings loaded             {posture['total_findings']:7d}")
        print(f"[OK] Unique CVEs                {posture['unique_cves']:7d}")
        print(f"[OK] Historical observations    {sum(f['observation_count'] for f in context['findings']):7d}")
        print(f"[OK] Persistent findings        {posture['persistent_findings']:7d}")
        print(f"[OK] Reopened findings          {posture['reopened_findings']:7d}")
        print(f"[OK] Multi-source CVEs          {posture['confirmed_by_multiple_sources']:7d}")
        print(f"[OK] Remediation actions        {len(context['remediation']['actions']):7d}")
        print(f"\nRisk:\n  P1 : {posture['p1']}\n  P2 : {posture['p2']}\n  P3 : {posture['p3']}")
        print(f"\nData quality:\n  Warnings : {len(context['data_quality']['warnings'])}")
    paths = write_intelligence_dataset(contexts, Path(args.output_dir), args.pretty_json)
    print("\nGenerated:")
    for path in paths:
        print(path)


if __name__ == "__main__":
    main()
