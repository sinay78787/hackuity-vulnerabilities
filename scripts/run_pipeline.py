from __future__ import annotations

import argparse
import subprocess
import sys

STEPS = {
    "inspect": ["scripts/inspect_hackuity_export.py"],
    "convert": ["scripts/convert_existing_export.py"],
    "ids": ["scripts/extract_finding_ids.py"],
    "enrich": ["scripts/enrich_finding_details.py", "--min-hyscore", "900", "--limit", "100", "--resume"],
    "silver": ["scripts/build_silver_model.py"],
    "detail-silver": ["scripts/build_finding_details_silver.py"],
    "gold": ["scripts/build_gold_model.py"],
    "remediation-gold": ["scripts/build_remediation_gold.py"],
    "validate": ["scripts/validate_outputs.py"],
}

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--step", choices=list(STEPS))
    parser.add_argument("--skip-inspect", action="store_true")
    parser.add_argument("--skip-enrich", action="store_true")
    parser.add_argument("--enrich-finding-details", action="store_true",
                        help="Autorise l'étape API, limitée à 100 findings prioritaires.")
    args = parser.parse_args()
    selected = [args.step] if args.step else list(STEPS)
    for name in selected:
        if name == "inspect" and args.skip_inspect:
            continue
        if name == "enrich" and (args.skip_enrich or not args.enrich_finding_details):
            continue
        if name in {"detail-silver", "remediation-gold"} and not args.enrich_finding_details:
            from pathlib import Path
            if not any(Path("output/bronze/finding_details").glob("*.json")):
                continue
        print(f"=== {name} ===", flush=True)
        subprocess.run([sys.executable, *STEPS[name]], check=True)

if __name__ == "__main__":
    main()
