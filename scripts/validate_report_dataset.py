from __future__ import annotations

import argparse
import json
from pathlib import Path

from _bootstrap import ROOT
from hackuity_pipeline.intelligence.quality import validate_context


def main() -> None:
    parser = argparse.ArgumentParser(description="Valide un report_context Hackuity.")
    parser.add_argument("path", type=Path)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    context = json.loads(args.path.read_text(encoding="utf-8"))
    errors = validate_context(context, args.strict)
    if errors:
        print("[FAIL] Report Intelligence Dataset")
        for error in errors:
            print(f"  - {error}")
        raise SystemExit(1)
    print(f"[OK] {args.path}")
    print(f"     schema={context['metadata']['schema_version']} findings={len(context['findings'])} CVE={len(context['vulnerabilities'])}")


if __name__ == "__main__":
    main()
