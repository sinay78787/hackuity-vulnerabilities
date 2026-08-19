from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def normalize(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def join_values(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, (list, tuple, set)):
        items = [str(item) for item in value if item not in (None, "")]
        return ", ".join(items) if items else "N/A"
    return str(value)


def find_report_context(hostname: str, root: Path) -> Path | None:
    target = normalize(hostname)
    dir_path = root / "output" / "intelligence" / "report_context"
    if not dir_path.exists():
        return None
    candidates: list[tuple[int, Path]] = []
    for path in sorted(dir_path.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        metadata = data.get("metadata", {}) if isinstance(data, dict) else {}
        names = {
            normalize(metadata.get("hostname")),
            normalize(metadata.get("fqdn")),
            normalize(path.stem),
        }
        score = 0
        if target in names:
            score = 0
        elif target in str(path.stem).lower() or target in str(metadata.get("hostname", "")).lower() or target in str(metadata.get("fqdn", "")).lower():
            score = 1
        else:
            continue
        candidates.append((score, path))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1]


def safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def get_first_present(mapping: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def summarize_component(component: dict[str, Any]) -> dict[str, Any]:
    package = component.get("package") or component.get("component") or component.get("product")
    return {
        "package": package,
        "vendor": component.get("vendor"),
        "product": component.get("product"),
        "installed_version": component.get("installed_version") or component.get("detected_version") or component.get("version"),
        "required_version": component.get("required_version") or component.get("target_version"),
        "language": component.get("language") or component.get("ecosystem"),
        "paths": component.get("paths") or component.get("occurrences") or component.get("install_paths") or [],
    }


def collect_component_rows(finding: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    technical = safe_dict(finding.get("technical_evidence"))
    for component in technical.get("components") or []:
        if isinstance(component, dict):
            rows.append(summarize_component(component))

    # Some contexts store components in nested attributes.
    for key in ("components", "component_evidence", "evidence_components"):
        raw = finding.get(key)
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    rows.append(summarize_component(item))

    if not rows:
        fallback = {
            "package": finding.get("affected_product") or finding.get("component") or finding.get("package"),
            "vendor": finding.get("vendor"),
            "product": finding.get("affected_product") or finding.get("product"),
            "installed_version": finding.get("detected_version") or finding.get("installed_version"),
            "required_version": finding.get("target_version") or finding.get("required_version"),
            "language": finding.get("language") or finding.get("ecosystem"),
            "paths": finding.get("install_paths") or finding.get("paths") or [],
        }
        if any(value not in (None, "") for value in fallback.values()):
            rows.append(fallback)
    return rows


def flatten_path_list(value: Any) -> list[str]:
    items: list[str] = []
    if value is None:
        return items
    if isinstance(value, list):
        for entry in value:
            if isinstance(entry, dict):
                for key in ("install_path", "installPath", "path", "file_path", "filePath", "location"):
                    if entry.get(key) not in (None, ""):
                        items.append(str(entry.get(key)))
                        break
                else:
                    items.extend(flatten_path_list(list(entry.values())))
            elif entry not in (None, ""):
                items.append(str(entry))
    elif isinstance(value, dict):
        for key in ("install_path", "installPath", "path", "file_path", "filePath", "location"):
            if value.get(key) not in (None, ""):
                items.append(str(value.get(key)))
        for nested in value.values():
            if isinstance(nested, (list, dict)):
                items.extend(flatten_path_list(nested))
    else:
        items.append(str(value))
    return [item for item in dict.fromkeys(items) if item not in (None, "")]


def collect_path_fields(finding: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    technical = safe_dict(finding.get("technical_evidence"))
    raw_fields = safe_dict(finding.get("raw_source_fields"))

    install_paths: list[str] = []
    vulnerable_paths: list[str] = []
    registry_paths: list[str] = []

    for source in (technical, raw_fields, finding):
        if not isinstance(source, dict):
            continue
        for key in ("install_paths", "installPaths", "install_path", "installPath"):
            install_paths.extend(flatten_path_list(source.get(key)))
        for key in ("vulnerableFilePaths", "vulnerable_file_paths", "filePaths", "file_paths"):
            vulnerable_paths.extend(flatten_path_list(source.get(key)))
        for key in ("registryPaths", "registry_paths", "registryPath", "registry_path"):
            registry_paths.extend(flatten_path_list(source.get(key)))
        for key in ("paths",):
            values = source.get(key)
            if isinstance(values, list):
                for item in values:
                    if isinstance(item, dict):
                        for nested_key in ("install_path", "installPath", "path", "file_path", "filePath", "location"):
                            if item.get(nested_key) not in (None, ""):
                                install_paths.append(str(item.get(nested_key)))
                    elif item not in (None, ""):
                        vulnerable_paths.append(str(item))

    registry_paths = [item for item in dict.fromkeys(registry_paths) if item not in (None, "")]
    vulnerable_paths = [item for item in dict.fromkeys(vulnerable_paths) if item not in (None, "")]
    install_paths = [item for item in dict.fromkeys(install_paths) if item not in (None, "")]
    return install_paths, vulnerable_paths, registry_paths


def extract_history_lines(finding: dict[str, Any], history_lookup: dict[str, list[dict[str, Any]]]) -> list[str]:
    history_rows: list[dict[str, Any]] = []
    finding_id = finding.get("finding_id") or finding.get("id")
    if finding_id and finding_id in history_lookup:
        history_rows = history_lookup[finding_id]
    else:
        history_rows = finding.get("history") or []

    lines: list[str] = []
    for item in history_rows[:20]:
        if not isinstance(item, dict):
            continue
        when = item.get("observation_date") or item.get("date") or item.get("timestamp") or item.get("event_timestamp")
        label = item.get("label") or item.get("event") or item.get("status") or item.get("type") or "Observation"
        if not when:
            continue
        detail_parts = []
        if item.get("detected") is not None:
            detail_parts.append("detected" if item.get("detected") else "not detected")
        if item.get("state"):
            detail_parts.append(str(item.get("state")))
        if item.get("severity"):
            detail_parts.append(f"severity {item.get('severity')}")
        if item.get("trs") is not None:
            detail_parts.append(f"HyScore {item.get('trs')}")
        if item.get("epss") is not None:
            detail_parts.append(f"EPSS {item.get('epss')}")
        if item.get("scanner"):
            detail_parts.append(str(item.get("scanner")))
        desc = " | ".join(detail_parts) if detail_parts else label
        lines.append(f"{when} | {label} | {desc}")

    if not lines:
        first_seen = finding.get("first_seen")
        last_seen = finding.get("last_seen")
        if first_seen:
            lines.append(f"{first_seen} | First detection")
        if last_seen:
            lines.append(f"{last_seen} | Last observation")
    return lines[:12]


def collect_findings(context: dict[str, Any]) -> list[dict[str, Any]]:
    findings = context.get("findings") or []
    if not isinstance(findings, list):
        return []
    history_lookup = {}
    raw_history = context.get("history", {}).get("finding_history", []) if isinstance(context.get("history"), dict) else []
    for row in raw_history:
        if isinstance(row, dict):
            finding_id = row.get("finding_id")
            if finding_id:
                history_lookup.setdefault(str(finding_id), []).append(row)
    for row in findings:
        if not isinstance(row, dict):
            continue
        finding_id = row.get("finding_id") or row.get("id")
        if finding_id and str(finding_id) not in history_lookup:
            history_lookup[str(finding_id)] = row.get("history") or []
    return findings


def format_paths(paths: Any) -> str:
    if not paths:
        return "N/A"
    items: list[str] = []
    if isinstance(paths, list):
        for item in paths:
            if isinstance(item, dict):
                if item.get("install_path"):
                    items.append(str(item.get("install_path")))
                elif item.get("path"):
                    items.append(str(item.get("path")))
                else:
                    items.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
            else:
                items.append(str(item))
    elif isinstance(paths, dict):
        for key, value in paths.items():
            if value not in (None, ""):
                items.append(f"{key}: {value}")
    else:
        items = [str(paths)]
    return "\n".join(f"- {item}" for item in items) if items else "N/A"


def render_summary(context: dict[str, Any], report_path: Path, limit: int = 5) -> str:
    metadata = safe_dict(context.get("metadata"))
    asset = safe_dict(context.get("asset"))
    posture = safe_dict(context.get("current_posture"))
    findings = collect_findings(context)
    history_lookup = {}
    raw_history = context.get("history", {}).get("finding_history", []) if isinstance(context.get("history"), dict) else []
    for row in raw_history:
        if isinstance(row, dict):
            fid = row.get("finding_id")
            if fid:
                history_lookup.setdefault(str(fid), []).append(row)

    effective_limit = max(1, int(limit) if limit is not None else 5)
    visible_findings = findings[:effective_limit]

    lines: list[str] = [
        "============================================================",
        "HACKUITY VULNERABILITY SUMMARY",
        "============================================================",
        "",
        "ASSET",
        "-----",
        f"Hostname : {metadata.get('hostname') or asset.get('hostname') or 'N/A'}",
        f"FQDN     : {metadata.get('fqdn') or asset.get('fqdn') or 'N/A'}",
        f"Asset ID : {asset.get('asset_id') or 'N/A'}",
        f"IP       : {join_values(asset.get('ip_addresses'))}",
        f"OS       : {asset.get('os', {}).get('name') if isinstance(asset.get('os'), dict) else 'N/A'}",
        f"Source   : {report_path.as_posix()}",
        "",
        "STATISTICS",
        "----------",
        f"Findings : {len(findings)}",
        f"With CVE : {sum(1 for f in findings if (f.get('cves') or f.get('cve') or f.get('findingAttributes', {}).get('cve_id')))}",
        f"With CVSS: {sum(1 for f in findings if f.get('cvss') not in (None, ''))}",
        f"With first/last seen: {sum(1 for f in findings if f.get('first_seen') or f.get('last_seen'))}",
        f"With remediation: {sum(1 for f in findings if (f.get('recommendation') not in (None, '')))}",
        f"With history: {sum(1 for f in findings if (f.get('history') or (str(f.get('finding_id') or f.get('id')) in history_lookup)))}",
        f"With components: {sum(1 for f in findings if collect_component_rows(f))}",
        f"Showing top {effective_limit} of {len(findings)} findings",
        "",
    ]

    if not findings:
        lines.extend(["No findings found for this asset."])
        return "\n".join(lines) + "\n"

    for finding in visible_findings:
        if not isinstance(finding, dict):
            continue
        finding_id = finding.get("finding_id") or finding.get("id") or "N/A"
        cves = finding.get("cves") or []
        if not cves and isinstance(finding.get("findingAttributes"), dict):
            cve_value = finding.get("findingAttributes", {}).get("cve_id")
            if cve_value:
                cves = [cve_value]
        else:
            cves = list(cves) if isinstance(cves, list) else [cves]

        title = finding.get("title") or finding.get("description") or finding.get("summary") or "N/A"
        scanner = safe_dict(finding.get("source")).get("scanner") or "N/A"
        qid = get_first_present(finding, ["qid", "qidId", "plugin_id", "pluginId", "reference_id"]) or safe_dict(finding.get("raw_source_fields")).get("vulnerability_type_id") or "N/A"
        cvss = finding.get("cvss") or finding.get("score") or "N/A"
        if isinstance(cvss, dict):
            cvss = cvss.get("base") or cvss.get("effective") or cvss.get("cvss31") or cvss.get("cvss") or "N/A"
        trs = finding.get("trs")
        if trs is None and isinstance(finding.get("risk_drivers"), dict):
            trs = safe_dict(finding.get("risk_drivers")).get("trs")
        if trs is None:
            risk_drivers = finding.get("risk_drivers") or []
            if isinstance(risk_drivers, list):
                for item in risk_drivers:
                    if isinstance(item, dict):
                        evidence = item.get("evidence") or {}
                        if evidence.get("trs") is not None:
                            trs = evidence.get("trs")
                            break
        epss = finding.get("epss")
        status = finding.get("status") or "N/A"
        first_seen = finding.get("first_seen")
        last_seen = finding.get("last_seen")
        recommendation = finding.get("recommendation") or "N/A"

        lines += [
            "",
            "=" * 60,
            str(finding_id),
            "=" * 60,
            "",
            f"Finding ID : {finding_id}",
            f"CVE        : {join_values(cves)}",
            f"Title      : {title[:220]}{'...' if len(title) > 220 else ''}",
            f"Scanner    : {scanner}",
            f"QID        : {qid}",
            "",
            "RISK",
            "----",
            f"CVSS       : {cvss}",
            f"HyScore    : {trs if trs is not None else 'N/A'}",
            f"EPSS       : {epss if epss is not None else 'N/A'}",
            f"Status     : {status}",
            "",
            "DETECTION",
            "---------",
            f"First Seen : {first_seen or 'N/A'}",
            f"Last Seen  : {last_seen or 'N/A'}",
            "",
            "SUMMARY",
            "-------",
            f"Recommendation: {recommendation[:320]}{'...' if len(str(recommendation)) > 320 else ''}",
            "",
            "COMPONENT",
            "---------",
        ]

        component_rows = collect_component_rows(finding)
        install_paths, vulnerable_paths, registry_paths = collect_path_fields(finding)

        if component_rows:
            component = component_rows[0]
            lines += [
                f"Package          : {component.get('package') or 'N/A'}",
                f"Vendor           : {component.get('vendor') or 'N/A'}",
                f"Product          : {component.get('product') or 'N/A'}",
                f"Installed Version: {component.get('installed_version') or 'N/A'}",
                f"Required Version : {component.get('required_version') or 'N/A'}",
                f"Language         : {component.get('language') or 'N/A'}",
                "Install Path(s):",
            ]
            if install_paths:
                for path in install_paths[:10]:
                    lines.append(f"- {path}")
            else:
                lines.append("- N/A")

            lines.append("Vulnerable File Paths:")
            if vulnerable_paths:
                for path in vulnerable_paths[:10]:
                    lines.append(f"- {path}")
            else:
                lines.append("- N/A")

            lines.append("Registry Path(s):")
            if registry_paths:
                for path in registry_paths[:10]:
                    lines.append(f"- {path}")
            else:
                lines.append("- N/A")
        else:
            lines += [
                "Package          : N/A",
                "Vendor           : N/A",
                "Product          : N/A",
                "Installed Version: N/A",
                "Required Version : N/A",
                "Language         : N/A",
                "Install Path(s):",
                "- N/A",
                "Vulnerable File Paths:",
                "- N/A",
                "Registry Path(s):",
                "- N/A",
            ]

        lines += [
            "",
            "HISTORY",
            "-------",
        ]

        history_lines = extract_history_lines(finding, history_lookup)
        if not history_lines:
            lines.append("N/A")
        else:
            for line in history_lines[:4]:
                lines.append(line)

    if len(findings) > effective_limit:
        lines += [
            "",
            f"... {len(findings) - effective_limit} additional findings omitted for compact output.",
        ]

    lines += [
        "",
        "============================================================",
        "END",
        "============================================================",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Export a compact Hackuity summary for a given hostname.")
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=5, help="Maximum number of detailed findings to include in the text export.")
    args = parser.parse_args()

    root = args.root.resolve()
    report_path = find_report_context(args.hostname, root)
    if report_path is None:
        raise FileNotFoundError(f"No report context found for hostname '{args.hostname}' under {root / 'output' / 'intelligence' / 'report_context'}")

    context = json.loads(report_path.read_text(encoding="utf-8"))
    output_text = render_summary(context, report_path, limit=args.limit)

    if args.output is None:
        target = root / "output" / "inspection" / f"{args.hostname}_summary.txt"
    else:
        target = args.output
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(output_text, encoding="utf-8")
    print(f"Summary written to: {target.resolve()}")


if __name__ == "__main__":
    main()
