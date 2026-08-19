from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import duckdb
import pyarrow.parquet as pq

KEY_ALIASES = {
    "hostname": ("hostname", "fqdn"),
    "asset_id": ("asset_id", "assetId"),
    "finding_id": ("finding_id", "findingId"),
    "cve": ("cve", "cveId", "cve_id", "cves"),
    "scanner": ("scanner", "provider", "providerId", "provider_id"),
    "first_seen": ("first_seen", "firstSeen"),
    "last_seen": ("last_seen", "lastSeen"),
    "installed_version": ("installed_version", "installedVersion", "detectedVersion"),
    "required_version": ("required_version", "requiredVersion", "expectedVersion", "targetVersion"),
    "install_path": ("install_path", "installPath", "path", "filePath"),
}


def quote(path: Path) -> str:
    return str(path.resolve()).replace("\\", "/").replace("'", "''")


def sql_name(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def display(value: Any, limit: int = 180) -> str:
    text = json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (list, dict)) else str(value)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def find_parquets(root: Path, include_tests: bool) -> list[Path]:
    paths = sorted(root.rglob("*.parquet"))
    if include_tests:
        return paths
    return [path for path in paths if "smoke" not in path.parts and "intelligence_multi_test" not in path.parts]


def matching_column(columns: list[str], aliases: tuple[str, ...]) -> str | None:
    lookup = {column.lower(): column for column in columns}
    return next((lookup[name.lower()] for name in aliases if name.lower() in lookup), None)


def inspect_file(con: duckdb.DuckDBPyConnection, path: Path, root: Path,
                 sample_size: int, null_threshold: float) -> dict[str, Any]:
    parquet = pq.ParquetFile(path)
    schema = parquet.schema_arrow
    columns = [field.name for field in schema]
    row_count = parquet.metadata.num_rows
    nulls: list[dict[str, Any]] = []
    if row_count:
        expressions = [f"sum(CASE WHEN {sql_name(column)} IS NULL THEN 1 ELSE 0 END)" for column in columns]
        counts = con.execute(f"SELECT {','.join(expressions)} FROM read_parquet('{quote(path)}')").fetchone()
        nulls = [{"column": column, "null_count": int(count or 0),
                  "null_pct": round(100 * int(count or 0) / row_count, 2)}
                 for column, count in zip(columns, counts)
                 if int(count or 0) / row_count >= null_threshold]
    samples = []
    if row_count and sample_size:
        cursor = con.execute(f"SELECT * FROM read_parquet('{quote(path)}') LIMIT {int(sample_size)}")
        names = [item[0] for item in cursor.description]
        samples = [dict(zip(names, row)) for row in cursor.fetchall()]
    useful = {key: matching_column(columns, aliases) for key, aliases in KEY_ALIASES.items()}
    return {"path": path.relative_to(root).as_posix(), "name": path.name,
            "rows": row_count, "columns_count": len(columns),
            "columns": [{"name": field.name, "type": str(field.type)} for field in schema],
            "useful_keys": {key: value for key, value in useful.items() if value},
            "high_null_columns": sorted(nulls, key=lambda row: (-row["null_pct"], row["column"])),
            "samples": samples}


def search(con: duckdb.DuckDBPyConnection, datasets: list[dict[str, Any]], root: Path,
           key: str, value: str, limit: int) -> list[dict[str, Any]]:
    results = []
    normalized_value = str(value).strip()
    for dataset in datasets:
        column = dataset["useful_keys"].get(key)
        if not column:
            continue
        path = root / dataset["path"]
        query = (
            f"SELECT * FROM read_parquet('{quote(path)}') "
            f"WHERE lower(trim(CAST({sql_name(column)} AS VARCHAR))) = lower(?) LIMIT {int(limit)}"
        )
        rows = con.execute(query, [normalized_value]).fetchall()
        names = [item[0] for item in con.description]
        if rows:
            results.append({"dataset": dataset["path"], "column": column,
                            "rows": [dict(zip(names, row)) for row in rows]})
    return results


def join_candidates(datasets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for dataset in datasets:
        for logical, physical in dataset["useful_keys"].items():
            by_key[logical].append((dataset["path"], physical))
    return [{"logical_key": key, "datasets": [{"path": path, "column": column} for path, column in tables]}
            for key, tables in sorted(by_key.items()) if len(tables) > 1]


def print_dataset(dataset: dict[str, Any]) -> None:
    print("\n" + "=" * 88)
    print(dataset["path"])
    print(f"Lignes: {dataset['rows']:,} | Colonnes: {dataset['columns_count']}")
    print("Schéma:")
    for column in dataset["columns"]:
        print(f"  - {column['name']}: {column['type']}")
    print("Clés utiles:", ", ".join(f"{key}={value}" for key, value in dataset["useful_keys"].items()) or "aucune")
    print("Colonnes très nulles:")
    if dataset["high_null_columns"]:
        for row in dataset["high_null_columns"]:
            print(f"  - {row['column']}: {row['null_count']:,}/{dataset['rows']:,} ({row['null_pct']:.2f} %)")
    else:
        print("  aucune au-dessus du seuil")
    print("Exemples:")
    for index, row in enumerate(dataset["samples"], 1):
        print(f"  [{index}] " + " | ".join(f"{key}={display(value)}" for key, value in row.items()))


def write_text_report(report: dict[str, Any], root: Path, selector: tuple[str, str] | None) -> None:
    if not selector:
        return
    key, value = selector
    if not value:
        return
    output_dir = root / "output" / "inspection"
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_value = value.replace("/", "_").replace("\\", "_")
    target = output_dir / f"{safe_value}.txt"
    search_results = report.get("searches", {}).get(key, [])
    lines = [
        "Hackuity Parquet inspection",
        f"root={report.get('root')}",
        f"selector={key}:{value}",
        f"file_count={report.get('file_count')}",
        "",
        f"Exact matches for {key}={value}",
        "=" * 80,
    ]
    if not search_results:
        lines.append("No exact match found.")
    else:
        for group in search_results:
            lines.append(f"Dataset: {group['dataset']}")
            lines.append(f"Column: {group['column']}")
            for row in group["rows"]:
                lines.append(json.dumps(row, ensure_ascii=False, indent=2, default=str))
            lines.append("")
    content = "\n".join(lines) + "\n"
    target.write_text(content, encoding="utf-8")
    print(f"\nRapport texte enregistré: {target.resolve()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspecte tous les Parquet Hackuity sans les modifier.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--dataset", help="Filtre sur le nom ou le chemin du dataset.")
    parser.add_argument("--hostname")
    parser.add_argument("--cve")
    parser.add_argument("--finding", "--finding-id", dest="finding")
    parser.add_argument("--sample-size", type=int, default=3)
    parser.add_argument("--search-limit", type=int, default=5)
    parser.add_argument("--null-threshold", type=float, default=0.8)
    parser.add_argument("--include-tests", action="store_true")
    parser.add_argument("--json", dest="json_output", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    paths = find_parquets(root, args.include_tests)
    if args.dataset:
        needle = args.dataset.lower()
        paths = [path for path in paths if needle in path.stem.lower() or needle in path.as_posix().lower()]
    con = duckdb.connect()
    datasets = [inspect_file(con, path, root, args.sample_size, args.null_threshold) for path in paths]
    searches = {}
    for key, value in (("hostname", args.hostname), ("cve", args.cve), ("finding_id", args.finding)):
        if value:
            searches[key] = search(con, datasets, root, key, value, args.search_limit)
    report = {"root": str(root), "file_count": len(datasets), "datasets": datasets,
              "searches": searches, "join_candidates": join_candidates(datasets)}
    chosen_selector = None
    for key, value in (("hostname", args.hostname), ("cve", args.cve), ("finding_id", args.finding)):
        if value:
            chosen_selector = (key, value)
            break

    if args.json_output:
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return

    write_text_report(report, root, chosen_selector)
    print(f"Parquet détectés: {len(datasets)}")
    for dataset in datasets:
        print_dataset(dataset)
    if searches:
        print("\n" + "=" * 88 + "\nRECHERCHES")
        for key, groups in searches.items():
            print(f"\n{key}: {len(groups)} dataset(s) avec résultats")
            for group in groups:
                print(f"  {group['dataset']} [{group['column']}]")
                for row in group["rows"]:
                    print("    " + " | ".join(f"{name}={display(value)}" for name, value in row.items()))
    print("\n" + "=" * 88 + "\nCLÉS DE JOINTURE POTENTIELLES")
    for candidate in report["join_candidates"]:
        datasets_text = ", ".join(f"{row['path']}::{row['column']}" for row in candidate["datasets"])
        print(f"  {candidate['logical_key']}: {datasets_text}")


if __name__ == "__main__":
    main()
