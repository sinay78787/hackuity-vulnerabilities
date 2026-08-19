"""Export autonome de Parquet vers Excel, sans modifier le pipeline."""
from __future__ import annotations

import argparse
import json
import math
import re
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable

import pyarrow.parquet as pq

try:
    import xlsxwriter
except ImportError as exc:
    raise SystemExit("Installez la dépendance : python -m pip install -r tools/requirements-excel.txt") from exc

MAX_ROWS = 1_048_576
MAX_COLUMNS = 16_384
MAX_TEXT = 32_767
INVALID_SHEET = re.compile(r"[\[\]:*?/\\\\]")

def excel_value(value: Any) -> Any:
    if value is None or isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    if isinstance(value, (bool, int, float, datetime, date)):
        return value
    if isinstance(value, (dict, list, tuple, set)):
        value = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
    else:
        value = str(value)
    if value.startswith(("=", "+", "-", "@")):
        value = "'" + value
    return value[:MAX_TEXT]

def discover(inputs: Iterable[str]) -> list[Path]:
    found: dict[str, Path] = {}
    for raw in inputs:
        path = Path(raw)
        candidates = sorted(path.glob("*.parquet")) if path.is_dir() else [path]
        for candidate in candidates:
            if not candidate.is_file() or candidate.suffix.lower() != ".parquet":
                raise SystemExit(f"Entrée Parquet introuvable : {candidate}")
            found[str(candidate.resolve()).lower()] = candidate
    if not found:
        raise SystemExit("Aucun fichier Parquet trouvé.")
    return list(found.values())

def unique_sheet_name(base: str, part: int, used: set[str]) -> str:
    clean = INVALID_SHEET.sub("_", base).strip("' ") or "Table"
    suffix = f"_{part}" if part > 1 else ""
    candidate = clean[:31-len(suffix)] + suffix
    counter = 2
    while candidate.lower() in used:
        suffix = f"_{counter}"
        candidate = clean[:31-len(suffix)] + suffix
        counter += 1
    used.add(candidate.lower())
    return candidate

def add_sheet(workbook: Any, name: str, columns: list[str], header: Any) -> Any:
    sheet = workbook.add_worksheet(name)
    sheet.freeze_panes(1, 0)
    sheet.hide_gridlines(2)
    sheet.set_row(0, 24)
    for index, column in enumerate(columns):
        sheet.write_string(0, index, column, header)
        sheet.set_column(index, index, min(45, max(12, len(column) + 2)))
    return sheet

def export_parquet(workbook: Any, path: Path, batch_size: int, used: set[str], header: Any, date_fmt: Any) -> tuple[int, list[str]]:
    parquet = pq.ParquetFile(path)
    columns = parquet.schema_arrow.names
    if len(columns) > MAX_COLUMNS:
        raise ValueError(f"{path}: trop de colonnes pour Excel ({len(columns)})")
    part, excel_row, total = 1, 1, 0
    names = [unique_sheet_name(path.stem, part, used)]
    sheet = add_sheet(workbook, names[-1], columns, header)
    for batch in parquet.iter_batches(batch_size=batch_size):
        for row in batch.to_pylist():
            if excel_row >= MAX_ROWS:
                sheet.autofilter(0, 0, excel_row - 1, len(columns) - 1)
                part += 1
                names.append(unique_sheet_name(path.stem, part, used))
                sheet = add_sheet(workbook, names[-1], columns, header)
                excel_row = 1
            for column_index, column in enumerate(columns):
                value = excel_value(row.get(column))
                if value is None:
                    continue
                if isinstance(value, (datetime, date)):
                    sheet.write_datetime(excel_row, column_index, value, date_fmt)
                elif isinstance(value, bool):
                    sheet.write_boolean(excel_row, column_index, value)
                elif isinstance(value, (int, float)):
                    sheet.write_number(excel_row, column_index, value)
                else:
                    sheet.write_string(excel_row, column_index, value)
            excel_row += 1
            total += 1
    sheet.autofilter(0, 0, max(0, excel_row - 1), len(columns) - 1)
    return total, names

def main() -> None:
    parser = argparse.ArgumentParser(description="Exporte des Parquet vers un classeur Excel autonome.")
    parser.add_argument("inputs", nargs="*", default=["output/gold"], help="Fichiers ou dossiers Parquet")
    parser.add_argument("--output", default="exports/hackuity_gold.xlsx")
    parser.add_argument("--batch-size", type=int, default=10_000)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists() and not args.overwrite:
        raise SystemExit(f"Le fichier existe déjà : {output}. Utilisez --overwrite.")
    output.parent.mkdir(parents=True, exist_ok=True)
    files = discover(args.inputs)
    workbook = xlsxwriter.Workbook(output, {"constant_memory": True})
    header = workbook.add_format({"bold": True, "font_color": "#FFFFFF", "bg_color": "#4338CA", "valign": "vcenter"})
    date_fmt = workbook.add_format({"num_format": "yyyy-mm-dd hh:mm:ss"})
    index_sheet = workbook.add_worksheet("_INDEX")
    index_sheet.hide_gridlines(2)
    for column, label in enumerate(("Source Parquet", "Lignes", "Onglets", "Noms des onglets")):
        index_sheet.write_string(0, column, label, header)
    index_sheet.set_column(0, 0, 55)
    index_sheet.set_column(1, 2, 14)
    index_sheet.set_column(3, 3, 60)
    used = {"_index"}
    try:
        for index, path in enumerate(files, start=1):
            rows, names = export_parquet(workbook, path, args.batch_size, used, header, date_fmt)
            index_sheet.write_string(index, 0, str(path))
            index_sheet.write_number(index, 1, rows)
            index_sheet.write_number(index, 2, len(names))
            index_sheet.write_string(index, 3, ", ".join(names))
            print(f"{path} -> {rows:,} lignes, {len(names)} onglet(s)")
    finally:
        workbook.close()
    print(f"Classeur créé : {output.resolve()}")

if __name__ == "__main__":
    main()
