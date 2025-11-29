"""
PML to CSV converter using procmon-parser.

Converts Procmon PML binary captures to CSV format identical to
Procmon's native "Save As CSV" export. This allows:
- Standard tool analysis (grep, pandas, Excel)
- Targeted AI queries on specific rows
- Archival in portable text format
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Optional

from procmon_parser import ProcmonLogsReader
from procmon_parser.consts import ColumnToOriginalName, Column


# CSV columns in Procmon's default export order
CSV_COLUMNS = [
    "Time of Day",
    "Process Name",
    "PID",
    "Operation",
    "Path",
    "Result",
    "Detail",
    "Command Line",
    "User",
    "Image Path",
    "Parent PID",
    "Architecture",
    "Integrity",
    "Category",
    "Event Class",
    "TID",
    "Duration",
    "Date & Time",
    "Relative Time",
    "Completion Time",
    "Session",
    "Company",
    "Description",
    "Version",
    "Authentication ID",
    "Virtualized",
    "Sequence",
]


def convert_pml_to_csv(
    pml_file: str,
    output_file: Optional[str] = None,
    process_filter: Optional[str] = None,
    limit: Optional[int] = None,
    columns: Optional[list] = None,
) -> str:
    """
    Convert PML file to CSV format.

    Args:
        pml_file: Path to .pml file
        output_file: Output CSV path (default: same name with .csv extension)
        process_filter: Optional process name filter (case-insensitive substring)
        limit: Maximum number of events to export
        columns: List of column names to include (default: all)

    Returns:
        Path to the generated CSV file
    """
    pml_path = Path(pml_file)
    if not pml_path.exists():
        raise FileNotFoundError(f"PML file not found: {pml_file}")

    # Default output path
    if output_file is None:
        output_file = str(pml_path.with_suffix('.csv'))

    # Columns to export
    export_columns = columns if columns else CSV_COLUMNS

    print(f"[pml_to_csv] Reading: {pml_file}")

    first_event_time = None
    event_count = 0
    filtered_count = 0

    with open(pml_path, 'rb') as f:
        reader = ProcmonLogsReader(f)
        total_events = len(reader)

        print(f"[pml_to_csv] Total events in PML: {total_events}")

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=export_columns, extrasaction='ignore')
            writer.writeheader()

            for event in reader:
                # Get first event time for relative time calculation
                if first_event_time is None:
                    first_event_time = event.date_filetime

                # Apply process filter
                if process_filter:
                    proc_name = ""
                    if hasattr(event, 'process') and event.process:
                        if hasattr(event.process, 'process_name'):
                            proc_name = event.process.process_name or ""
                        else:
                            proc_name = str(event.process)

                    if process_filter.lower() not in proc_name.lower():
                        continue

                filtered_count += 1

                # Get CSV-compatible row data
                try:
                    row = event.get_compatible_csv_info(first_event_time)
                    writer.writerow(row)
                    event_count += 1
                except Exception as e:
                    # Skip malformed events
                    print(f"[pml_to_csv] Warning: Skipped event - {e}")
                    continue

                # Check limit
                if limit and event_count >= limit:
                    print(f"[pml_to_csv] Reached limit of {limit} events")
                    break

    print(f"[pml_to_csv] Exported {event_count} events to: {output_file}")
    if process_filter:
        print(f"[pml_to_csv] (Filtered from {total_events} total, {filtered_count} matched filter)")

    return output_file


def get_csv_stats(csv_file: str) -> dict:
    """
    Get basic statistics from a CSV file.

    Returns:
        Dict with row count, column names, and sample data
    """
    csv_path = Path(csv_file)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_file}")

    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames or []

        rows = list(reader)
        total_rows = len(rows)

        # Count by operation
        op_counts = {}
        for row in rows:
            op = row.get('Operation', 'Unknown')
            op_counts[op] = op_counts.get(op, 0) + 1

        # Top operations
        top_ops = sorted(op_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # Count by process
        proc_counts = {}
        for row in rows:
            proc = row.get('Process Name', 'Unknown')
            proc_counts[proc] = proc_counts.get(proc, 0) + 1

        top_procs = sorted(proc_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "file": str(csv_path),
        "total_rows": total_rows,
        "columns": columns,
        "top_operations": top_ops,
        "top_processes": top_procs,
    }


def filter_csv_rows(
    csv_file: str,
    operation: Optional[str] = None,
    path_contains: Optional[str] = None,
    process_name: Optional[str] = None,
    result: Optional[str] = None,
    limit: int = 100,
) -> list:
    """
    Filter CSV rows by various criteria.

    Args:
        csv_file: Path to CSV file
        operation: Filter by operation (e.g., "RegSetValue", "WriteFile")
        path_contains: Filter by path substring (case-insensitive)
        process_name: Filter by process name (case-insensitive)
        result: Filter by result (e.g., "SUCCESS", "NAME NOT FOUND")
        limit: Maximum rows to return

    Returns:
        List of matching row dicts
    """
    csv_path = Path(csv_file)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_file}")

    matches = []

    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            # Apply filters
            if operation and row.get('Operation', '') != operation:
                continue
            if path_contains and path_contains.lower() not in row.get('Path', '').lower():
                continue
            if process_name and process_name.lower() not in row.get('Process Name', '').lower():
                continue
            if result and result.upper() not in row.get('Result', '').upper():
                continue

            matches.append(row)

            if len(matches) >= limit:
                break

    return matches


def format_rows_for_ai(rows: list, columns: Optional[list] = None, max_rows: int = 150) -> str:
    """
    Format CSV rows for AI analysis.

    Args:
        rows: List of row dicts
        columns: Columns to include (default: essential columns)
        max_rows: Maximum rows to format

    Returns:
        Compact text format for AI consumption
    """
    if columns is None:
        columns = ["Process Name", "Operation", "Path", "Result", "Detail"]

    lines = []
    for row in rows[:max_rows]:
        parts = []
        for col in columns:
            val = row.get(col, '')
            if val:
                # Truncate long values
                if len(str(val)) > 80:
                    val = str(val)[:77] + "..."
                parts.append(str(val))
        lines.append(" | ".join(parts))

    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pml_to_csv.py <pml_file> [output_csv] [process_filter]")
        print("\nExample:")
        print("  python pml_to_csv.py capture.pml")
        print("  python pml_to_csv.py capture.pml output.csv")
        print("  python pml_to_csv.py capture.pml output.csv ccsetup")
        sys.exit(1)

    pml_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    process_filter = sys.argv[3] if len(sys.argv) > 3 else None

    csv_path = convert_pml_to_csv(pml_file, output_file, process_filter)

    # Show stats
    print("\n" + "=" * 60)
    stats = get_csv_stats(csv_path)
    print(f"CSV Statistics:")
    print(f"  Total Rows: {stats['total_rows']}")
    print(f"\nTop Operations:")
    for op, count in stats['top_operations'][:5]:
        print(f"  {op}: {count}")
    print(f"\nTop Processes:")
    for proc, count in stats['top_processes'][:5]:
        print(f"  {proc}: {count}")
