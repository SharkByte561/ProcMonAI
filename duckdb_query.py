"""
DuckDB query execution via PSDuckDB PowerShell module.

Executes SQL queries against CSV files using DuckDB's powerful
analytical SQL engine. Supports direct CSV file references in FROM clauses.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any


# Path to the PSDuckDB module
# Check worktree first, then fall back to main repo
_local_psduckdb = Path(__file__).parent / "PSDuckDB" / "PSDuckDB.psd1"
_main_psduckdb = Path("X:/ProcmonAI/PSDuckDB/PSDuckDB.psd1")

if _local_psduckdb.exists():
    PSDUCKDB_MODULE = _local_psduckdb
elif _main_psduckdb.exists():
    PSDUCKDB_MODULE = _main_psduckdb
else:
    raise RuntimeError("PSDuckDB module not found. Install it or update PSDUCKDB_MODULE path.")


def run_sql(
    query: str,
    csv_file: Optional[str] = None,
    timeout: int = 30,
) -> List[Dict[str, Any]]:
    """
    Execute a SQL query using PSDuckDB.

    Args:
        query: SQL query to execute. Use '{csv}' as placeholder for csv_file path.
        csv_file: Optional CSV file path to substitute for {csv} in query.
        timeout: Timeout in seconds for the PowerShell process.

    Returns:
        List of row dicts from query results.

    Example:
        >>> rows = run_sql("SELECT * FROM '{csv}' LIMIT 10", csv_file="capture.csv")
        >>> rows = run_sql("SELECT count(*) as cnt FROM 'C:/data/events.csv'")
    """
    # Substitute CSV path if provided
    if csv_file and "{csv}" in query:
        # Convert to forward slashes for DuckDB compatibility
        csv_path = str(Path(csv_file).resolve()).replace("\\", "/")
        query = query.replace("{csv}", csv_path)

    # Build PowerShell command
    ps_script = f"""
Import-Module '{PSDUCKDB_MODULE}' -Force
$result = psduckdb -command @"
{query}
"@
$result | ConvertTo-Json -Depth 10
"""

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"DuckDB query failed: {error_msg}")

        # Parse JSON output
        output = result.stdout.strip()
        if not output:
            return []

        try:
            data = json.loads(output)
            # Ensure it's always a list
            if isinstance(data, dict):
                return [data]
            return data if data else []
        except json.JSONDecodeError:
            # Non-JSON output (possibly error message)
            raise RuntimeError(f"Invalid query output: {output[:500]}")

    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Query timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError("PowerShell not found. Ensure PowerShell is installed.")


def get_csv_schema(csv_file: str) -> List[Dict[str, str]]:
    """
    Get the schema (column names and types) of a CSV file.

    Args:
        csv_file: Path to CSV file.

    Returns:
        List of dicts with 'column_name' and 'column_type' keys.
    """
    csv_path = str(Path(csv_file).resolve()).replace("\\", "/")
    query = f"DESCRIBE SELECT * FROM '{csv_path}'"

    try:
        return run_sql(query)
    except RuntimeError:
        # Fallback: just get column names from first row
        query = f"SELECT * FROM '{csv_path}' LIMIT 0"
        return run_sql(query)


def get_csv_row_count(csv_file: str) -> int:
    """Get total number of rows in a CSV file."""
    csv_path = str(Path(csv_file).resolve()).replace("\\", "/")
    query = f"SELECT count(*) as row_count FROM '{csv_path}'"
    result = run_sql(query)
    if result:
        return int(result[0].get("row_count", 0))
    return 0


def get_unique_values(csv_file: str, column: str, limit: int = 20) -> List[str]:
    """Get unique values from a column."""
    csv_path = str(Path(csv_file).resolve()).replace("\\", "/")
    query = f"""
SELECT DISTINCT "{column}" as val
FROM '{csv_path}'
WHERE "{column}" IS NOT NULL AND "{column}" != ''
LIMIT {limit}
"""
    result = run_sql(query)
    return [str(row.get("val", "")) for row in result if row.get("val")]


def query_procmon_csv(
    csv_file: str,
    select: str = "*",
    where: Optional[str] = None,
    order_by: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """
    Query a Procmon CSV file with common options.

    Args:
        csv_file: Path to Procmon CSV file.
        select: Columns to select (default: all).
        where: WHERE clause conditions (without 'WHERE' keyword).
        order_by: ORDER BY clause (without 'ORDER BY' keyword).
        limit: Maximum rows to return.

    Returns:
        List of matching row dicts.

    Example:
        >>> rows = query_procmon_csv(
        ...     "capture.csv",
        ...     select='"Process Name", Operation, Path',
        ...     where="Operation = 'RegSetValue'",
        ...     limit=50
        ... )
    """
    csv_path = str(Path(csv_file).resolve()).replace("\\", "/")

    query_parts = [f"SELECT {select}", f"FROM '{csv_path}'"]

    if where:
        query_parts.append(f"WHERE {where}")
    if order_by:
        query_parts.append(f"ORDER BY {order_by}")
    if limit:
        query_parts.append(f"LIMIT {limit}")

    query = "\n".join(query_parts)
    return run_sql(query)


# Common Procmon query helpers
def find_registry_modifications(csv_file: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Find registry modification events."""
    return query_procmon_csv(
        csv_file,
        select='"Process Name", Operation, Path, Detail, Result',
        where="Operation IN ('RegSetValue', 'RegCreateKey', 'RegDeleteKey', 'RegDeleteValue')",
        limit=limit,
    )


def find_file_writes(csv_file: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Find file write events."""
    return query_procmon_csv(
        csv_file,
        select='"Process Name", Operation, Path, Result',
        where="Operation IN ('WriteFile', 'CreateFile') AND Result = 'SUCCESS'",
        limit=limit,
    )


def find_process_creation(csv_file: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Find process creation events."""
    return query_procmon_csv(
        csv_file,
        select='"Process Name", Path, "Command Line", "Parent PID"',
        where="Operation = 'Process Create'",
        limit=limit,
    )


def find_network_activity(csv_file: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Find network-related events."""
    return query_procmon_csv(
        csv_file,
        select='"Process Name", Operation, Path, Result',
        where="Path LIKE '%TCP%' OR Path LIKE '%UDP%'",
        limit=limit,
    )


def search_path(csv_file: str, pattern: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Search for events with path containing pattern."""
    # Escape single quotes in pattern
    safe_pattern = pattern.replace("'", "''")
    return query_procmon_csv(
        csv_file,
        select='"Process Name", Operation, Path, Result, Detail',
        where=f"Path ILIKE '%{safe_pattern}%'",
        limit=limit,
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python duckdb_query.py <csv_file> <sql_query>")
        print("\nExample:")
        print('  python duckdb_query.py capture.csv "SELECT count(*) FROM \'{csv}\'"')
        print('  python duckdb_query.py capture.csv "SELECT * FROM \'{csv}\' LIMIT 5"')
        sys.exit(1)

    csv_file = sys.argv[1]
    query = sys.argv[2]

    try:
        results = run_sql(query, csv_file=csv_file)
        for row in results:
            print(row)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
