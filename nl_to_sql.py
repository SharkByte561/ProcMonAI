"""
Natural Language to SQL translation for Procmon CSV analysis.

Uses Claude to translate natural language questions into DuckDB SQL queries.
Dynamically discovers schema from CSV and provides sample data for context.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from anthropic import Anthropic


def get_csv_schema_and_sample(
    csv_file: str,
    sample_rows: int = 5,
) -> Tuple[List[str], List[Dict[str, str]], Dict[str, List[str]]]:
    """
    Get schema, sample rows, and unique values from CSV file.

    Args:
        csv_file: Path to CSV file.
        sample_rows: Number of sample rows to return.

    Returns:
        Tuple of (columns, sample_data, unique_values_by_column)
    """
    columns: List[str] = []
    samples: List[Dict[str, str]] = []
    unique_values: Dict[str, set] = {}

    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames or []

        # Initialize unique value sets for key columns
        key_columns = ["Operation", "Process Name", "Result", "Category", "Event Class"]
        for col in key_columns:
            if col in columns:
                unique_values[col] = set()

        # Read all rows for unique values, but keep only sample
        row_count = 0
        for row in reader:
            if row_count < sample_rows:
                samples.append(row)

            # Collect unique values for key columns (first 1000 rows)
            if row_count < 1000:
                for col in key_columns:
                    if col in row and row[col]:
                        unique_values[col].add(row[col])

            row_count += 1

    # Convert sets to sorted lists (top 20)
    unique_lists = {
        col: sorted(list(vals))[:20]
        for col, vals in unique_values.items()
    }

    return columns, samples, unique_lists


def build_schema_context(
    csv_file: str,
    columns: List[str],
    sample_data: List[Dict[str, str]],
    unique_values: Dict[str, List[str]],
) -> str:
    """Build the schema context string for Claude."""
    csv_path = str(Path(csv_file).resolve()).replace("\\", "/")

    context = f"""CSV FILE: '{csv_path}'

COLUMNS ({len(columns)} total):
{', '.join(f'"{col}"' for col in columns)}

KEY COLUMN VALUES:
"""
    for col, values in unique_values.items():
        context += f"  {col}: {', '.join(repr(v) for v in values[:15])}\n"

    context += "\nSAMPLE DATA:\n"
    for i, row in enumerate(sample_data[:3], 1):
        context += f"Row {i}: "
        # Show key columns only
        key_cols = ["Process Name", "Operation", "Path", "Result"]
        parts = [f'{col}={repr(row.get(col, "")[:50])}' for col in key_cols if col in row]
        context += ", ".join(parts) + "\n"

    return context


class NLToSQL:
    """Translates natural language questions to SQL queries for Procmon CSV."""

    def __init__(self, csv_file: str, model: Optional[str] = None):
        """
        Initialize with a CSV file.

        Args:
            csv_file: Path to Procmon CSV file.
            model: Claude model to use.
        """
        self.csv_file = csv_file
        self.csv_path = str(Path(csv_file).resolve()).replace("\\", "/")
        self.model = model or os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")
        self.client = Anthropic()

        # Load schema once
        self.columns, self.samples, self.unique_values = get_csv_schema_and_sample(csv_file)
        self.schema_context = build_schema_context(
            csv_file, self.columns, self.samples, self.unique_values
        )

        self.system_prompt = self._build_system_prompt()

    def _build_system_prompt(self) -> str:
        """Build the system prompt for SQL translation."""
        return f"""You are a SQL expert that translates natural language questions into DuckDB SQL queries for Procmon (Windows Process Monitor) data analysis.

{self.schema_context}

RULES:
1. ALWAYS use the exact CSV path: '{self.csv_path}'
2. Column names with spaces MUST be quoted: "Process Name", "Command Line", "Time of Day"
3. String comparisons are case-sensitive. Use ILIKE for case-insensitive matching.
4. Use LIMIT to restrict results (default 100, but use 500+ for "all files" or comprehensive queries).
5. For pattern matching, use ILIKE with % wildcards.
6. When searching for a program name, also check for installer names (e.g., "CCleaner" -> also check "ccsetup", "ccleaner")

COMMON PROCMON PATTERNS:
- Files CREATED: To find files a process created, look for DISTINCT Paths where Operation = 'CreateFile' AND Result = 'SUCCESS' AND Detail LIKE '%OpenResult: Created%'
- Files WRITTEN: Operation = 'WriteFile' shows data being written to files
- Registry persistence: Path contains 'Run', 'RunOnce', 'Services'
- Process creation: Operation = 'Process Create'
- Executable locations: Path ILIKE '%Program Files%' OR Path ILIKE '%.exe'
- Network: Path contains 'TCP' or 'UDP'
- DLL loading: Operation = 'Load Image'

RESPOND WITH ONLY THE SQL QUERY. No explanation, no markdown, just the raw SQL.
If the question cannot be answered with the available data, respond with: ERROR: <reason>"""

    def translate(self, question: str) -> str:
        """
        Translate a natural language question to SQL.

        Args:
            question: Natural language question about the Procmon data.

        Returns:
            SQL query string (or error message starting with "ERROR:").
        """
        response = self.client.messages.create(
            model=self.model,
            max_tokens=500,
            system=self.system_prompt,
            messages=[{"role": "user", "content": question}],
        )

        sql = response.content[0].text.strip()

        # Clean up any markdown formatting that might have slipped through
        if sql.startswith("```"):
            lines = sql.split("\n")
            sql = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        return sql

    def translate_with_explanation(self, question: str) -> Tuple[str, str]:
        """
        Translate question to SQL and provide explanation.

        Returns:
            Tuple of (sql_query, explanation).
        """
        prompt = f"""Question: {question}

First, provide the SQL query, then explain what it does.

Format:
SQL:
<your sql query>

EXPLANATION:
<brief explanation>"""

        response = self.client.messages.create(
            model=self.model,
            max_tokens=800,
            system=self.system_prompt.replace(
                "RESPOND WITH ONLY THE SQL QUERY",
                "Provide both SQL and a brief explanation"
            ),
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text.strip()

        # Parse SQL and explanation
        sql = ""
        explanation = ""

        if "SQL:" in text and "EXPLANATION:" in text:
            parts = text.split("EXPLANATION:")
            sql_part = parts[0].replace("SQL:", "").strip()
            explanation = parts[1].strip() if len(parts) > 1 else ""

            # Clean SQL
            sql = sql_part.strip()
            if sql.startswith("```"):
                lines = sql.split("\n")
                sql = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])
        else:
            sql = text
            explanation = "No explanation provided."

        return sql.strip(), explanation


def interactive_translate(csv_file: str):
    """Interactive session for testing NL to SQL translation."""
    print(f"\n{'=' * 60}")
    print("NL to SQL - Procmon Query Translator")
    print(f"{'=' * 60}")

    translator = NLToSQL(csv_file)

    print(f"Loaded: {csv_file}")
    print(f"Columns: {len(translator.columns)}")
    print(f"\nSample Operations: {', '.join(translator.unique_values.get('Operation', [])[:10])}")
    print(f"\nType a question to get SQL. Type 'quit' to exit.")
    print(f"{'=' * 60}\n")

    while True:
        try:
            question = input("Question: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[Goodbye]")
            break

        if not question:
            continue
        if question.lower() in ('quit', 'exit', 'q'):
            print("[Goodbye]")
            break

        sql = translator.translate(question)
        print(f"\nSQL:\n{sql}\n")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python nl_to_sql.py <csv_file> [question]")
        print("\nExamples:")
        print("  python nl_to_sql.py capture.csv")
        print('  python nl_to_sql.py capture.csv "What registry keys were modified?"')
        sys.exit(1)

    csv_file = sys.argv[1]

    if len(sys.argv) > 2:
        # Single question mode
        question = " ".join(sys.argv[2:])
        translator = NLToSQL(csv_file)
        sql = translator.translate(question)
        print(sql)
    else:
        # Interactive mode
        interactive_translate(csv_file)
