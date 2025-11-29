"""
SQL-based chat for Procmon CSV analysis.

Combines natural language to SQL translation with DuckDB query execution.
User asks questions in plain English → Claude generates SQL → DuckDB runs it.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, List, Dict, Any

from anthropic import Anthropic

from nl_to_sql import NLToSQL, get_csv_schema_and_sample, build_schema_context
from duckdb_query import run_sql, get_csv_row_count


class SQLChat:
    """Chat interface using SQL queries for precise Procmon analysis."""

    def __init__(self, csv_file: str, model: Optional[str] = None):
        """
        Initialize SQL-based chat.

        Args:
            csv_file: Path to Procmon CSV file.
            model: Claude model to use.
        """
        self.csv_file = csv_file
        self.csv_path = str(Path(csv_file).resolve()).replace("\\", "/")
        self.model = model or os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")
        self.client = Anthropic()

        # Initialize NL to SQL translator
        self.translator = NLToSQL(csv_file, model)

        # Get row count
        self.row_count = get_csv_row_count(csv_file)

        # Conversation history for analysis context
        self.history: List[Dict[str, str]] = []

        # Build analysis system prompt
        self.analysis_prompt = self._build_analysis_prompt()

    def _build_analysis_prompt(self) -> str:
        """Build system prompt for analyzing query results."""
        return f"""You are a security analyst examining Windows Process Monitor data.

CAPTURE INFO:
- File: {self.csv_path}
- Total Events: {self.row_count}

Available columns: {', '.join(f'"{c}"' for c in self.translator.columns)}

When analyzing query results:
1. Focus on security implications
2. Identify suspicious patterns (persistence, lateral movement, exfiltration)
3. Note any anomalies or red flags
4. Be concise but thorough
5. If results are empty, suggest what else to look for

Respond in a clear, professional manner."""

    def ask(self, question: str, show_sql: bool = True) -> str:
        """
        Ask a natural language question about the capture.

        Workflow:
        1. Translate question to SQL
        2. Execute SQL via DuckDB
        3. Have Claude analyze the results

        Args:
            question: Natural language question.
            show_sql: Whether to include the SQL in the response.

        Returns:
            Analysis of the query results.
        """
        # Step 1: Translate to SQL
        sql = self.translator.translate(question)

        if sql.startswith("ERROR:"):
            return sql

        # Step 2: Execute SQL
        try:
            results = run_sql(sql)
        except RuntimeError as e:
            return f"SQL Error: {e}\n\nGenerated SQL:\n{sql}"

        # Step 3: Analyze results with Claude
        if not results:
            result_text = "No matching events found."
        else:
            # Format results for analysis
            result_lines = []
            for i, row in enumerate(results[:50], 1):  # Limit display
                parts = [f"{k}={repr(str(v)[:60])}" for k, v in row.items() if v]
                result_lines.append(f"{i}. {', '.join(parts)}")
            result_text = "\n".join(result_lines)
            if len(results) > 50:
                result_text += f"\n... and {len(results) - 50} more rows"

        # Build analysis request
        user_message = f"""QUESTION: {question}

SQL QUERY:
{sql}

RESULTS ({len(results)} rows):
{result_text}

Please analyze these results and answer the original question."""

        # Add to history
        self.history.append({"role": "user", "content": user_message})

        # Keep history manageable
        if len(self.history) > 10:
            self.history = self.history[-10:]

        # Get analysis
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1500,
            system=self.analysis_prompt,
            messages=self.history,
        )

        analysis = response.content[0].text
        self.history.append({"role": "assistant", "content": analysis})

        # Format output
        if show_sql:
            return f"SQL: {sql}\n\nResults: {len(results)} rows\n\n{analysis}"
        return analysis

    def raw_sql(self, sql: str) -> List[Dict[str, Any]]:
        """Execute raw SQL and return results."""
        return run_sql(sql)

    def query(self, question: str) -> tuple:
        """
        Get SQL and results separately.

        Returns:
            Tuple of (sql_query, results_list)
        """
        sql = self.translator.translate(question)
        if sql.startswith("ERROR:"):
            return sql, []
        try:
            results = run_sql(sql)
            return sql, results
        except RuntimeError as e:
            return sql, [{"error": str(e)}]

    def clear(self):
        """Clear conversation history."""
        self.history = []


def interactive_sql_chat(csv_file: str):
    """Run interactive SQL-based chat session."""
    print(f"\n{'=' * 60}")
    print("SQL CHAT - Procmon Analysis with DuckDB")
    print(f"{'=' * 60}")

    chat = SQLChat(csv_file)

    print(f"Loaded: {csv_file}")
    print(f"Events: {chat.row_count}")
    print(f"\nCommands:")
    print("  Type a question - Claude translates to SQL and runs it")
    print("  'sql <query>'   - Run raw SQL directly")
    print("  'schema'        - Show CSV columns")
    print("  'sample'        - Show sample data")
    print("  'clear'         - Clear conversation history")
    print("  'quit'          - Exit")
    print(f"{'=' * 60}\n")

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[Goodbye]")
            break

        if not user_input:
            continue

        cmd = user_input.lower()

        if cmd in ('quit', 'exit', 'q'):
            print("[Goodbye]")
            break

        elif cmd == 'schema':
            print(f"\nColumns ({len(chat.translator.columns)}):")
            for col in chat.translator.columns:
                print(f"  - {col}")
            print()

        elif cmd == 'sample':
            print("\nSample data:")
            for i, row in enumerate(chat.translator.samples[:3], 1):
                print(f"\n--- Row {i} ---")
                for k, v in list(row.items())[:10]:
                    print(f"  {k}: {v[:60] if v else ''}")
            print()

        elif cmd == 'clear':
            chat.clear()
            print("[History cleared]\n")

        elif cmd.startswith('sql '):
            sql = user_input[4:].strip()
            try:
                results = chat.raw_sql(sql)
                print(f"\nResults ({len(results)} rows):")
                for row in results[:20]:
                    print(row)
                if len(results) > 20:
                    print(f"... and {len(results) - 20} more")
            except RuntimeError as e:
                print(f"\nError: {e}")
            print()

        else:
            print("\n" + chat.ask(user_input) + "\n")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python sql_chat.py <csv_file>")
        print("\nExample:")
        print("  python sql_chat.py capture.csv")
        sys.exit(1)

    csv_file = sys.argv[1]
    interactive_sql_chat(csv_file)
