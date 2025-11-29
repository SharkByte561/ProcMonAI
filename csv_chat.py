"""
CSV-based chat with Claude for Procmon analysis.

Uses CSV files (converted from PML) for efficient querying and
targeted AI analysis. Sends only relevant rows to Claude.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path
from typing import Optional, List, Dict, Any

from anthropic import Anthropic

from pml_to_csv import filter_csv_rows, format_rows_for_ai, get_csv_stats


class CSVChat:
    """Chat with Claude about a Procmon CSV capture."""

    def __init__(self, csv_file: str, model: Optional[str] = None):
        """
        Initialize chat with a CSV file.

        Args:
            csv_file: Path to CSV file (exported from PML)
            model: Claude model to use (default: from env or claude-3-5-haiku-20241022)
        """
        self.csv_file = csv_file
        self.model = model or os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")
        self.client = Anthropic()
        self.history: List[Dict[str, str]] = []

        # Load CSV stats
        self.stats = get_csv_stats(csv_file)
        self.system_prompt = self._build_system_prompt()

    def _build_system_prompt(self) -> str:
        """Build system prompt with CSV context."""
        stats = self.stats

        prompt = f"""You are a security analyst examining Windows Process Monitor (Procmon) data.

CAPTURE OVERVIEW:
- File: {stats['file']}
- Total Events: {stats['total_rows']}

TOP OPERATIONS:
{chr(10).join(f"  {op}: {count}" for op, count in stats['top_operations'][:8])}

TOP PROCESSES:
{chr(10).join(f"  {proc}: {count}" for proc, count in stats['top_processes'][:8])}

When analyzing events:
1. Focus on security-relevant patterns (persistence, lateral movement, data exfiltration)
2. Identify suspicious registry keys (Run, RunOnce, Services, etc.)
3. Flag unusual file operations (executables in temp, writes to system folders)
4. Note process creation chains that may indicate malware
5. Be concise but thorough in your analysis

The user will provide specific event data to analyze. Focus on what the data shows."""

        return prompt

    def query(
        self,
        question: str,
        operation: Optional[str] = None,
        path_contains: Optional[str] = None,
        process_name: Optional[str] = None,
        result: Optional[str] = None,
        limit: int = 150,
    ) -> str:
        """
        Ask a question with filtered event context.

        Args:
            question: The question to ask
            operation: Filter by operation type
            path_contains: Filter by path substring
            process_name: Filter by process name
            result: Filter by result
            limit: Max events to include

        Returns:
            Claude's response
        """
        # Get filtered rows
        rows = filter_csv_rows(
            self.csv_file,
            operation=operation,
            path_contains=path_contains,
            process_name=process_name,
            result=result,
            limit=limit,
        )

        if not rows:
            return f"No events found matching the filter criteria."

        # Format for AI
        events_text = format_rows_for_ai(rows, max_rows=limit)

        # Build message with context
        user_message = f"""EVENTS ({len(rows)} rows):
{events_text}

QUESTION: {question}"""

        # Add to history
        self.history.append({"role": "user", "content": user_message})

        # Keep history manageable (last 6 exchanges)
        if len(self.history) > 12:
            self.history = self.history[-12:]

        # Call Claude
        response = self.client.messages.create(
            model=self.model,
            max_tokens=2000,
            system=self.system_prompt,
            messages=self.history,
        )

        assistant_message = response.content[0].text

        # Add response to history
        self.history.append({"role": "assistant", "content": assistant_message})

        return assistant_message

    def analyze_registry(self, question: Optional[str] = None) -> str:
        """Analyze registry operations."""
        question = question or "What registry changes were made? Are there any persistence mechanisms?"

        # Get registry operations
        rows = []
        for op in ["RegSetValue", "RegCreateKey", "RegDeleteKey", "RegDeleteValue"]:
            rows.extend(filter_csv_rows(self.csv_file, operation=op, limit=50))

        if not rows:
            return "No registry modification events found."

        events_text = format_rows_for_ai(rows[:150])

        return self.query(question, limit=0)  # We already have events

    def analyze_files(self, question: Optional[str] = None) -> str:
        """Analyze file operations."""
        question = question or "What files were created or modified? Any executables written?"

        rows = []
        for op in ["CreateFile", "WriteFile", "SetDispositionInformationFile"]:
            rows.extend(filter_csv_rows(self.csv_file, operation=op, result="SUCCESS", limit=50))

        if not rows:
            return "No file write events found."

        events_text = format_rows_for_ai(rows[:150])

        user_message = f"""FILE EVENTS ({len(rows)} rows):
{events_text}

QUESTION: {question}"""

        self.history.append({"role": "user", "content": user_message})

        response = self.client.messages.create(
            model=self.model,
            max_tokens=2000,
            system=self.system_prompt,
            messages=self.history,
        )

        result = response.content[0].text
        self.history.append({"role": "assistant", "content": result})
        return result

    def analyze_network(self, question: Optional[str] = None) -> str:
        """Analyze network operations."""
        question = question or "What network connections were made? Any suspicious destinations?"

        # Network events have TCP/UDP in operation
        rows = filter_csv_rows(self.csv_file, path_contains="TCP", limit=75)
        rows.extend(filter_csv_rows(self.csv_file, path_contains="UDP", limit=75))

        if not rows:
            return "No network events found."

        events_text = format_rows_for_ai(rows[:150])

        user_message = f"""NETWORK EVENTS ({len(rows)} rows):
{events_text}

QUESTION: {question}"""

        self.history.append({"role": "user", "content": user_message})

        response = self.client.messages.create(
            model=self.model,
            max_tokens=2000,
            system=self.system_prompt,
            messages=self.history,
        )

        result = response.content[0].text
        self.history.append({"role": "assistant", "content": result})
        return result

    def analyze_processes(self, question: Optional[str] = None) -> str:
        """Analyze process creation."""
        question = question or "What processes were created? Show the process tree and any suspicious spawns."

        rows = filter_csv_rows(self.csv_file, operation="Process Create", limit=150)

        if not rows:
            return "No process creation events found."

        # Include command line for process analysis
        events_text = format_rows_for_ai(
            rows,
            columns=["Process Name", "Operation", "Path", "Detail", "Command Line"],
            max_rows=150
        )

        user_message = f"""PROCESS CREATION EVENTS ({len(rows)} rows):
{events_text}

QUESTION: {question}"""

        self.history.append({"role": "user", "content": user_message})

        response = self.client.messages.create(
            model=self.model,
            max_tokens=2000,
            system=self.system_prompt,
            messages=self.history,
        )

        result = response.content[0].text
        self.history.append({"role": "assistant", "content": result})
        return result

    def search(self, path_pattern: str, question: Optional[str] = None) -> str:
        """Search for events matching a path pattern."""
        question = question or f"What activity involved '{path_pattern}'?"

        rows = filter_csv_rows(self.csv_file, path_contains=path_pattern, limit=150)

        if not rows:
            return f"No events found with path containing '{path_pattern}'."

        events_text = format_rows_for_ai(rows)

        user_message = f"""SEARCH RESULTS for '{path_pattern}' ({len(rows)} rows):
{events_text}

QUESTION: {question}"""

        self.history.append({"role": "user", "content": user_message})

        response = self.client.messages.create(
            model=self.model,
            max_tokens=2000,
            system=self.system_prompt,
            messages=self.history,
        )

        result = response.content[0].text
        self.history.append({"role": "assistant", "content": result})
        return result

    def ask(self, question: str) -> str:
        """
        Ask a general question. Auto-detects relevant events from keywords.
        """
        q_lower = question.lower()

        # Auto-detect category from question
        if any(x in q_lower for x in ['registry', 'reg', 'hkey', 'run key', 'persistence']):
            return self.query(
                question,
                path_contains="HKEY" if "hkey" in q_lower else None,
                limit=150
            )
        elif any(x in q_lower for x in ['file', 'write', 'create', 'executable', '.exe', '.dll']):
            return self.analyze_files(question)
        elif any(x in q_lower for x in ['network', 'tcp', 'udp', 'connection', 'ip', 'port']):
            return self.analyze_network(question)
        elif any(x in q_lower for x in ['process', 'spawn', 'execute', 'command line', 'child']):
            return self.analyze_processes(question)
        elif any(x in q_lower for x in ['task', 'schedule', 'schtask']):
            return self.search("Task", question)
        else:
            # General query - send sample of all event types
            rows = filter_csv_rows(self.csv_file, limit=100)
            events_text = format_rows_for_ai(rows)

            user_message = f"""SAMPLE EVENTS ({len(rows)} rows):
{events_text}

QUESTION: {question}"""

            self.history.append({"role": "user", "content": user_message})

            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=self.system_prompt,
                messages=self.history,
            )

            result = response.content[0].text
            self.history.append({"role": "assistant", "content": result})
            return result

    def clear(self):
        """Clear conversation history."""
        self.history = []


def interactive_chat(csv_file: str):
    """Run interactive chat session."""
    print(f"\n{'=' * 60}")
    print("CSV CHAT - Procmon Analysis")
    print(f"{'=' * 60}")

    chat = CSVChat(csv_file)

    print(f"Loaded: {csv_file}")
    print(f"Events: {chat.stats['total_rows']}")
    print(f"\nCommands:")
    print("  Type a question to ask Claude")
    print("  'registry' - Analyze registry changes")
    print("  'files'    - Analyze file operations")
    print("  'network'  - Analyze network activity")
    print("  'processes'- Analyze process creation")
    print("  'search <pattern>' - Search for path pattern")
    print("  'stats'    - Show CSV statistics")
    print("  'clear'    - Clear conversation history")
    print("  'quit'     - Exit")
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
        elif cmd == 'registry':
            print("\nClaude:", chat.analyze_registry())
        elif cmd == 'files':
            print("\nClaude:", chat.analyze_files())
        elif cmd == 'network':
            print("\nClaude:", chat.analyze_network())
        elif cmd == 'processes':
            print("\nClaude:", chat.analyze_processes())
        elif cmd.startswith('search '):
            pattern = user_input[7:].strip()
            print(f"\nClaude:", chat.search(pattern))
        elif cmd == 'stats':
            print(f"\nTotal Events: {chat.stats['total_rows']}")
            print("Top Operations:")
            for op, count in chat.stats['top_operations'][:5]:
                print(f"  {op}: {count}")
            print("Top Processes:")
            for proc, count in chat.stats['top_processes'][:5]:
                print(f"  {proc}: {count}")
        elif cmd == 'clear':
            chat.clear()
            print("[History cleared]")
        else:
            print("\nClaude:", chat.ask(user_input))

        print()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python csv_chat.py <csv_file>")
        print("\nExample:")
        print("  python csv_chat.py capture.csv")
        sys.exit(1)

    csv_file = sys.argv[1]
    interactive_chat(csv_file)
