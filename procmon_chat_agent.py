"""
Interactive ProcmonAI agent with CSV-first analysis.

New approach:
1. Convert PML to CSV (portable, searchable)
2. Generate local summary (no AI, instant)
3. Chat with AI using filtered CSV rows
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from procmon_filters import write_pmc_for_scenario
from procmon_report import generate_excel_report
from procmon_runner import (
    ProcmonError,
    get_timestamped_pml_path,
    start_procmon,
    stop_procmon,
)
from pml_to_csv import convert_pml_to_csv, get_csv_stats

# Try to import chat modules
try:
    from csv_chat import CSVChat, interactive_chat
    CSV_CHAT_AVAILABLE = True
except ImportError:
    CSVChat = None  # type: ignore
    interactive_chat = None  # type: ignore
    CSV_CHAT_AVAILABLE = False

# Legacy chat for backwards compatibility
try:
    from ai_chat import ProcmonChat
    LEGACY_CHAT_AVAILABLE = True
except ImportError:
    ProcmonChat = None  # type: ignore
    LEGACY_CHAT_AVAILABLE = False


def _prompt(text: str) -> str:
    return input(text).strip()


def print_csv_summary(csv_file: str) -> None:
    """Print summary of CSV file."""
    stats = get_csv_stats(csv_file)

    print("\n" + "=" * 70)
    print("CAPTURE SUMMARY")
    print("=" * 70)
    print(f"CSV File: {stats['file']}")
    print(f"Total Events: {stats['total_rows']}")

    print("\n--- Top Operations ---")
    for op, count in stats['top_operations'][:8]:
        print(f"  {op}: {count}")

    print("\n--- Top Processes ---")
    for proc, count in stats['top_processes'][:8]:
        print(f"  {proc}: {count}")

    print("=" * 70)


def interactive_loop() -> None:
    """Main interactive loop with CSV-first approach."""
    print("=" * 70)
    print(" ProcmonAI - CSV-First Analysis")
    print("=" * 70)
    print("Commands:")
    print("  start   - Start a new Procmon capture")
    print("  stop    - Stop a running manual capture")
    print("  convert - Convert PML to CSV (also shows summary)")
    print("  chat    - Chat with AI about the CSV")
    print("  report  - Generate Excel report")
    print("  load    - Load an existing CSV or PML file")
    print("  quit    - Exit")
    print("=" * 70)

    if not CSV_CHAT_AVAILABLE:
        print("\n[WARNING] AI chat not available. Check ANTHROPIC_API_KEY.")

    last_pml: Optional[Path] = None
    last_csv: Optional[Path] = None
    last_scenario: str = "capture"
    last_target_process: Optional[str] = None

    while True:
        cmd = _prompt("\n[agent] Command: ").lower()

        if cmd in ("quit", "exit", "q"):
            print("Goodbye.")
            return

        elif cmd == "start":
            print("Choose scenario:")
            print("  malware            - File writes, registry persistence, network, process creation")
            print("  software_install   - Installer activity, registry changes, file deployment")
            print("  file_tracking      - All file operations (create, read, write, delete)")
            print("  network            - TCP/UDP connections, sends, receives")
            print("  privilege_escalation - Sensitive file/registry modifications")
            print("  custom             - General-purpose with default noise filtering")
            scenario = _prompt("Enter choice [malware]: ") or "malware"
            duration_raw = _prompt("Duration in seconds (empty for manual): ")
            duration = int(duration_raw) if duration_raw else None
            target_process = _prompt("Target process (e.g., notepad.exe) [optional]: ")
            target_path = _prompt("Target path (e.g., C:\\Sensitive) [optional]: ")

            try:
                pmc_path = write_pmc_for_scenario(
                    scenario=scenario,
                    target_process=target_process or None,
                    target_path=target_path or None,
                )
                print(f"[info] PMC config: {pmc_path}")

                pml_path = get_timestamped_pml_path(scenario=scenario)
                print(f"[info] PML path: {pml_path}")

                start_procmon(
                    pml_path=pml_path,
                    runtime_seconds=duration,
                    config_path=pmc_path,
                )

                last_pml = pml_path
                last_csv = None
                last_scenario = scenario
                last_target_process = target_process or None

                if duration:
                    print(f"[info] Procmon running for {duration}s. Perform your activity.")
                    print("[info] Use 'convert' when done to create CSV.")
                else:
                    print("[info] Procmon running. Use 'stop' when done, then 'convert'.")

            except ProcmonError as e:
                print(f"[error] {e}")
            except Exception as e:
                print(f"[error] {e}")

        elif cmd == "stop":
            try:
                stop_procmon()
                print("[info] Procmon stopped.")
                print("[info] Use 'convert' to create CSV for analysis.")
            except ProcmonError as e:
                print(f"[error] {e}")

        elif cmd == "convert":
            if not last_pml:
                print("[error] No capture yet. Run 'start' first.")
                continue

            if not last_pml.exists():
                print(f"[error] PML not found: {last_pml}")
                continue

            process_filter = _prompt("Process filter (optional): ").strip() or None
            if not process_filter and last_target_process:
                process_filter = Path(last_target_process).name
                print(f"[info] Using filter: '{process_filter}'")

            try:
                csv_path = convert_pml_to_csv(
                    str(last_pml),
                    process_filter=process_filter,
                )
                last_csv = Path(csv_path)

                # Show summary
                print_csv_summary(csv_path)
                print(f"\nCSV saved to: {csv_path}")
                print("Tip: Use 'chat' to ask AI questions!")

            except Exception as e:
                print(f"[error] Failed to convert: {e}")

        elif cmd == "load":
            file_path = _prompt("Path to CSV or PML file: ").strip()
            if not file_path:
                print("[error] No path provided.")
                continue

            path = Path(file_path)
            if not path.exists():
                print(f"[error] File not found: {path}")
                continue

            if path.suffix.lower() == '.csv':
                last_csv = path
                print_csv_summary(str(path))
                print("Use 'chat' to analyze with AI.")

            elif path.suffix.lower() == '.pml':
                last_pml = path
                print(f"[info] Loaded PML: {path}")
                print("Use 'convert' to create CSV for analysis.")

            else:
                print(f"[error] Unknown file type: {path.suffix}")

        elif cmd == "chat":
            if not CSV_CHAT_AVAILABLE:
                print("[error] AI chat not available. Set ANTHROPIC_API_KEY.")
                continue

            if not last_csv:
                if last_pml and last_pml.exists():
                    print("[info] No CSV yet. Converting PML first...")
                    try:
                        csv_path = convert_pml_to_csv(str(last_pml))
                        last_csv = Path(csv_path)
                        print_csv_summary(csv_path)
                    except Exception as e:
                        print(f"[error] Failed to convert: {e}")
                        continue
                else:
                    print("[error] No capture available. Use 'start' or 'load' first.")
                    continue

            # Start interactive CSV chat
            interactive_chat(str(last_csv))

        elif cmd == "report":
            if not last_pml or not last_pml.exists():
                print("[error] No PML capture available.")
                continue

            print("[info] Generating Excel report...")
            try:
                report_path = generate_excel_report(last_pml, open_file=True)
                print(f"[success] Report: {report_path}")
            except Exception as e:
                print(f"[error] {e}")

        elif cmd == "stats":
            if last_csv and last_csv.exists():
                print_csv_summary(str(last_csv))
            elif last_pml and last_pml.exists():
                print(f"[info] PML: {last_pml}")
                print(f"[info] Size: {last_pml.stat().st_size / (1024*1024):.2f} MB")
                print("Use 'convert' to see detailed stats.")
            else:
                print("[error] No capture loaded.")

        elif cmd == "help":
            print("\nCommands:")
            print("  start   - Capture new Procmon trace")
            print("  stop    - Stop manual capture")
            print("  convert - Convert PML to CSV (shows summary)")
            print("  load    - Load existing CSV or PML")
            print("  chat    - Chat with AI about the capture")
            print("  stats   - Show capture statistics")
            print("  report  - Excel report")
            print("  quit    - Exit")

        else:
            print("Unknown command. Type 'help' for options.")


if __name__ == "__main__":
    interactive_loop()
