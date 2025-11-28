"""
Interactive ProcmonAI agent with multi-turn chat support.

This script provides a natural conversation interface for analyzing
Procmon captures with Claude. Unlike single-query mode, chat mode
maintains conversation history so you can ask follow-up questions.
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
from procmon_raw_extractor import extract_raw_events

# Try to import chat module
try:
    from ai_chat import ProcmonChat
    CHAT_AVAILABLE = True
except ImportError:
    ProcmonChat = None  # type: ignore
    CHAT_AVAILABLE = False


def _prompt(text: str) -> str:
    return input(text).strip()


def _print_raw_summary(raw_data: dict) -> None:
    """Print a brief summary of the raw extracted events."""
    print("\n=== Capture Summary ===")
    print(f"Total events: {raw_data['total_events']}")

    if raw_data['truncated']:
        print(f"(Showing first 1000 of {raw_data['total_events']} events)")

    print("\nEvent types:")
    for category, count in raw_data['event_categories'].items():
        if count > 0:
            print(f"  {category}: {count}")

    print("\nTop processes:")
    for proc in raw_data['top_processes'][:5]:
        print(f"  {proc['process']}: {proc['count']} events")
    print()


def chat_loop(chat: "ProcmonChat") -> None:
    """
    Interactive chat loop for asking questions about a loaded capture.

    Commands within chat:
      - Type any question to ask Claude
      - 'done' or 'exit' to leave chat mode
      - 'clear' to clear conversation history (keeps capture)
      - 'history' to see conversation length
    """
    print("\n" + "=" * 70)
    print("CHAT MODE - Ask questions about the capture")
    print("=" * 70)
    print("Type your questions naturally. Claude remembers the conversation.")
    print("Commands: 'done' (exit chat), 'clear' (reset history), 'history' (show length)")
    print("=" * 70 + "\n")

    while True:
        try:
            user_input = _prompt("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[Leaving chat mode]")
            break

        if not user_input:
            continue

        lower_input = user_input.lower()

        if lower_input in ('done', 'exit', 'quit', 'q'):
            print("[Leaving chat mode]")
            break

        if lower_input == 'clear':
            chat.clear()
            print("[Conversation history cleared. Capture context retained.]")
            continue

        if lower_input == 'history':
            print(f"[Conversation has {chat.get_conversation_length()} messages]")
            continue

        # Send question to Claude
        try:
            print("\nClaude: ", end="", flush=True)
            response = chat.ask(user_input)
            print(response)
            print()
        except Exception as e:
            print(f"\n[Error: {e}]")


def interactive_loop() -> None:
    """Main interactive loop with chat support."""
    print("=" * 70)
    print(" ProcmonAI - Interactive Analysis with Chat")
    print("=" * 70)
    print("Commands:")
    print("  start   - Start a new Procmon capture")
    print("  stop    - Stop a running manual capture")
    print("  chat    - Start interactive chat about the capture (NEW!)")
    print("  analyze - Quick one-shot analysis")
    print("  report  - Generate Excel report")
    print("  inspect - Debug: show processes in PML")
    print("  quit    - Exit")
    print("=" * 70)

    if not CHAT_AVAILABLE:
        print("\n[WARNING] Chat module not available. Check ANTHROPIC_API_KEY.")

    last_pml: Optional[Path] = None
    last_scenario: str = "summary"
    last_target_process: Optional[str] = None
    last_raw_data: Optional[dict] = None
    chat_session: Optional["ProcmonChat"] = None

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
                last_scenario = scenario
                last_target_process = target_process or None
                last_raw_data = None
                chat_session = None  # Reset chat for new capture

                if duration:
                    print(f"[info] Procmon running for {duration}s. Perform your activity.")
                    print("[info] Use 'chat' or 'analyze' when done.")
                else:
                    print("[info] Procmon running. Use 'stop' when done, then 'chat'.")

            except ProcmonError as e:
                print(f"[error] {e}")
            except Exception as e:
                print(f"[error] {e}")

        elif cmd == "stop":
            try:
                stop_procmon()
                print("[info] Procmon stopped.")
            except ProcmonError as e:
                print(f"[error] {e}")

        elif cmd == "chat":
            if not CHAT_AVAILABLE:
                print("[error] Chat not available. Set ANTHROPIC_API_KEY.")
                continue

            if not last_pml:
                print("[error] No capture yet. Run 'start' first.")
                continue

            if not last_pml.exists():
                print(f"[error] PML not found: {last_pml}")
                continue

            # Extract events if needed
            if not last_raw_data:
                process_filter = _prompt("Process filter (optional): ").strip() or None
                if not process_filter and last_target_process:
                    process_filter = Path(last_target_process).name
                    print(f"[info] Using filter: '{process_filter}'")

                limit_raw = _prompt("Event limit [1000]: ").strip()
                event_limit = int(limit_raw) if limit_raw else 1000

                print(f"[info] Loading {last_pml} (limit: {event_limit} events)...")
                try:
                    last_raw_data = extract_raw_events(
                        str(last_pml),
                        process_filter=process_filter,
                        limit=event_limit,
                    )
                    _print_raw_summary(last_raw_data)
                except Exception as e:
                    print(f"[error] Failed to extract: {e}")
                    continue

            # Start or resume chat session
            if chat_session is None:
                print("[info] Starting chat session with Claude...")
                try:
                    chat_session = ProcmonChat()
                    initial_response = chat_session.load_capture(
                        last_raw_data,
                        scenario=last_scenario,
                    )
                    print("\n" + "=" * 70)
                    print("CLAUDE'S INITIAL ANALYSIS")
                    print("=" * 70)
                    print(initial_response)
                    print("=" * 70)
                except Exception as e:
                    print(f"[error] Failed to start chat: {e}")
                    chat_session = None
                    continue
            else:
                print("[info] Resuming existing chat session...")

            # Enter chat loop
            chat_loop(chat_session)

        elif cmd == "analyze":
            # Quick one-shot analysis (original behavior)
            if not last_pml or not last_pml.exists():
                print("[error] No capture available.")
                continue

            if not CHAT_AVAILABLE:
                print("[error] Claude not available.")
                continue

            process_filter = _prompt("Process filter (optional): ").strip() or None
            if not process_filter and last_target_process:
                process_filter = Path(last_target_process).name

            limit_raw = _prompt("Event limit [1000]: ").strip()
            event_limit = int(limit_raw) if limit_raw else 1000

            print(f"[info] Analyzing {last_pml} (limit: {event_limit} events)...")
            try:
                last_raw_data = extract_raw_events(
                    str(last_pml),
                    process_filter=process_filter,
                    limit=event_limit,
                )
                _print_raw_summary(last_raw_data)

                # One-shot analysis
                temp_chat = ProcmonChat()
                analysis = temp_chat.load_capture(last_raw_data, scenario=last_scenario)

                print("\n" + "=" * 70)
                print("ANALYSIS")
                print("=" * 70)
                print(analysis)
                print("=" * 70)
                print("\nTip: Use 'chat' for follow-up questions!")

            except Exception as e:
                print(f"[error] {e}")

        elif cmd == "report":
            if not last_pml or not last_pml.exists():
                print("[error] No capture available.")
                continue

            print(f"[info] Generating Excel report...")
            try:
                report_path = generate_excel_report(last_pml, open_file=True)
                print(f"[success] Report: {report_path}")
            except Exception as e:
                print(f"[error] {e}")

        elif cmd == "inspect":
            if not last_pml or not last_pml.exists():
                print("[error] No capture available.")
                continue

            print(f"[info] Inspecting: {last_pml}")
            print(f"[info] Size: {last_pml.stat().st_size / (1024*1024):.2f} MB")

            try:
                from procmon_parser import ProcmonLogsReader
                with open(last_pml, 'rb') as f:
                    reader = ProcmonLogsReader(f)
                    total = len(reader)
                    print(f"[info] Total events: {total}")

                    if total > 0:
                        process_names = set()
                        for i, event in enumerate(reader):
                            if i >= 1000:
                                break
                            if hasattr(event, 'process'):
                                proc = event.process
                                if isinstance(proc, tuple):
                                    process_names.add(proc[0])
                                else:
                                    process_names.add(str(proc))

                        print(f"\nProcesses (sample of {len(process_names)}):")
                        for name in sorted(process_names)[:20]:
                            print(f"  {name}")
            except Exception as e:
                print(f"[error] {e}")

        elif cmd == "help":
            print("\nCommands:")
            print("  start   - Capture new Procmon trace")
            print("  stop    - Stop manual capture")
            print("  chat    - Interactive Q&A with Claude about the capture")
            print("  analyze - One-shot analysis")
            print("  report  - Excel report")
            print("  inspect - Debug PML contents")
            print("  quit    - Exit")

        else:
            print("Unknown command. Type 'help' for options.")


if __name__ == "__main__":
    interactive_loop()
