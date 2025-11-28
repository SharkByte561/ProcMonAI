"""
Interactive ProcmonAI agent with summary-first analysis.

New approach:
1. Generate local summary (no AI, instant)
2. Show key findings immediately
3. Allow targeted AI questions on specific categories
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
from procmon_summary import (
    extract_categorized_events,
    print_summary,
    get_category_events,
    format_events_for_ai,
)

# Try to import chat module
try:
    from ai_chat import ProcmonChat
    CHAT_AVAILABLE = True
except ImportError:
    ProcmonChat = None  # type: ignore
    CHAT_AVAILABLE = False


def _prompt(text: str) -> str:
    return input(text).strip()


def _build_summary_text(data: dict) -> str:
    """Build a brief text summary for AI context."""
    lines = [
        f"Total Events: {data['total_events']}",
        f"Process Filter: {data['process_filter'] or 'None'}",
        "",
        "Event Counts:",
    ]
    for cat, count in data['category_counts'].items():
        if count > 0:
            lines.append(f"  {cat}: {count}")

    lines.append("")
    lines.append("Top Processes:")
    for proc in data['top_processes'][:5]:
        lines.append(f"  {proc['process']}: {proc['count']}")

    return "\n".join(lines)


def chat_loop(chat: "ProcmonChat", data: dict) -> None:
    """
    Interactive chat loop with category-aware context.

    Users can ask questions, and we'll include relevant events
    based on keywords in their question.
    """
    print("\n" + "=" * 70)
    print("AI CHAT - Ask questions about the capture")
    print("=" * 70)
    print("Commands:")
    print("  Type a question to ask Claude (relevant events auto-selected)")
    print("  'registry' - Analyze registry changes")
    print("  'files'    - Analyze file operations")
    print("  'network'  - Analyze network activity")
    print("  'processes'- Analyze process creation")
    print("  'done'     - Exit chat")
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
            print("[Conversation cleared]")
            continue

        # Determine which events to include based on question
        events_text = ""
        category = None

        # Check for category commands
        if lower_input in ('registry', 'reg'):
            category = "Registry"
            events = get_category_events(data, "registry", limit=150)
            events_text = format_events_for_ai(events, max_events=150)
            user_input = "Analyze these registry operations. What keys were created or modified? Are there any persistence mechanisms?"

        elif lower_input in ('files', 'file'):
            category = "File Operations"
            events = get_category_events(data, "files", limit=150)
            events_text = format_events_for_ai(events, max_events=150)
            user_input = "Analyze these file operations. What files were created or written? Any executables or suspicious paths?"

        elif lower_input in ('network', 'net'):
            category = "Network"
            events = get_category_events(data, "network", limit=100)
            events_text = format_events_for_ai(events, max_events=100)
            user_input = "Analyze this network activity. What connections were made? Any suspicious destinations?"

        elif lower_input in ('processes', 'process', 'procs'):
            category = "Processes"
            events = get_category_events(data, "processes", limit=50)
            events_text = format_events_for_ai(events, max_events=50)
            user_input = "Analyze these process creation events. What processes were spawned? Any suspicious child processes?"

        elif lower_input in ('dlls', 'dll', 'images'):
            category = "DLL Loads"
            events = get_category_events(data, "dlls", limit=100)
            events_text = format_events_for_ai(events, max_events=100)
            user_input = "Analyze these DLL/image loads. Any suspicious or unusual DLLs loaded?"

        else:
            # Auto-detect category from question keywords
            if any(kw in lower_input for kw in ['registry', 'reg', 'hkey', 'hklm', 'hkcu', 'autorun', 'persistence', 'startup']):
                events = get_category_events(data, "registry", limit=150)
                events_text = format_events_for_ai(events, max_events=150)

            elif any(kw in lower_input for kw in ['file', 'write', 'create', 'exe', 'dll', 'path', 'folder', 'directory']):
                events = get_category_events(data, "files", limit=150)
                events_text = format_events_for_ai(events, max_events=150)

            elif any(kw in lower_input for kw in ['network', 'tcp', 'udp', 'connect', 'ip', 'port', 'internet']):
                events = get_category_events(data, "network", limit=100)
                events_text = format_events_for_ai(events, max_events=100)

            elif any(kw in lower_input for kw in ['process', 'spawn', 'child', 'execute', 'launch']):
                events = get_category_events(data, "processes", limit=50)
                events_text = format_events_for_ai(events, max_events=50)

            elif any(kw in lower_input for kw in ['task', 'schedule', 'scheduled']):
                # Scheduled tasks are in file operations
                all_files = get_category_events(data, "files", limit=500)
                task_events = [e for e in all_files if 'task' in e['path'].lower() or 'schedule' in e['path'].lower()]
                events_text = format_events_for_ai(task_events, max_events=50)

        # Send to Claude
        try:
            print("\nClaude: ", end="", flush=True)
            response = chat.ask(user_input, events=events_text)
            print(response)
            print()
        except Exception as e:
            print(f"\n[Error: {e}]")


def interactive_loop() -> None:
    """Main interactive loop with summary-first approach."""
    print("=" * 70)
    print(" ProcmonAI - Summary-First Analysis")
    print("=" * 70)
    print("Commands:")
    print("  start   - Start a new Procmon capture")
    print("  stop    - Stop a running manual capture")
    print("  summary - Generate local summary (no AI, instant)")
    print("  chat    - Ask AI questions about specific categories")
    print("  report  - Generate Excel report")
    print("  inspect - Debug: show processes in PML")
    print("  quit    - Exit")
    print("=" * 70)

    if not CHAT_AVAILABLE:
        print("\n[WARNING] AI chat not available. Check ANTHROPIC_API_KEY.")

    last_pml: Optional[Path] = None
    last_scenario: str = "summary"
    last_target_process: Optional[str] = None
    last_data: Optional[dict] = None
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
                last_data = None
                chat_session = None

                if duration:
                    print(f"[info] Procmon running for {duration}s. Perform your activity.")
                    print("[info] Use 'summary' when done to see findings.")
                else:
                    print("[info] Procmon running. Use 'stop' when done, then 'summary'.")

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

        elif cmd == "summary":
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

            print(f"[info] Analyzing {last_pml}...")
            try:
                last_data = extract_categorized_events(
                    str(last_pml),
                    process_filter=process_filter,
                )
                print_summary(last_data)
                print("\nTip: Use 'chat' to ask AI about specific categories!")

            except Exception as e:
                print(f"[error] Failed to analyze: {e}")

        elif cmd == "chat":
            if not CHAT_AVAILABLE:
                print("[error] AI chat not available. Set ANTHROPIC_API_KEY.")
                continue

            if not last_data:
                print("[error] No summary yet. Run 'summary' first.")
                continue

            # Create/reuse chat session
            if chat_session is None:
                chat_session = ProcmonChat()
                summary_text = _build_summary_text(last_data)
                chat_session.set_summary(summary_text)

            chat_loop(chat_session, last_data)

        elif cmd == "report":
            if not last_pml or not last_pml.exists():
                print("[error] No capture available.")
                continue

            print("[info] Generating Excel report...")
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
            print("  summary - Local analysis (instant, no AI)")
            print("  chat    - AI questions by category")
            print("  report  - Excel report")
            print("  inspect - Debug PML contents")
            print("  quit    - Exit")

        else:
            print("Unknown command. Type 'help' for options.")


if __name__ == "__main__":
    interactive_loop()
