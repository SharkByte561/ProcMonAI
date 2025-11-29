"""
Structured summary generator for Procmon captures.

Generates detailed reports WITHOUT AI - pure data extraction and grouping.
This allows users to see what's in a capture before asking targeted AI questions.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from procmon_parser import ProcmonLogsReader


def extract_categorized_events(
    pml_file: str,
    process_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extract events from PML and categorize them by type.

    Returns a structured dict with events grouped by category,
    ready for targeted AI queries or local reporting.
    """
    pml_path = Path(pml_file)
    if not pml_path.exists():
        raise FileNotFoundError(f"PML file not found: {pml_file}")

    # Category buckets
    registry_creates = []
    registry_sets = []
    registry_deletes = []
    all_registry_ops = []  # All registry operations for persistence detection
    file_creates = []
    file_writes = []
    file_deletes = []
    process_creates = []
    network_ops = []
    dll_loads = []
    other_ops = []

    # Stats
    process_counts = defaultdict(int)
    total_events = 0

    with open(pml_path, 'rb') as f:
        reader = ProcmonLogsReader(f)

        for event in reader:
            total_events += 1

            # Extract process info
            process_name = ""
            pid = 0

            if hasattr(event, 'process') and event.process:
                if hasattr(event.process, 'process_name'):
                    process_name = event.process.process_name or ""
                    pid = getattr(event.process, 'pid', 0)
                else:
                    process_name = str(event.process).split(',')[0].strip('\'()') if event.process else ""

            # Apply process filter
            if process_filter and process_filter.lower() not in process_name.lower():
                continue

            process_counts[process_name] += 1

            op = str(event.operation) if event.operation else ""
            path = str(event.path) if event.path else ""
            result = str(event.result) if event.result else ""
            detail = str(event.details) if event.details else ""

            event_dict = {
                "process": process_name,
                "pid": pid,
                "operation": op,
                "path": path,
                "result": result,
                "detail": detail,
            }

            # Categorize - use broader matching
            if op.startswith("Reg"):
                # All registry ops go to appropriate buckets
                if op == "RegCreateKey":
                    registry_creates.append(event_dict)
                elif op == "RegSetValue":
                    registry_sets.append(event_dict)
                elif op in ("RegDeleteKey", "RegDeleteValue"):
                    registry_deletes.append(event_dict)
                # Also track all registry ops for persistence detection
                all_registry_ops.append(event_dict)
            elif op == "CreateFile" and "SUCCESS" in result:
                file_creates.append(event_dict)
            elif op == "WriteFile":
                file_writes.append(event_dict)
            elif op in ("SetDispositionInformationFile", "DeleteFile"):
                file_deletes.append(event_dict)
            elif op == "Process Create":
                process_creates.append(event_dict)
            elif "TCP" in op or "UDP" in op:
                network_ops.append(event_dict)
            elif op == "Load Image":
                dll_loads.append(event_dict)
            else:
                other_ops.append(event_dict)

    # Build top processes list
    top_processes = sorted(process_counts.items(), key=lambda x: x[1], reverse=True)[:15]

    return {
        "pml_file": str(pml_path),
        "total_events": total_events,
        "process_filter": process_filter,
        "top_processes": [{"process": p, "count": c} for p, c in top_processes],
        "categories": {
            "registry_creates": registry_creates,
            "registry_sets": registry_sets,
            "registry_deletes": registry_deletes,
            "all_registry": all_registry_ops,
            "file_creates": file_creates,
            "file_writes": file_writes,
            "file_deletes": file_deletes,
            "process_creates": process_creates,
            "network": network_ops,
            "dll_loads": dll_loads,
        },
        "category_counts": {
            "Registry Creates": len(registry_creates),
            "Registry Sets": len(registry_sets),
            "Registry Deletes": len(registry_deletes),
            "File Creates": len(file_creates),
            "File Writes": len(file_writes),
            "File Deletes": len(file_deletes),
            "Process Creates": len(process_creates),
            "Network": len(network_ops),
            "DLL Loads": len(dll_loads),
        },
    }


def print_summary(data: Dict[str, Any]) -> None:
    """Print a human-readable summary to console."""
    print("\n" + "=" * 70)
    print("CAPTURE SUMMARY")
    print("=" * 70)
    print(f"File: {data['pml_file']}")
    print(f"Total Events: {data['total_events']}")
    if data['process_filter']:
        print(f"Process Filter: {data['process_filter']}")

    print("\n--- Event Counts by Category ---")
    for cat, count in data['category_counts'].items():
        if count > 0:
            print(f"  {cat}: {count}")

    print("\n--- Top Processes ---")
    for proc in data['top_processes'][:10]:
        print(f"  {proc['process']}: {proc['count']} events")

    # Highlight interesting findings
    print("\n--- Key Findings ---")

    # Registry persistence - scan ALL registry operations
    persistence_keys = []
    persistence_indicators = ['\\run\\', '\\runonce\\', 'currentversion\\run',
                               'startup', 'userinit', 'shell', 'winlogon',
                               'image file execution', 'appinit_dlls']
    for ev in data['categories'].get('all_registry', []):
        path_lower = ev['path'].lower()
        if any(x in path_lower for x in persistence_indicators):
            persistence_keys.append(ev)

    if persistence_keys:
        print(f"\n[!] Potential Persistence ({len(persistence_keys)} registry operations):")
        seen_paths = set()
        for ev in persistence_keys:
            # Dedupe by path
            if ev['path'] not in seen_paths:
                seen_paths.add(ev['path'])
                print(f"    {ev['operation']}: {ev['path'][:70]}")
                if ev['detail']:
                    print(f"      -> {ev['detail'][:60]}")
                if len(seen_paths) >= 10:
                    break

    # Scheduled tasks - check process creates for schtasks AND file operations
    task_events = []
    for ev in data['categories']['process_creates']:
        if 'schtasks' in ev['path'].lower() or 'schtasks' in ev['detail'].lower():
            task_events.append(ev)
    for ev in data['categories']['file_creates'] + data['categories']['file_writes']:
        path_lower = ev['path'].lower()
        if '\\tasks\\' in path_lower or 'system32\\tasks' in path_lower:
            task_events.append(ev)

    if task_events:
        print(f"\n[!] Scheduled Task Activity ({len(task_events)} operations):")
        for ev in task_events[:5]:
            print(f"    {ev['process']}: {ev['operation']} -> {ev['path'][:60]}")
            if ev['detail']:
                print(f"      {ev['detail'][:60]}")

    # Executables written
    exe_writes = []
    for ev in data['categories']['file_creates'] + data['categories']['file_writes']:
        if ev['path'].lower().endswith(('.exe', '.dll', '.sys')):
            exe_writes.append(ev)

    if exe_writes:
        print(f"\n[!] Executable Files Written ({len(exe_writes)}):")
        seen = set()
        for ev in exe_writes:
            if ev['path'] not in seen:
                seen.add(ev['path'])
                print(f"    {ev['path'][:70]}")
                if len(seen) >= 10:
                    break

    # Network connections
    if data['categories']['network']:
        print(f"\n[!] Network Activity ({len(data['categories']['network'])} operations):")
        for ev in data['categories']['network'][:5]:
            print(f"    {ev['process']}: {ev['operation']} {ev['path']}")

    # Process spawns
    if data['categories']['process_creates']:
        print(f"\n[!] Processes Created ({len(data['categories']['process_creates'])}):")
        for ev in data['categories']['process_creates'][:5]:
            print(f"    {ev['process']} -> {ev['path'][:60]}")

    print("\n" + "=" * 70)


def get_category_events(data: Dict[str, Any], category: str, limit: int = 100) -> List[Dict]:
    """Get events for a specific category, with optional limit."""
    cat_map = {
        "registry": data['categories'].get('all_registry', []),  # All registry ops
        "registry_creates": data['categories']['registry_creates'],
        "registry_sets": data['categories']['registry_sets'],
        "files": data['categories']['file_creates'] + data['categories']['file_writes'],
        "file_creates": data['categories']['file_creates'],
        "file_writes": data['categories']['file_writes'],
        "processes": data['categories']['process_creates'],
        "network": data['categories']['network'],
        "dlls": data['categories']['dll_loads'],
    }

    events = cat_map.get(category.lower(), [])
    return events[:limit]


def format_events_for_ai(events: List[Dict], max_events: int = 200) -> str:
    """Format a list of events for AI analysis (compact format)."""
    lines = []
    for ev in events[:max_events]:
        line = f"{ev['process']} | {ev['operation']} | {ev['path']}"
        if ev['detail']:
            line += f" | {ev['detail'][:50]}"
        lines.append(line)
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        pml_file = sys.argv[1]
        process_filter = sys.argv[2] if len(sys.argv) > 2 else None

        data = extract_categorized_events(pml_file, process_filter)
        print_summary(data)
