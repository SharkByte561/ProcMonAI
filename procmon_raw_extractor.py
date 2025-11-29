"""
Raw Procmon event extractor for Claude analysis.

Instead of trying to write complex heuristics locally,
this module simply extracts all relevant event data
and lets Claude do the intelligent analysis.
"""

import json
from procmon_parser import ProcmonLogsReader
import pandas as pd
from pathlib import Path
from typing import Optional, Dict, Any, List


def extract_raw_events(
    pml_file: str,
    process_filter: Optional[str] = None,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Extract raw event data from PML file with minimal filtering.
    
    Args:
        pml_file: Path to .pml file
        process_filter: Optional process name to filter (case-insensitive substring match)
        limit: Optional max number of events to extract (for large captures)
    
    Returns:
        Dict with raw events and metadata for Claude analysis
    """
    pml_path = Path(pml_file)
    if not pml_path.exists():
        raise FileNotFoundError(f"PML file not found: {pml_file}")
    
    print(f"[Extractor] Reading PML: {pml_file}", flush=True)
    
    events = []
    process_names = set()
    
    try:
        with open(pml_path, 'rb') as f:
            reader = ProcmonLogsReader(f)
            
            for event in reader:
                # Extract process info
                process_name = ""
                pid = 0
                
                if hasattr(event, 'process') and event.process:
                    if hasattr(event.process, 'process_name'):
                        process_name = event.process.process_name or ""
                        pid = event.process.pid if hasattr(event.process, 'pid') else 0
                    else:
                        process_name = str(event.process).split(',')[0].strip('\'()') if event.process else ""
                
                # Skip if process filter doesn't match
                if process_filter and process_filter.lower() not in process_name.lower():
                    continue
                
                process_names.add(process_name)
                
                # Collect all events with key details
                event_dict = {
                    "process": process_name,
                    "pid": pid,
                    "operation": str(event.operation),
                    "path": event.path or "",
                    "result": event.result or "",
                    "detail": event.details or "",
                }
                
                events.append(event_dict)
                
                # Optional limit
                if limit and len(events) >= limit:
                    break
    
    except Exception as e:
        raise RuntimeError(f"Error reading PML: {e}") from e
    
    print(f"[Extractor] Loaded {len(events)} events", flush=True)
    
    # Basic categorization for Claude context
    categories = {
        "Process Creates": sum(1 for e in events if e["operation"] == "Process Create"),
        "File Writes": sum(1 for e in events if e["operation"] in ["WriteFile", "SetDispositionInformationFile"]),
        "File Creates": sum(1 for e in events if e["operation"] == "CreateFile"),
        "Registry Ops": sum(1 for e in events if e["operation"].startswith("Reg")),
        "Network Ops": sum(1 for e in events if "TCP" in e["operation"] or "UDP" in e["operation"]),
    }
    
    # Top processes
    process_counts = {}
    for event in events:
        process_counts[event["process"]] = process_counts.get(event["process"], 0) + 1
    top_processes = sorted(process_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    return {
        "status": "success",
        "pml_file": str(pml_path),
        "total_events": len(events),
        "events": events[:1000] if len(events) > 1000 else events,  # Limit to 1000 for API
        "truncated": len(events) > 1000,
        "process_filter": process_filter,
        "unique_processes": sorted(list(process_names)),
        "top_processes": [{"process": name, "count": count} for name, count in top_processes],
        "event_categories": categories,
    }


def format_for_claude(raw_data: Dict[str, Any]) -> str:
    """Format extracted data as a readable prompt for Claude."""
    
    lines = []
    lines.append("=" * 70)
    lines.append("PROCMON CAPTURE DATA FOR ANALYSIS")
    lines.append("=" * 70)
    lines.append("")
    
    lines.append(f"PML File: {raw_data['pml_file']}")
    lines.append(f"Total Events: {raw_data['total_events']}")
    
    if raw_data['process_filter']:
        lines.append(f"Process Filter: {raw_data['process_filter']}")
    
    if raw_data['truncated']:
        lines.append(f"NOTE: Data truncated to first 1000 events (total: {raw_data['total_events']})")
    
    lines.append("")
    lines.append("EVENT DISTRIBUTION:")
    for category, count in raw_data['event_categories'].items():
        lines.append(f"  - {category}: {count}")
    
    lines.append("")
    lines.append("TOP PROCESSES (by event count):")
    for proc_info in raw_data['top_processes']:
        lines.append(f"  - {proc_info['process']}: {proc_info['count']} events")
    
    lines.append("")
    lines.append("ALL UNIQUE PROCESSES:")
    lines.append(", ".join(raw_data['unique_processes']))
    
    lines.append("")
    lines.append("-" * 70)
    lines.append("RAW EVENTS:")
    lines.append("-" * 70)
    
    # Format events in a readable way
    for i, event in enumerate(raw_data['events'], 1):
        lines.append(f"\n[{i}] {event['process']} (PID: {event['pid']})")
        lines.append(f"    Operation: {event['operation']}")
        lines.append(f"    Path: {event['path']}")
        if event['result'] and event['result'].lower() != 'success':
            lines.append(f"    Result: {event['result']}")
        if event['detail']:
            lines.append(f"    Detail: {event['detail']}")
    
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        pml_file = sys.argv[1]
        process_filter = sys.argv[2] if len(sys.argv) > 2 else None
        
        raw_data = extract_raw_events(pml_file, process_filter)
        print(format_for_claude(raw_data))

