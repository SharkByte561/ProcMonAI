"""
Scenario-based Procmon filter configuration using procmon-parser PMC files.

This module mirrors the high-level scenarios described in SKILL.md:
- malware
- privilege_escalation
- file_tracking
- network
- software_install
- custom

It builds a Procmon configuration dictionary and writes it to a PMC file
using procmon-parser's configuration helpers. The resulting PMC can be
loaded by Procmon via the /LoadConfig command-line switch.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Iterable, List, Optional

from procmon_parser import (
    Column,
    Rule,
    RuleAction,
    RuleRelation,
    dump_configuration,
)


def _default_exclusion_rules() -> List[Rule]:
    """
    Approximate the default noise filters from the original PowerShell module.
    """
    rules: List[Rule] = []

    # Exclude Procmon and common Sysinternals tools and System
    for proc_name in (
        "Procmon.exe",
        "Procmon64.exe",
        "Procexp.exe",
        "Procexp64.exe",
        "Autoruns.exe",
        "System",
    ):
        rules.append(Rule("Process_Name", "is", proc_name, "exclude"))

    # Exclude IRP and FASTIO noise
    rules.append(Rule("Operation", "begins_with", "IRP_MJ_", "exclude"))
    rules.append(Rule("Operation", "begins_with", "FASTIO_", "exclude"))
    rules.append(Rule("Result", "begins_with", "FAST IO", "exclude"))

    # Exclude NTFS metadata paths
    for suffix in (
        "pagefile.sys",
        "$Mft",
        "$MftMirr",
        "$LogFile",
        "$Volume",
        "$AttrDef",
        "$Root",
        "$Bitmap",
        "$Boot",
        "$BadClus",
        "$Secure",
        "$UpCase",
    ):
        rules.append(Rule("Path", "ends_with", suffix, "exclude"))

    rules.append(Rule("Path", "contains", "$Extend", "exclude"))
    rules.append(Rule("Event_Class", "is", "Profiling", "exclude"))

    return rules


def _scenario_include_rules(
    scenario: str,
    target_process: Optional[str] = None,
    target_path: Optional[str] = None,
) -> List[Rule]:
    """
    Build inclusive rules for a given scenario.
    """
    s = (scenario or "").lower()
    rules: List[Rule] = []

    if s == "malware":
        rules.extend(
            [
                Rule("Operation", "is", "CreateFile", "include"),
                Rule("Operation", "is", "WriteFile", "include"),
                Rule("Operation", "is", "SetRenameInformationFile", "include"),
                Rule("Operation", "is", "SetDispositionInformationFile", "include"),
                Rule("Operation", "is", "RegCreateKey", "include"),
                Rule("Operation", "is", "RegSetValue", "include"),
                Rule("Operation", "is", "RegDeleteKey", "include"),
                Rule("Operation", "is", "RegDeleteValue", "include"),
                Rule("Operation", "is", "TCP Connect", "include"),
                Rule("Operation", "is", "TCP Send", "include"),
                Rule("Operation", "is", "TCP Receive", "include"),
                Rule("Operation", "is", "UDP Connect", "include"),
                Rule("Operation", "is", "UDP Send", "include"),
                Rule("Operation", "is", "UDP Receive", "include"),
                Rule("Operation", "is", "Load Image", "include"),
                Rule("Operation", "is", "Process Create", "include"),
            ]
        )
    elif s == "privilege_escalation":
        rules.extend(
            [
                Rule("Operation", "is", "WriteFile", "include"),
                Rule("Operation", "is", "RegSetValue", "include"),
            ]
        )
    elif s == "file_tracking":
        rules.extend(
            [
                Rule("Operation", "is", "CreateFile", "include"),
                Rule("Operation", "is", "WriteFile", "include"),
                Rule("Operation", "is", "ReadFile", "include"),
                Rule("Operation", "is", "LockFile", "include"),
                Rule("Operation", "is", "CloseFile", "include"),
                Rule("Operation", "is", "SetDispositionInformationFile", "include"),
            ]
        )
    elif s == "network":
        rules.extend(
            [
                Rule("Operation", "is", "TCP Connect", "include"),
                Rule("Operation", "is", "TCP Send", "include"),
                Rule("Operation", "is", "TCP Receive", "include"),
                Rule("Operation", "is", "UDP Connect", "include"),
                Rule("Operation", "is", "UDP Send", "include"),
                Rule("Operation", "is", "UDP Receive", "include"),
            ]
        )
    elif s in ("software_install", "software", "install"):
        rules.extend(
            [
                Rule("Operation", "is", "CreateFile", "include"),
                Rule("Operation", "is", "WriteFile", "include"),
                Rule("Operation", "is", "RegSetValue", "include"),
                Rule("Operation", "is", "RegCreateKey", "include"),
                Rule("Operation", "is", "Process Create", "include"),
                Rule("Operation", "is", "Load Image", "include"),
            ]
        )
    else:  # custom / default
        # Start with a reasonable default similar to software_install
        rules.extend(
            [
                Rule("Operation", "is", "CreateFile", "include"),
                Rule("Operation", "is", "WriteFile", "include"),
                Rule("Operation", "is", "RegSetValue", "include"),
                Rule("Operation", "is", "RegCreateKey", "include"),
                Rule("Operation", "is", "Process Create", "include"),
                Rule("Operation", "is", "Load Image", "include"),
            ]
        )

    if target_process:
        rules.append(Rule("Process_Name", "is", target_process, "include"))

    if target_path:
        rules.append(Rule("Path", "contains", target_path, "include"))

    return rules


def build_rules(
    scenario: str,
    target_process: Optional[str] = None,
    target_path: Optional[str] = None,
) -> List[Rule]:
    """
    Build the full rule list (scenario + default exclusions).
    """
    include_rules = _scenario_include_rules(scenario, target_process, target_path)
    default_rules = _default_exclusion_rules()
    # Order is not critical, but keep scenario rules first
    return include_rules + default_rules


def build_configuration(
    rules: Iterable[Rule],
    destructive_filter: bool = False,
) -> dict:
    """
    Build a Procmon configuration dictionary suitable for dump_configuration.
    
    Note: When destructive_filter=True, Procmon will drop filtered events from the log.
    This is useful when you want to ONLY capture specific events (e.g., only notepad.exe).
    However, be careful: if filters are too restrictive, you might miss important context.
    """
    cfg: dict = {
        "FilterRules": list(rules),
        # 0 = keep filtered events in log, 1 = drop them
        # When target_process is specified, use destructive filtering to ensure ONLY that process
        "DestructiveFilter": 1 if destructive_filter else 0,
    }
    return cfg


def write_pmc_for_scenario(
    scenario: str,
    target_process: Optional[str] = None,
    target_path: Optional[str] = None,
    output_dir: Optional[Path] = None,
) -> Path:
    """
    Build rules for a scenario and write them to a PMC file.

    When target_process is specified, we use destructive filtering to ensure
    ONLY events from that process are captured. This prevents contamination
    from other processes.

    Returns:
        Path to the PMC file on disk.
    """
    rules = build_rules(scenario, target_process, target_path)
    
    # If a target_process is specified, use destructive filtering to ensure
    # ONLY events from that process are kept in the PML
    use_destructive = target_process is not None
    
    cfg = build_configuration(rules, destructive_filter=use_destructive)

    if output_dir is None:
        tmp_dir = Path(tempfile.gettempdir())
    else:
        tmp_dir = output_dir
    tmp_dir.mkdir(parents=True, exist_ok=True)

    pmc_path = tmp_dir / f"Procmon_{scenario or 'custom'}.pmc"

    with pmc_path.open("wb") as f:
        dump_configuration(cfg, f)

    return pmc_path


__all__ = [
    "build_rules",
    "build_configuration",
    "write_pmc_for_scenario",
    "Rule",
    "Column",
    "RuleAction",
    "RuleRelation",
]


