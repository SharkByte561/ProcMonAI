"""
Procmon launcher utilities for the standalone ProcmonAI agent.

Responsibilities:
- Locate the Procmon binary under the repo's `assets` directory.
- Ensure the EULA is accepted.
- Verify the process is running as Administrator.
- Start Procmon with a backing PML file (and optional config) with the GUI visible.
- Stop Procmon cleanly.
"""

import ctypes
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import winreg  # type: ignore[attr-defined]
except ImportError:  # Non-Windows platforms
    winreg = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parent
ASSETS_DIR = REPO_ROOT / "assets"

# Default capture paths (align with SKILL behavior, but configurable via env)
PROCMON_BASE_DIR = Path(os.environ.get("PROCMON_BASE_DIR", r"C:\ProgramData\Procmon"))
PROCMON_BASE_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_PML_PATH = PROCMON_BASE_DIR / "events.pml"


def get_timestamped_pml_path(scenario: str = "capture") -> Path:
    """
    Generate a timestamped PML filename to ensure each capture is unique.
    
    Args:
        scenario: Optional scenario name to include in the filename.
    
    Returns:
        Path to a timestamped PML file (e.g., events_20250115_143022_malware.pml).
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"events_{timestamp}_{scenario}.pml"
    return PROCMON_BASE_DIR / filename


class ProcmonError(RuntimeError):
    """Custom error type for Procmon-related failures."""


def is_windows() -> bool:
    return sys.platform.startswith("win")


def ensure_admin() -> None:
    """
    Ensure the current process is running elevated.

    Raises:
        ProcmonError: if not running as Administrator on Windows.
    """
    if not is_windows():
        raise ProcmonError("Procmon is only supported on Windows.")

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover - defensive
        raise ProcmonError(f"Unable to determine admin status: {exc}") from exc

    if not is_admin:
        raise ProcmonError(
            "Administrator privileges are required to run Procmon.\n"
            "Please launch your terminal or IDE as Administrator and try again."
        )


def _set_eula_accepted() -> None:
    """
    Accept the Sysinternals Procmon EULA via registry so the GUI does not prompt.
    """
    if not winreg:
        return

    key_path = r"SOFTWARE\Sysinternals\Process Monitor"
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(key, "EulaAccepted", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
    except OSError:
        # Non-fatal – Procmon may still prompt, but agent will continue.
        return


def _find_procmon_exe() -> Path:
    """
    Locate the Procmon executable under `assets`.

    Preference order:
    1. Procmon64.exe
    2. Procmon.exe

    Returns:
        Path to the Procmon executable.

    Raises:
        ProcmonError: if no Procmon binary is found.
    """
    candidates = [
        ASSETS_DIR / "Procmon64.exe",
        ASSETS_DIR / "Procmon.exe",
    ]
    for path in candidates:
        if path.exists():
            return path

    raise ProcmonError(
        f"Could not find Procmon executable under assets.\n"
        f"Expected one of: {', '.join(str(p) for p in candidates)}"
    )


def start_procmon(
    pml_path: Optional[Path] = None,
    runtime_seconds: Optional[int] = None,
    config_path: Optional[Path] = None,
) -> subprocess.Popen:
    """
    Start Procmon with a backing PML file and optional runtime/config.

    Procmon GUI is left visible (no /Minimized flag) so the user can inspect
    filters and event rows while the capture is running.

    Args:
        pml_path: Target PML file path. Defaults to DEFAULT_PML_PATH.
        runtime_seconds: Optional fixed runtime; if None, capture runs until stopped.
        config_path: Optional PMC configuration file to load via /LoadConfig.

    Returns:
        subprocess.Popen for the Procmon process.

    Raises:
        ProcmonError: for validation or startup failures.
    """
    ensure_admin()
    _set_eula_accepted()

    procmon_exe = _find_procmon_exe()
    pml_path = pml_path or DEFAULT_PML_PATH
    pml_path.parent.mkdir(parents=True, exist_ok=True)

    # Aggressively delete any old PML at this location to prevent contamination
    # Retry with waits in case the file is locked by a previous Procmon instance
    if pml_path.exists():
        max_retries = 5
        for attempt in range(max_retries):
            try:
                pml_path.unlink()
                break  # Successfully deleted
            except OSError:
                if attempt < max_retries - 1:
                    time.sleep(0.5)  # Wait 500ms before retry
                else:
                    # Last attempt failed - raise an error to prevent contamination
                    raise ProcmonError(
                        f"Could not delete old PML file at {pml_path}. "
                        "It may be locked by another process. Please close any "
                        "Procmon instances and try again."
                    )

    args = [
        str(procmon_exe),
        "/BackingFile",
        str(pml_path),
        "/Quiet",
        "/AcceptEula",
    ]

    if runtime_seconds and runtime_seconds > 0:
        args.extend(["/Runtime", str(runtime_seconds)])

    if config_path:
        args.extend(["/LoadConfig", str(config_path)])

    try:
        # Visible GUI: do NOT pass /Minimized
        proc = subprocess.Popen(args)  # noqa: S603
    except OSError as exc:
        raise ProcmonError(f"Failed to start Procmon: {exc}") from exc

    return proc


def stop_procmon(wait_seconds: int = 30) -> None:
    """
    Stop Procmon by issuing the /Terminate command and waiting for exit.

    Args:
        wait_seconds: Maximum time to wait for Procmon to exit.

    Raises:
        ProcmonError: if Procmon does not exit within the wait timeout.
    """
    procmon_exe = _find_procmon_exe()

    # Issue terminate command (this spawns a short-lived helper Procmon instance)
    try:
        subprocess.run(  # noqa: S603
            [str(procmon_exe), "/Terminate"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise ProcmonError(f"Failed to send /Terminate to Procmon: {exc}") from exc

    # Poll for running Procmon processes
    deadline = time.time() + max(wait_seconds, 0)
    exe_name = procmon_exe.name.lower()

    while time.time() < deadline:
        # Use 'tasklist' to check for remaining Procmon processes
        try:
            result = subprocess.run(  # noqa: S603
                ["tasklist", "/FI", "IMAGENAME eq Procmon.exe", "/FI", "IMAGENAME eq Procmon64.exe"],
                capture_output=True,
                text=True,
            )
        except OSError:
            # If tasklist fails, just break and hope Procmon exited
            break

        output = result.stdout.lower()
        if "procmon.exe" not in output and "procmon64.exe" not in output and exe_name not in output:
            return

        time.sleep(1.0)

    raise ProcmonError("Procmon did not exit within the allotted wait time.")


__all__ = [
    "ProcmonError",
    "DEFAULT_PML_PATH",
    "PROCMON_BASE_DIR",
    "get_timestamped_pml_path",
    "start_procmon",
    "stop_procmon",
]


