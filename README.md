# ProcmonAI

**Interactive Process Monitor analysis powered by Claude AI**

ProcmonAI lets you have natural language conversations with your Windows Process Monitor (Procmon) captures. Ask questions like "What files did this process create?" or "Show me suspicious registry modifications" and get intelligent, context-aware answers.

## Features

- **CSV-First Workflow**: Convert PML to CSV for portable, searchable analysis
- **Smart AI Chat**: Ask questions in natural language - relevant events are automatically filtered and sent to Claude
- **Category Analysis**: Quick commands for registry, files, network, process analysis
- **Scenario-based Filtering**: Pre-configured filters for malware analysis, software installation, file tracking, network activity, and privilege escalation
- **Process-focused Analysis**: Filter captures to specific processes for targeted investigation
- **Excel Reports**: Generate detailed spreadsheet reports from captures
- **Automated Capture**: Start/stop Procmon programmatically with custom filters

## Quick Start

### Prerequisites

- Windows 10/11
- Python 3.10+
- [Anthropic API key](https://console.anthropic.com/)

### Installation

```powershell
# Clone the repository
git clone https://github.com/SharkByte561/ProcMonAI.git
cd ProcMonAI

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Set your API key (run once, saves to User environment variables)
.\set_anthropic_model.ps1
```

### Usage

```powershell
# Activate venv if not already active
.\venv\Scripts\Activate.ps1

# Run the interactive agent
python procmon_chat_agent.py
```

## Interactive Commands

| Command | Description |
|---------|-------------|
| `start` | Begin a new Procmon capture with scenario-based filters |
| `stop` | Stop a manual (untimed) capture |
| `convert` | Convert PML to CSV and show summary |
| `load` | Load an existing CSV or PML file |
| `chat` | Chat with AI about the capture |
| `stats` | Show capture statistics |
| `report` | Generate Excel report |
| `quit` | Exit the agent |

## Example Session

```
[agent] Command: start
Enter choice [malware]: software_install
Duration in seconds (empty for manual):
Target process (e.g., notepad.exe) [optional]: ccsetup

[info] Procmon running. Use 'stop' when done, then 'convert'.

[agent] Command: stop
[info] Procmon stopped.

[agent] Command: convert
Process filter (optional):

======================================================================
CAPTURE SUMMARY
======================================================================
CSV File: C:\ProgramData\Procmon\capture.csv
Total Events: 12847

--- Top Operations ---
  RegQueryValue: 4521
  ReadFile: 2103
  CreateFile: 1847
  RegOpenKey: 1234

--- Top Processes ---
  ccsetup639.exe: 8432
  msiexec.exe: 2341
  explorer.exe: 874
======================================================================

[agent] Command: chat

============================================================
CSV CHAT - Procmon Analysis
============================================================
Commands:
  Type a question to ask Claude
  'registry' - Analyze registry changes
  'files'    - Analyze file operations
  'network'  - Analyze network activity
  'processes'- Analyze process creation
  'search <pattern>' - Search for path pattern
  'quit'     - Exit
============================================================

You: What registry persistence was set up?
Claude: Based on the registry operations, I found the following persistence:

1. **Run Key**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
   - Value: "CCleaner" -> "C:\Program Files\CCleaner\CCleaner64.exe /MONITOR"

2. **Scheduled Task Registration**:
   - Task: CCleaner Update
   - Trigger: Daily at startup

You: search schtasks
Claude: Found 3 schtasks-related events:
  - ccsetup639.exe created scheduled task "CCleaner Update"
  - Task XML written to C:\Windows\System32\Tasks\CCleaner Update

You: quit
```

## Analysis Scenarios

| Scenario | Focus Areas |
|----------|-------------|
| `malware` | File writes, registry persistence, network connections, process creation, DLL loading |
| `software_install` | Installer activity, registry changes, file deployment, service creation |
| `file_tracking` | All file operations (create, read, write, delete, rename) |
| `network` | TCP/UDP connections, sends, receives |
| `privilege_escalation` | Sensitive file writes, registry modifications |
| `custom` | General-purpose capture with default noise filtering |

## Architecture

```
ProcmonAI/
├── procmon_chat_agent.py    # Main interactive CLI
├── pml_to_csv.py            # PML to CSV converter (Procmon-compatible format)
├── csv_chat.py              # CSV-based AI chat with filtered queries
├── procmon_runner.py        # Procmon process control
├── procmon_filters.py       # Scenario-based PMC filter generation
├── procmon_report.py        # Excel report generation
├── procmon-parser/          # PML/PMC file format library (submodule)
├── assets/                  # Bundled Procmon executables
└── requirements.txt
```

## Python API

Use ProcmonAI programmatically:

```python
from pml_to_csv import convert_pml_to_csv, filter_csv_rows, format_rows_for_ai
from csv_chat import CSVChat

# Convert PML to CSV
csv_path = convert_pml_to_csv(
    r"C:\ProgramData\Procmon\capture.pml",
    process_filter="ccsetup"
)

# Filter specific events
registry_rows = filter_csv_rows(csv_path, operation="RegSetValue", limit=100)
print(f"Found {len(registry_rows)} registry modifications")

# Chat with AI
chat = CSVChat(csv_path)
print(chat.ask("What persistence mechanisms were installed?"))
print(chat.analyze_registry())
print(chat.search("schtasks"))

# Direct category analysis
print(chat.analyze_files("Were any executables written?"))
print(chat.analyze_network())
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Your Anthropic API key | Required |
| `ANTHROPIC_MODEL` | Claude model to use | `claude-3-5-haiku-20241022` |

### Setting API Key Permanently

```powershell
# Interactive setup (recommended)
.\set_anthropic_model.ps1

# Or set manually
[Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", "sk-ant-...", "User")
```

## Testing

```powershell
# Run the test suite
python test_chat.py
```

The test validates:
- Event extraction from PML files
- Multi-turn conversation with context retention
- Conversation history management

## Troubleshooting

### "ANTHROPIC_API_KEY is not set"
```powershell
# Check if set
$env:ANTHROPIC_API_KEY

# If empty, run setup
.\set_anthropic_model.ps1
```

### "No module named 'procmon_parser'"
```powershell
# Ensure venv is activated
.\venv\Scripts\Activate.ps1

# Reinstall dependencies
pip install -r requirements.txt
```

### Empty capture / No events
- Verify Procmon window appeared during capture
- Try without process filter first
- Use `inspect` command to see raw PML contents

### Rate limit errors (429)
- The summary-first architecture dramatically reduces token usage
- Each category query sends only ~100-150 events instead of full capture
- If still hitting limits, use shorter category limits in chat

## Requirements

- **anthropic** >= 0.38.0 - Claude API client
- **pandas** >= 2.1.0 - Data processing for reports
- **rich** >= 13.7.0 - Terminal formatting
- **procmon-parser** - PML/PMC file parsing (bundled)

## License

MIT License - See LICENSE file for details.

## Acknowledgments

- [Sysinternals Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) by Mark Russinovich
- [procmon-parser](https://github.com/eronnen/procmon-parser) for PML file parsing
- [Anthropic Claude](https://www.anthropic.com/) for AI-powered analysis
