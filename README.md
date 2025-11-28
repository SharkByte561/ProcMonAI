# ProcmonAI

**Interactive Process Monitor analysis powered by Claude AI**

ProcmonAI lets you have natural language conversations with your Windows Process Monitor (Procmon) captures. Ask questions like "What files did this process create?" or "Show me suspicious registry modifications" and get intelligent, context-aware answers.

## Features

- **Summary-First Analysis**: Instant local summary shows key findings before asking AI questions
- **Category-Based Chat**: Ask AI questions about specific event types (registry, files, network, processes) without hitting rate limits
- **Automatic Detection**: Local summary highlights persistence mechanisms, scheduled tasks, and suspicious executables
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
| `summary` | Generate instant local summary (no AI, shows key findings) |
| `chat` | Start category-based Q&A with Claude |
| `report` | Generate Excel report |
| `inspect` | Debug: show raw process data in PML |
| `quit` | Exit the agent |

## Example Session

```
[agent] Command: start
Choose scenario:
  malware            - File writes, registry persistence, network, process creation
  software_install   - Installer activity, registry changes, file deployment
  file_tracking      - All file operations (create, read, write, delete)
  network            - TCP/UDP connections, sends, receives
  privilege_escalation - Sensitive file/registry modifications
  custom             - General-purpose with default noise filtering
Enter choice [malware]: file_tracking
Duration in seconds (empty for manual): 30
Target process (e.g., notepad.exe) [optional]: notepad.exe

[info] Procmon running for 30s. Perform your activity.

[agent] Command: summary
Process filter (optional): notepad

======================================================================
CAPTURE SUMMARY
======================================================================
File: C:\ProgramData\Procmon\capture_file_tracking_20241128_143052.pml
Total Events: 847

--- Event Counts by Category ---
  File Creates: 12
  File Writes: 45
  Registry Sets: 8

--- Key Findings ---
[!] Executable Files Written (1):
    C:\Users\...\AppData\Local\Temp\~notepad.tmp

======================================================================

Tip: Use 'chat' to ask AI about specific categories!

[agent] Command: chat

======================================================================
AI CHAT - Ask questions about the capture
======================================================================
Commands:
  Type a question to ask Claude (relevant events auto-selected)
  'registry' - Analyze registry changes
  'files'    - Analyze file operations
  'network'  - Analyze network activity
  'processes'- Analyze process creation
  'done'     - Exit chat
======================================================================

You: files
Claude: [INFO] File Operations Analysis:
  Notepad.exe created the following files:
  1. C:\Users\...\Documents\notes.txt (WriteFile operations)
  2. C:\Users\...\AppData\Local\Temp\~notepad.tmp (temporary file)
...

You: done
[Leaving chat mode]
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
├── procmon_chat_agent.py    # Main interactive CLI (summary-first flow)
├── procmon_summary.py       # Local summary generator (no AI, instant)
├── ai_chat.py               # Category-based chat with Claude API
├── procmon_runner.py        # Procmon process control
├── procmon_filters.py       # Scenario-based PMC filter generation
├── procmon_raw_extractor.py # PML file parsing and event extraction
├── procmon_report.py        # Excel report generation
├── procmon-parser/          # PML/PMC file format library (submodule)
├── assets/                  # Bundled Procmon executables
└── requirements.txt
```

## Python API

Use ProcmonAI programmatically:

```python
from procmon_summary import extract_categorized_events, get_category_events, format_events_for_ai
from ai_chat import ProcmonChat

# Load and categorize events from PML capture
data = extract_categorized_events(
    r"C:\ProgramData\Procmon\capture.pml",
    process_filter="notepad"
)

# See what's in the capture
print(f"Total events: {data['total_events']}")
print(f"Registry creates: {data['category_counts']['Registry Creates']}")
print(f"File writes: {data['category_counts']['File Writes']}")

# Start targeted chat session
chat = ProcmonChat()
chat.set_summary(f"Total: {data['total_events']} events")

# Ask about specific categories
registry_events = get_category_events(data, "registry", limit=100)
events_text = format_events_for_ai(registry_events)
print(chat.ask("What registry persistence was set up?", events=events_text))

# Clear history for next category
chat.clear()
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
