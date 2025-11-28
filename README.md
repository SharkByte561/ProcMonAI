# ProcmonAI

**Interactive Process Monitor analysis powered by Claude AI**

ProcmonAI lets you have natural language conversations with your Windows Process Monitor (Procmon) captures. Ask questions like "What files did this process create?" or "Show me suspicious registry modifications" and get intelligent, context-aware answers.

## Features

- **Multi-turn Conversations**: Claude remembers context across questions - ask follow-ups naturally
- **Prompt Caching**: Capture data is cached by Anthropic after the first request, making follow-up questions fast and cost-effective
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
| `chat` | Start interactive Q&A with Claude about the capture |
| `analyze` | Quick one-shot analysis |
| `report` | Generate Excel report |
| `inspect` | Debug: show raw process data in PML |
| `quit` | Exit the agent |

## Example Session

```
[agent] Command: start
Scenario (malware/software_install/file_tracking/network/privilege_escalation/custom) [malware]: file_tracking
Duration in seconds (empty for manual): 30
Target process (e.g., notepad.exe) [optional]: notepad.exe

[info] Procmon running for 30s. Perform your activity.

[agent] Command: chat
Process filter (optional): notepad
[info] Loading capture...

======================================================================
CLAUDE'S INITIAL ANALYSIS
======================================================================
Based on the capture, I can see Notepad.exe performed 847 operations...

[INFO] Most file activity occurred in the user's Documents folder...
======================================================================

You: What files did notepad create?
Claude: Notepad.exe created the following files:
  1. C:\Users\...\Documents\notes.txt (WriteFile operations)
  2. C:\Users\...\AppData\Local\Temp\~DF4A2B.tmp (temporary file)
...

You: Were any of those on the Desktop?
Claude: Looking at the files I mentioned, none were on the Desktop...

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
├── procmon_chat_agent.py    # Main interactive CLI
├── ai_chat.py               # Multi-turn chat with Claude API (prompt caching)
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
from procmon_raw_extractor import extract_raw_events
from ai_chat import ProcmonChat

# Load an existing PML capture
raw_data = extract_raw_events(
    r"C:\ProgramData\Procmon\capture.pml",
    process_filter="notepad",
    limit=2000
)

# Start chat session
chat = ProcmonChat()
print(chat.load_capture(raw_data, scenario="file_tracking"))

# Ask questions
print(chat.ask("What files were modified?"))
print(chat.ask("Show me any registry changes"))

# Clear history but keep capture loaded
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
- The Haiku model has a 50k tokens/minute limit
- Reduce event limit: `extract_raw_events(..., limit=500)`
- Add delays between rapid API calls

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
