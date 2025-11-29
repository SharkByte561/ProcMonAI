# ProcmonAI

**Interactive Process Monitor analysis powered by Claude AI and SQL**

ProcmonAI lets you have natural language conversations with your Windows Process Monitor (Procmon) captures. Ask questions like "What files did this process create?" or "Show me suspicious registry modifications" and get intelligent, context-aware answers powered by SQL queries.

## Features

- **SQL-Powered Analysis**: Natural language questions are translated to DuckDB SQL queries for precise results
- **CSV-First Workflow**: Convert PML to CSV for portable, searchable analysis
- **Smart AI Chat**: Ask questions in plain English - Claude generates SQL, DuckDB executes it
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
| `chat` | Chat with AI using SQL queries |
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
SQL CHAT - Procmon Analysis with DuckDB
============================================================
Commands:
  Type a question - Claude translates to SQL and runs it
  'sql <query>'   - Run raw SQL directly
  'schema'        - Show CSV columns
  'sample'        - Show sample data
  'clear'         - Clear conversation history
  'quit'          - Exit
============================================================

You: Where was CCleaner installed?
SQL: SELECT DISTINCT Path FROM '...' WHERE "Process Name" ILIKE '%ccsetup%'
     AND Operation = 'CreateFile' AND Path ILIKE '%Program Files%'

Results: 5 rows

Based on the query results, CCleaner was installed to:
- C:\Program Files\CCleaner\CCleaner64.exe
- C:\Program Files\CCleaner\CCleaner.exe
- C:\Program Files\CCleaner\uninst.exe
...

You: sql SELECT count(*) FROM 'capture.csv' WHERE Operation = 'RegSetValue'

Results (1 rows):
{'count_star()': 234}

You: quit
```

## How SQL Chat Works

1. **You ask a question** in natural language
2. **Claude generates SQL** based on your question and the CSV schema
3. **DuckDB executes** the SQL query locally (fast, no data leaves your machine)
4. **Claude analyzes** the results and provides security insights

This approach provides:
- **Precise queries**: SQL can find exact matches, not just keyword approximations
- **Low token usage**: Only query results are sent to Claude, not raw data
- **Transparency**: You can see and modify the SQL queries
- **Power user mode**: Run raw SQL with `sql <query>` command

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
├── sql_chat.py              # SQL-powered AI chat (NEW!)
├── nl_to_sql.py             # Natural language to SQL translation
├── duckdb_query.py          # DuckDB query execution via PSDuckDB
├── pml_to_csv.py            # PML to CSV converter
├── csv_chat.py              # Fallback CSV-based chat
├── procmon_runner.py        # Procmon process control
├── procmon_filters.py       # Scenario-based PMC filter generation
├── procmon_report.py        # Excel report generation
├── PSDuckDB/                # PowerShell DuckDB module
├── procmon-parser/          # PML/PMC file format library
├── assets/                  # Bundled Procmon executables
└── requirements.txt
```

## Python API

Use ProcmonAI programmatically:

```python
from pml_to_csv import convert_pml_to_csv
from sql_chat import SQLChat
from duckdb_query import run_sql, find_registry_modifications

# Convert PML to CSV
csv_path = convert_pml_to_csv(
    r"C:\ProgramData\Procmon\capture.pml",
    process_filter="ccsetup"
)

# Run direct SQL queries
results = run_sql(f"""
    SELECT "Process Name", Path, Result
    FROM '{csv_path}'
    WHERE Operation = 'CreateFile'
    AND Path ILIKE '%Program Files%'
    LIMIT 50
""")

# Use helper functions
registry_mods = find_registry_modifications(csv_path)
print(f"Found {len(registry_mods)} registry modifications")

# Chat with AI (NL → SQL → Results → Analysis)
chat = SQLChat(csv_path)
print(chat.ask("What persistence mechanisms were installed?"))

# Get SQL and results separately
sql, results = chat.query("Find all .exe files created")
print(f"Generated SQL: {sql}")
print(f"Results: {len(results)} rows")
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
# Run the DuckDB integration tests
python test_duckdb.py

# Run the full test suite
python test_chat.py
```

The test validates:
- DuckDB query execution via PSDuckDB
- CSV file querying and filtering
- Natural language to SQL translation
- Full chat workflow

## Troubleshooting

### "ANTHROPIC_API_KEY is not set"
```powershell
# Check if set
$env:ANTHROPIC_API_KEY

# If empty, run setup
.\set_anthropic_model.ps1
```

### "PSDuckDB module not found"
Ensure the PSDuckDB folder exists in the project directory. If not:
```powershell
# Install from PowerShell Gallery
Install-Module PSDuckDB -Scope CurrentUser
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
- SQL-powered chat dramatically reduces token usage
- Only query results are sent to Claude, not raw CSV data
- Each query typically uses <5k tokens

## Requirements

- **anthropic** >= 0.38.0 - Claude API client
- **pandas** >= 2.1.0 - Data processing for reports
- **rich** >= 13.7.0 - Terminal formatting
- **procmon-parser** - PML/PMC file parsing (bundled)
- **PSDuckDB** - PowerShell DuckDB module (bundled)

## License

MIT License - See LICENSE file for details.

## Acknowledgments

- [Sysinternals Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) by Mark Russinovich
- [procmon-parser](https://github.com/eronnen/procmon-parser) for PML file parsing
- [DuckDB](https://duckdb.org/) for fast analytical SQL
- [PSDuckDB](https://github.com/dfinke/PSDuckDB) PowerShell module by Doug Finke
- [Anthropic Claude](https://www.anthropic.com/) for AI-powered analysis
