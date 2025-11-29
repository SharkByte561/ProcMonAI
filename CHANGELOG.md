# Changelog

All notable changes to ProcmonAI will be documented in this file.

## [1.4.0] - 2025-11-29

### Changed

- **SQL-Powered Analysis**: Complete redesign using DuckDB for precise queries
  - Natural language questions are translated to SQL by Claude
  - SQL executed locally via DuckDB/PSDuckDB - data never leaves your machine
  - Results analyzed by Claude for security insights
  - Dramatically reduces token usage - only results sent to AI, not raw data

### Added

- `sql_chat.py` - SQL-based AI chat
  - Natural language → SQL → DuckDB → Analysis workflow
  - Raw SQL mode with `sql <query>` command
  - Schema exploration with `schema` command
  - Full conversation history for follow-up questions
- `nl_to_sql.py` - Natural language to SQL translator
  - Dynamically discovers CSV schema
  - Provides sample data context to Claude
  - Generates DuckDB-compatible SQL
- `duckdb_query.py` - DuckDB query execution wrapper
  - Calls PSDuckDB PowerShell module from Python
  - Helper functions for common Procmon queries
  - Support for direct SQL execution
- `test_duckdb.py` - Integration test suite

### Technical

- Integrates with PSDuckDB PowerShell module for DuckDB access
- Schema-aware query generation with column and value samples
- Supports complex SQL queries (JOIN, GROUP BY, aggregations)
- CSV path normalization for cross-platform compatibility

## [1.3.0] - 2024-11-28

### Changed

- **CSV-First Architecture**: Complete redesign using CSV as the primary format
  - PML → CSV conversion using procmon-parser's native export format
  - CSV files are portable, searchable, and can be opened in Excel
  - AI chat queries filter CSV rows directly instead of re-parsing PML

### Added

- `pml_to_csv.py` - PML to CSV converter
  - Identical format to Procmon's native "Save As CSV"
  - Optional process filter during conversion
  - Includes all Procmon columns (27 total)
- `csv_chat.py` - CSV-based AI chat
  - Auto-detects relevant events from question keywords
  - Category shortcuts: `registry`, `files`, `network`, `processes`
  - `search <pattern>` for path-based queries
  - Efficient row filtering keeps token usage low
- New commands: `convert`, `load`, `stats`

### Technical

- Uses procmon-parser's `get_compatible_csv_info()` for accurate export
- Filters CSV rows before sending to Claude (max 150 per query)
- Multi-turn conversation with automatic history trimming

## [1.2.0] - 2024-11-28

### Changed

- **Summary-First Architecture**: Redesigned to avoid API rate limits
  - Local summary generation (instant, no AI) shows key findings immediately
  - AI chat now uses targeted category queries instead of full capture context
  - Each question sends only relevant events (max 150) for that category
  - Auto-detects categories from question keywords (registry, files, network, processes)

### Added

- `procmon_summary.py` - Structured summary generator with:
  - Categorized event extraction (registry, files, network, processes, DLLs)
  - Automatic detection of persistence mechanisms
  - Scheduled task activity highlighting
  - Executable file write detection
  - Top processes analysis
- New `summary` command for instant local analysis
- Category shortcuts in chat: `registry`, `files`, `network`, `processes`, `dlls`

### Technical

- Reduced token usage from ~50k to ~5-10k per request
- Conversation history trimmed to last 4 exchanges
- Category-aware context selection

## [1.1.0] - 2024-11-28

### Changed

- **Simplified Architecture**: Replaced semantic search (SemTools) with Anthropic's native prompt caching
  - Full capture data now included in system prompt (cached after first request)
  - Removes Node.js dependency
  - More reliable - Claude sees all events, not just search results
  - Simpler codebase with fewer moving parts

### Removed

- SemTools semantic search integration (no longer needed with prompt caching)
- Node.js prerequisite

## [1.0.0] - 2024-11-28

### New Features

- **Natural Language Chat**: Have conversations with your Procmon captures - ask questions like "What files did this process create?" and get intelligent, context-aware answers

- **Multi-turn Conversations**: Claude remembers context across questions, so you can ask follow-ups naturally without repeating yourself

- **Scenario-based Capture Filtering**: Pre-configured filters for common analysis scenarios:
  - Malware analysis
  - Software installation tracking
  - File operation monitoring
  - Network activity
  - Privilege escalation detection

- **Interactive CLI**: Simple command interface with `start`, `stop`, `chat`, `analyze`, `report`, and `inspect` commands

- **Excel Report Generation**: Export capture analysis to spreadsheet format for further investigation

- **Automated Procmon Control**: Start and stop captures programmatically with custom duration and filters

### Technical

- PML file parsing via procmon-parser library
- Bundled Procmon executables (32-bit and 64-bit)
- Haiku model by default for fast, cost-effective responses
