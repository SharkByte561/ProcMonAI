# Changelog

All notable changes to ProcmonAI will be documented in this file.

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
