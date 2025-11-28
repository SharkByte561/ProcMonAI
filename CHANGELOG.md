# Changelog

All notable changes to ProcmonAI will be documented in this file.

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
