"""
Multi-turn chat interface for Procmon trace analysis with Claude.

This module provides a conversational interface where Claude maintains
context across multiple questions about the same capture.

Uses semantic search (via semtools) to send only relevant events per question,
dramatically reducing token usage and avoiding rate limits.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from anthropic import Anthropic, APIError

# Path to semtools search binary - check multiple locations
def _get_semtools_paths() -> list:
    """Get list of possible semtools search binary paths."""
    paths = []

    # 1. Local project copy (bundled)
    paths.append(os.path.join(os.path.dirname(__file__), "semtools", "bin", "search.exe"))

    # 2. npm global install location (Windows)
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        paths.append(os.path.join(appdata, "npm", "node_modules", "@llamaindex", "semtools", "dist", "bin", "search.exe"))

    # 3. npm prefix location (cross-platform)
    try:
        import subprocess
        result = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            npm_root = result.stdout.strip()
            paths.append(os.path.join(npm_root, "@llamaindex", "semtools", "dist", "bin", "search.exe"))
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        pass

    # 4. In PATH
    paths.append("search")
    paths.append("search.exe")

    return paths

SEMTOOLS_SEARCH_PATHS = _get_semtools_paths()

SYSTEM_PROMPT_TEMPLATE = """You are a security analysis assistant specialized in interpreting Process Monitor (Procmon) captures.

You help users understand what happened during a Windows system capture by analyzing file operations, registry changes, network activity, and process behavior.

Guidelines:
- Be specific: cite exact file paths, registry keys, process names, and operation counts
- Highlight security-relevant findings with [CRITICAL], [WARNING], or [INFO] tags
- When asked about specific processes, focus on their activities
- Explain technical concepts when the user seems unfamiliar
- Suggest follow-up questions or investigation steps when appropriate
- If you don't have enough information to answer, say so clearly

CAPTURE SUMMARY:
{capture_summary}

The user will ask questions about this capture. For each question, you'll receive semantically relevant events. Use both the summary above and the provided events to answer."""


def find_search_binary() -> Optional[str]:
    """Find the semtools search binary."""
    for path in SEMTOOLS_SEARCH_PATHS:
        if os.path.isfile(path):
            # Verify it's actually executable by testing it
            try:
                result = subprocess.run(
                    [path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
                continue
    return None


class ProcmonChat:
    """
    Multi-turn chat session for analyzing Procmon captures with Claude.

    Uses a hybrid approach:
    1. Compact summary in system prompt (always available to Claude)
    2. Semantic search to find relevant events per question
    3. Only sends matching events, not the full capture

    This dramatically reduces token usage from ~50k to ~10k per request.
    """

    def __init__(self, model: Optional[str] = None):
        """Initialize chat session."""
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set in the environment.")

        self.client = Anthropic(api_key=api_key)
        self.model = model or os.environ.get("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")
        self.messages: List[Dict[str, str]] = []
        self.capture_loaded = False
        self.capture_summary = ""
        self.events_file: Optional[str] = None  # Temp file for semantic search
        self.raw_events: List[Dict[str, Any]] = []  # Keep events for fallback
        self.search_binary = find_search_binary()

    def load_capture(self, raw_events_data: Dict[str, Any], scenario: str = "") -> str:
        """
        Load a Procmon capture into the chat context.

        Creates a compact summary for the system prompt and indexes events
        for semantic search.

        Args:
            raw_events_data: Output from procmon_raw_extractor.extract_raw_events()
            scenario: Analysis scenario (malware, file_tracking, etc.)

        Returns:
            Claude's initial analysis/greeting
        """
        # Build compact summary (NOT full events)
        self.capture_summary = self._build_summary(raw_events_data, scenario)

        # Store events for semantic search
        self.raw_events = raw_events_data.get('events', [])

        # Create temp file with events for semantic search
        self._create_events_index(raw_events_data)

        # Build system prompt with summary
        system_prompt = SYSTEM_PROMPT_TEMPLATE.format(capture_summary=self.capture_summary)

        # Get sample of interesting events for initial analysis
        sample_events = self._get_sample_events(raw_events_data, max_events=50)

        initial_message = f"""I've loaded a Procmon capture. Here's a sample of notable events:

{sample_events}

Please provide a brief overview of what you see, highlighting the most significant activities and any potential security concerns."""

        self.messages = [{"role": "user", "content": initial_message}]

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=system_prompt,
                messages=self.messages,
            )

            assistant_message = self._extract_text(response)
            self.messages.append({"role": "assistant", "content": assistant_message})
            self.capture_loaded = True

            return assistant_message

        except APIError as e:
            raise RuntimeError(f"Claude API error: {e}") from e

    def ask(self, question: str) -> str:
        """
        Ask a question about the loaded capture.

        Uses semantic search to find relevant events, then sends only
        those events to Claude along with the question.

        Args:
            question: Natural language question about the capture

        Returns:
            Claude's response
        """
        if not self.capture_loaded:
            raise RuntimeError("No capture loaded. Call load_capture() first.")

        # Find relevant events using semantic search
        relevant_events = self._semantic_search(question, max_results=75)

        # Build question with relevant context
        if relevant_events:
            user_content = f"""Question: {question}

Relevant events from the capture:
{relevant_events}"""
        else:
            user_content = question

        # Add to history
        self.messages.append({"role": "user", "content": user_content})

        # Build system prompt with summary
        system_prompt = SYSTEM_PROMPT_TEMPLATE.format(capture_summary=self.capture_summary)

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=system_prompt,
                messages=self.messages,
            )

            assistant_message = self._extract_text(response)
            self.messages.append({"role": "assistant", "content": assistant_message})

            return assistant_message

        except APIError as e:
            # Remove the failed question from history
            self.messages.pop()
            raise RuntimeError(f"Claude API error: {e}") from e

    def _build_summary(self, raw_data: Dict[str, Any], scenario: str) -> str:
        """Build a compact summary for the system prompt."""
        lines = [
            f"Total Events: {raw_data['total_events']}",
            f"Unique Processes: {len(raw_data['unique_processes'])}",
        ]

        if scenario:
            lines.append(f"Analysis Scenario: {scenario}")

        if raw_data.get('process_filter'):
            lines.append(f"Process Filter: {raw_data['process_filter']}")

        lines.append("\nEvent Distribution:")
        for category, count in raw_data.get('event_categories', {}).items():
            if count > 0:
                lines.append(f"  {category}: {count}")

        lines.append("\nProcesses Observed:")
        for proc in raw_data.get('unique_processes', [])[:20]:
            lines.append(f"  - {proc}")

        lines.append("\nMost Active Processes:")
        for proc in raw_data.get('top_processes', [])[:10]:
            lines.append(f"  {proc['process']}: {proc['count']} events")

        return "\n".join(lines)

    def _get_sample_events(self, raw_data: Dict[str, Any], max_events: int = 50) -> str:
        """Get a sample of interesting events for initial analysis."""
        events = raw_data.get('events', [])

        # Prioritize interesting operations
        priority_ops = ['CreateFile', 'WriteFile', 'RegSetValue', 'Process Create',
                       'TCP Connect', 'UDP Send', 'Load Image']

        prioritized = []
        other = []

        for event in events:
            op = event.get('operation', '')
            if any(p in op for p in priority_ops):
                prioritized.append(event)
            else:
                other.append(event)

        # Take mix of prioritized and other
        sample = prioritized[:max_events//2] + other[:max_events//2]
        sample = sample[:max_events]

        lines = []
        for event in sample:
            lines.append(
                f"{event['process']} | {event['operation']:<25} | {event['path'][:70]}"
            )

        return "\n".join(lines)

    def _create_events_index(self, raw_data: Dict[str, Any]) -> None:
        """Create a temporary file with events for semantic search."""
        events = raw_data.get('events', [])

        # Create temp file
        fd, self.events_file = tempfile.mkstemp(suffix='.txt', prefix='procmon_events_')

        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            for i, event in enumerate(events):
                # Format each event as a searchable line with index for retrieval
                # Include semantic hints for common search patterns
                parts = [f"[{i}]", event['process'], event['operation'], event['path']]

                # Add semantic context based on operation/path
                path_lower = event['path'].lower()
                op = event['operation'].lower()

                # Registry hints
                if 'reg' in op or path_lower.startswith('hk'):
                    parts.append("registry")
                    if 'run' in path_lower:
                        parts.append("startup autorun persistence")
                    if 'services' in path_lower:
                        parts.append("service")
                    if 'schedule' in path_lower or 'task' in path_lower:
                        parts.append("scheduled task")

                # File operation hints
                if 'createfile' in op or 'writefile' in op:
                    if '.exe' in path_lower or '.dll' in path_lower:
                        parts.append("executable binary")
                    if 'task' in path_lower or 'schedule' in path_lower:
                        parts.append("scheduled task")
                    if 'system32' in path_lower:
                        parts.append("system file")

                # Process hints
                if 'process' in op:
                    parts.append("process creation spawn")

                # Network hints
                if 'tcp' in op or 'udp' in op:
                    parts.append("network connection")

                detail = event.get('detail', '')
                if detail:
                    parts.append(detail)
                result = event.get('result', '')
                if result:
                    parts.append(result)

                f.write(" ".join(parts) + "\n")

    def _semantic_search(self, query: str, max_results: int = 75) -> str:
        """
        Search events using semantic similarity.

        Uses semtools search if available, falls back to keyword search.
        """
        if self.search_binary and self.events_file and os.path.exists(self.events_file):
            try:
                result = subprocess.run(
                    [
                        self.search_binary,
                        query,
                        self.events_file,
                        "--top-k", str(max_results),
                        "--n-lines", "0",  # Just the matching line
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                pass  # Fall back to keyword search

        # Fallback: simple keyword search
        return self._keyword_search(query, max_results)

    def _keyword_search(self, query: str, max_results: int = 75) -> str:
        """Fallback keyword-based search."""
        keywords = query.lower().split()

        matches = []
        for event in self.raw_events:
            event_text = f"{event['process']} {event['operation']} {event['path']}".lower()
            detail = str(event.get('detail', '')).lower()

            # Score by keyword matches
            score = sum(1 for kw in keywords if kw in event_text or kw in detail)
            if score > 0:
                matches.append((score, event))

        # Sort by score descending
        matches.sort(key=lambda x: x[0], reverse=True)

        lines = []
        for _, event in matches[:max_results]:
            lines.append(
                f"{event['process']} | {event['operation']:<25} | {event['path'][:70]}"
            )

        return "\n".join(lines)

    def get_conversation_length(self) -> int:
        """Return the number of messages in the conversation."""
        return len(self.messages)

    def clear(self) -> None:
        """Clear conversation history (keeps capture loaded)."""
        if self.capture_loaded and self.messages:
            # Keep only the initial capture message and response
            self.messages = self.messages[:2]

    def reset(self) -> None:
        """Fully reset the chat session."""
        self.messages = []
        self.capture_loaded = False
        self.capture_summary = ""
        self.raw_events = []
        if self.events_file and os.path.exists(self.events_file):
            try:
                os.remove(self.events_file)
            except OSError:
                pass
        self.events_file = None

    def __del__(self):
        """Cleanup temp files on deletion."""
        if hasattr(self, 'events_file') and self.events_file and os.path.exists(self.events_file):
            try:
                os.remove(self.events_file)
            except OSError:
                pass

    def _extract_text(self, response) -> str:
        """Extract text content from Claude response."""
        chunks = []
        for block in response.content:
            if block.type == "text":
                chunks.append(block.text)
        return "".join(chunks).strip()


def create_chat_session(model: Optional[str] = None) -> ProcmonChat:
    """Factory function to create a new chat session."""
    return ProcmonChat(model=model)


__all__ = ["ProcmonChat", "create_chat_session"]
