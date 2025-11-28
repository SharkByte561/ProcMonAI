"""
Multi-turn chat interface for Procmon trace analysis with Claude.

This module provides a conversational interface where Claude maintains
context across multiple questions about the same capture.

Uses Anthropic's prompt caching to efficiently handle large capture data -
the full event list is sent once in the system prompt and cached for
subsequent questions.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from anthropic import Anthropic, APIError


SYSTEM_PROMPT_TEMPLATE = """You are a security analysis assistant specialized in interpreting Process Monitor (Procmon) captures.

You help users understand what happened during a Windows system capture by analyzing file operations, registry changes, network activity, and process behavior.

Guidelines:
- Be specific: cite exact file paths, registry keys, process names, and operation counts
- Highlight security-relevant findings with [CRITICAL], [WARNING], or [INFO] tags
- When asked about specific processes, focus on their activities
- Explain technical concepts when the user seems unfamiliar
- Suggest follow-up questions or investigation steps when appropriate
- If you don't have enough information to answer, say so clearly

CAPTURE DATA:
{capture_data}"""


class ProcmonChat:
    """
    Multi-turn chat session for analyzing Procmon captures with Claude.

    Uses Anthropic's prompt caching - the full capture is included in the
    system prompt which gets cached after the first request. This means:
    - First request: full tokens charged
    - Subsequent requests: only new question tokens charged

    This is simpler and more reliable than semantic search approaches.
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
        self.system_prompt = ""

    def load_capture(self, raw_events_data: Dict[str, Any], scenario: str = "") -> str:
        """
        Load a Procmon capture into the chat context.

        The full capture data is embedded in the system prompt, which
        Anthropic caches automatically for subsequent requests.

        Args:
            raw_events_data: Output from procmon_raw_extractor.extract_raw_events()
            scenario: Analysis scenario (malware, file_tracking, etc.)

        Returns:
            Claude's initial analysis/greeting
        """
        # Build the full capture data for the system prompt
        capture_data = self._format_capture_data(raw_events_data, scenario)

        # Build system prompt with full capture (will be cached)
        self.system_prompt = SYSTEM_PROMPT_TEMPLATE.format(capture_data=capture_data)

        # Initial message asking for overview
        initial_message = "Please provide a brief overview of this capture, highlighting the most significant activities and any potential security concerns."

        self.messages = [{"role": "user", "content": initial_message}]

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=self.system_prompt,
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

        The system prompt (with full capture) is cached by Anthropic,
        so only the new question tokens are charged.

        Args:
            question: Natural language question about the capture

        Returns:
            Claude's response
        """
        if not self.capture_loaded:
            raise RuntimeError("No capture loaded. Call load_capture() first.")

        # Add question to history
        self.messages.append({"role": "user", "content": question})

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=self.system_prompt,
                messages=self.messages,
            )

            assistant_message = self._extract_text(response)
            self.messages.append({"role": "assistant", "content": assistant_message})

            return assistant_message

        except APIError as e:
            # Remove the failed question from history
            self.messages.pop()
            raise RuntimeError(f"Claude API error: {e}") from e

    def _format_capture_data(self, raw_data: Dict[str, Any], scenario: str) -> str:
        """Format the full capture data for the system prompt."""
        lines = []

        # Summary section
        lines.append("=== SUMMARY ===")
        lines.append(f"Total Events: {raw_data['total_events']}")
        lines.append(f"Unique Processes: {len(raw_data['unique_processes'])}")

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

        # Full events section
        lines.append("\n=== ALL EVENTS ===")
        lines.append("Process | Operation | Path | Detail | Result")
        lines.append("-" * 80)

        for event in raw_data.get('events', []):
            process = event.get('process', '')
            operation = event.get('operation', '')
            path = event.get('path', '')
            detail = event.get('detail', '')
            result = event.get('result', '')

            # Truncate very long paths/details to keep tokens reasonable
            if len(path) > 100:
                path = path[:97] + "..."
            if len(detail) > 80:
                detail = detail[:77] + "..."

            lines.append(f"{process} | {operation} | {path} | {detail} | {result}")

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
        self.system_prompt = ""

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
