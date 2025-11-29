"""
Multi-turn chat interface for Procmon trace analysis with Claude.

This module provides a conversational interface where Claude maintains
context across multiple questions about the same capture.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from anthropic import Anthropic, APIError

SYSTEM_PROMPT = """You are a security analysis assistant specialized in interpreting Process Monitor (Procmon) captures.

You help users understand what happened during a Windows system capture by analyzing file operations, registry changes, network activity, and process behavior.

Guidelines:
- Be specific: cite exact file paths, registry keys, process names, and operation counts
- Highlight security-relevant findings with [CRITICAL], [WARNING], or [INFO] tags
- When asked about specific processes, focus on their activities
- Explain technical concepts when the user seems unfamiliar
- Suggest follow-up questions or investigation steps when appropriate
- If you don't have enough information to answer, say so clearly

You have access to the captured Procmon events provided at the start of the conversation. Reference this data when answering questions."""


class ProcmonChat:
    """
    Multi-turn chat session for analyzing Procmon captures with Claude.

    Maintains conversation history so Claude can reference prior questions
    and provide contextual follow-up answers.
    """

    def __init__(self, model: Optional[str] = None):
        """Initialize chat session."""
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set in the environment.")

        self.client = Anthropic(api_key=api_key)
        self.model = model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
        self.messages: List[Dict[str, str]] = []
        self.capture_loaded = False
        self.capture_summary = ""

    def load_capture(self, raw_events_data: Dict[str, Any], scenario: str = "") -> str:
        """
        Load a Procmon capture into the chat context.

        This formats the capture data and sends it to Claude as the first message,
        establishing the context for all subsequent questions.

        Args:
            raw_events_data: Output from procmon_raw_extractor.extract_raw_events()
            scenario: Analysis scenario (malware, file_tracking, etc.)

        Returns:
            Claude's initial analysis/greeting
        """
        # Build capture summary for Claude
        self.capture_summary = self._format_capture_data(raw_events_data, scenario)

        # Create initial user message with capture data
        initial_message = f"""I have a Procmon capture I'd like to analyze. Here's the data:

{self.capture_summary}

Please provide a brief overview of what you see in this capture, highlighting the most significant activities and any potential security concerns. Then I'll ask you specific questions about it."""

        # Send to Claude and get initial analysis
        self.messages = [{"role": "user", "content": initial_message}]

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=SYSTEM_PROMPT,
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

        Maintains conversation history so Claude can reference prior
        questions and answers.

        Args:
            question: Natural language question about the capture

        Returns:
            Claude's response
        """
        if not self.capture_loaded:
            raise RuntimeError("No capture loaded. Call load_capture() first.")

        # Add user question to history
        self.messages.append({"role": "user", "content": question})

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=SYSTEM_PROMPT,
                messages=self.messages,
            )

            assistant_message = self._extract_text(response)
            self.messages.append({"role": "assistant", "content": assistant_message})

            return assistant_message

        except APIError as e:
            # Remove the failed question from history
            self.messages.pop()
            raise RuntimeError(f"Claude API error: {e}") from e

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

    def _format_capture_data(self, raw_data: Dict[str, Any], scenario: str) -> str:
        """Format capture data for Claude."""
        lines = [
            "=" * 60,
            "PROCMON CAPTURE DATA",
            "=" * 60,
            "",
            f"Total Events: {raw_data['total_events']}",
            f"Unique Processes: {len(raw_data['unique_processes'])}",
        ]

        if scenario:
            lines.append(f"Analysis Scenario: {scenario}")

        if raw_data.get('process_filter'):
            lines.append(f"Process Filter: {raw_data['process_filter']}")

        if raw_data.get('truncated'):
            lines.append(f"Note: Showing first 1000 of {raw_data['total_events']} events")

        lines.extend(["", "Event Distribution:"])
        for category, count in raw_data.get('event_categories', {}).items():
            if count > 0:
                lines.append(f"  {category}: {count}")

        lines.extend(["", "Most Active Processes:"])
        for proc in raw_data.get('top_processes', [])[:10]:
            lines.append(f"  {proc['process']}: {proc['count']} events")

        lines.extend(["", "-" * 60, "Event Details:", "-" * 60])

        for event in raw_data.get('events', []):
            lines.append(
                f"{event['process']} | {event['operation']:<30} | {event['path'][:60]}"
            )
            result = event.get('result', '')
            if result and str(result).lower() != 'success':
                lines.append(f"  -> Result: {result}")
            detail = event.get('detail', '')
            if detail:
                # Truncate very long details
                detail_str = str(detail)[:100]
                if len(str(detail)) > 100:
                    detail_str += "..."
                lines.append(f"  -> Detail: {detail_str}")

        return "\n".join(lines)

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
