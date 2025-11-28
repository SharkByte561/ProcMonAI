"""
Targeted AI chat for Procmon analysis.

Instead of sending full captures (which hit rate limits), this module
supports targeted queries on specific event categories. Each query
sends only relevant events, keeping context small.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from anthropic import Anthropic, APIError


SYSTEM_PROMPT = """You are a security analysis assistant specialized in interpreting Process Monitor (Procmon) data.

You help users understand Windows system activity by analyzing file operations, registry changes, network activity, and process behavior.

Guidelines:
- Be specific: cite exact file paths, registry keys, and process names
- Highlight security-relevant findings with [CRITICAL], [WARNING], or [INFO] tags
- Focus on the specific category of events provided
- If data seems incomplete, mention what additional information might help
- Be concise but thorough"""


class ProcmonChat:
    """
    Targeted chat for Procmon analysis.

    Each query receives only relevant events for that category,
    keeping token usage low and avoiding rate limits.
    """

    def __init__(self, model: Optional[str] = None):
        """Initialize chat session."""
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set in the environment.")

        self.client = Anthropic(api_key=api_key)
        self.model = model or os.environ.get("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")
        self.messages: List[Dict[str, str]] = []
        self.summary_context = ""  # Brief summary always included

    def set_summary(self, summary: str) -> None:
        """Set the brief summary context (should be small - just stats)."""
        self.summary_context = summary

    def ask(self, question: str, events: str = "") -> str:
        """
        Ask a question with optional event context.

        Args:
            question: User's question
            events: Formatted events relevant to the question (keep under 200)

        Returns:
            Claude's response
        """
        # Build the user message
        if events:
            user_content = f"""Context - Capture Summary:
{self.summary_context}

Relevant Events:
{events}

Question: {question}"""
        else:
            user_content = f"""Context - Capture Summary:
{self.summary_context}

Question: {question}"""

        # Add to history (but keep history short to avoid growing context)
        self.messages.append({"role": "user", "content": user_content})

        # Trim history if too long (keep last 4 exchanges)
        if len(self.messages) > 8:
            self.messages = self.messages[-8:]

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1500,
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

    def analyze_category(self, category: str, events: str, summary: str) -> str:
        """
        Analyze a specific category of events.

        This is a one-shot analysis - doesn't add to conversation history.
        """
        prompt = f"""Analyze these {category} events from a Procmon capture:

Capture Summary:
{summary}

{category} Events:
{events}

Provide a security-focused analysis highlighting:
1. Key findings
2. Any suspicious or notable activity
3. Potential security implications"""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1500,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            return self._extract_text(response)

        except APIError as e:
            raise RuntimeError(f"Claude API error: {e}") from e

    def clear(self) -> None:
        """Clear conversation history."""
        self.messages = []

    def get_conversation_length(self) -> int:
        """Return the number of messages in the conversation."""
        return len(self.messages)

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
