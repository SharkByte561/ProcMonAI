"""Test the new chat functionality with a real PML file."""

import os
import subprocess
import sys

# Load ANTHROPIC_API_KEY from Windows User environment if not already set
if not os.environ.get("ANTHROPIC_API_KEY"):
    result = subprocess.run(
        ["powershell", "-Command", "[Environment]::GetEnvironmentVariable('ANTHROPIC_API_KEY', 'User')"],
        capture_output=True, text=True
    )
    key = result.stdout.strip()
    if key:
        os.environ["ANTHROPIC_API_KEY"] = key
        print(f"[setup] Loaded API key from Windows User environment")

sys.path.insert(0, r"C:\Users\halexand\.claude-worktrees\ProcmonAI\silly-colden")

from procmon_raw_extractor import extract_raw_events
from ai_chat import ProcmonChat

PML_FILE = r"C:\ProgramData\Procmon\events_20251126_131211_test_notepad.pml"

def main():
    print("=" * 70)
    print("Testing ProcmonChat with real PML file")
    print("=" * 70)

    # Step 1: Extract events
    print(f"\n[1] Extracting events from: {PML_FILE}")
    raw_data = extract_raw_events(PML_FILE, process_filter="notepad", limit=2000)

    print(f"    Total events: {raw_data['total_events']}")
    print(f"    Unique processes: {len(raw_data['unique_processes'])}")
    print(f"    Event categories: {raw_data['event_categories']}")

    # Step 2: Start chat session
    print("\n[2] Starting chat session with Claude...")
    chat = ProcmonChat()

    # Step 3: Load capture and get initial analysis
    print("\n[3] Loading capture into chat...")
    initial = chat.load_capture(raw_data, scenario="file_tracking")

    print("\n" + "=" * 70)
    print("CLAUDE'S INITIAL ANALYSIS:")
    print("=" * 70)
    print(initial)

    # Step 4: Ask follow-up questions
    questions = [
        "What files did notepad write to?",
        "Were any files created on the Desktop?",
        "Summarize the most important findings in 3 bullet points.",
    ]

    for i, q in enumerate(questions, 1):
        print("\n" + "=" * 70)
        print(f"QUESTION {i}: {q}")
        print("=" * 70)
        answer = chat.ask(q)
        print(answer)

    print(f"\n[Done] Conversation length: {chat.get_conversation_length()} messages")


if __name__ == "__main__":
    main()
