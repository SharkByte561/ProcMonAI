#!/usr/bin/env python
"""
Test script for ProcmonAI multi-turn chat.

Usage:
    cd X:\ProcmonAI
    .\venv\Scripts\python.exe test_chat.py

Requirements:
    - ANTHROPIC_API_KEY environment variable set
    - A PML file to analyze (uses default test file)
"""

import os
import sys
import time

# Default test PML file
DEFAULT_PML = r"C:\ProgramData\Procmon\events_20251126_131211_test_notepad.pml"


def check_prerequisites():
    """Check that everything is set up correctly."""
    print("=" * 60)
    print("ProcmonAI Chat - Test Script")
    print("=" * 60)

    errors = []

    # Check API key
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        # Mask the key for display (show first 10 chars)
        masked = api_key[:10] + "..." if len(api_key) > 10 else api_key
        print(f"[OK] ANTHROPIC_API_KEY is set ({masked})")
    else:
        errors.append("ANTHROPIC_API_KEY not set")
        print("[FAIL] ANTHROPIC_API_KEY not set")
        print("       Set it as a User environment variable or run:")
        print("       $env:ANTHROPIC_API_KEY = 'sk-ant-...'")

    # Check PML file
    if not os.path.exists(DEFAULT_PML):
        errors.append(f"PML file not found: {DEFAULT_PML}")
        print(f"[FAIL] Test PML not found: {DEFAULT_PML}")
    else:
        size_mb = os.path.getsize(DEFAULT_PML) / (1024 * 1024)
        print(f"[OK] Test PML found ({size_mb:.1f} MB)")

    # Check imports
    try:
        from procmon_raw_extractor import extract_raw_events
        print("[OK] procmon_raw_extractor imported")
    except ImportError as e:
        errors.append(f"Import error: {e}")
        print(f"[FAIL] Cannot import procmon_raw_extractor: {e}")

    try:
        from ai_chat import ProcmonChat
        print("[OK] ai_chat imported")
    except ImportError as e:
        errors.append(f"Import error: {e}")
        print(f"[FAIL] Cannot import ai_chat: {e}")

    print()
    return len(errors) == 0


def test_extraction():
    """Test that we can extract events from the PML."""
    print("=" * 60)
    print("Test 1: Event Extraction")
    print("=" * 60)

    from procmon_raw_extractor import extract_raw_events

    print(f"Loading: {DEFAULT_PML}")
    # Use limit=500 to avoid rate limits (50k tokens/min)
    raw_data = extract_raw_events(DEFAULT_PML, process_filter="notepad", limit=500)

    print(f"  Total events: {raw_data['total_events']}")
    print(f"  Unique processes: {len(raw_data['unique_processes'])}")
    print(f"  Processes: {raw_data['unique_processes'][:5]}")
    print(f"  Event categories: {raw_data['event_categories']}")
    print()

    assert raw_data['total_events'] > 0, "No events extracted!"
    print("[PASS] Event extraction works\n")
    return raw_data


def test_chat_session(raw_data):
    """Test multi-turn chat with Claude."""
    print("=" * 60)
    print("Test 2: Multi-Turn Chat")
    print("=" * 60)

    from ai_chat import ProcmonChat

    print("Creating chat session...")
    chat = ProcmonChat()
    print(f"  Model: {chat.model}")

    # Load capture
    print("\nLoading capture and getting initial analysis...")
    initial = chat.load_capture(raw_data, scenario="file_tracking")

    print("\n--- INITIAL ANALYSIS ---")
    print(initial[:500] + "..." if len(initial) > 500 else initial)
    print("--- END ---\n")

    assert chat.capture_loaded, "Capture not loaded!"
    assert len(chat.messages) == 2, f"Expected 2 messages, got {len(chat.messages)}"
    print(f"[OK] Capture loaded, {len(chat.messages)} messages in history")

    # Wait to avoid rate limits
    print("\n[Waiting 5s to avoid rate limits...]")
    time.sleep(5)

    # Ask follow-up question
    print("Asking follow-up: 'What specific files did notepad write to?'")
    answer1 = chat.ask("What specific files did notepad write to?")

    print("\n--- ANSWER 1 ---")
    print(answer1[:400] + "..." if len(answer1) > 400 else answer1)
    print("--- END ---\n")

    assert len(chat.messages) == 4, f"Expected 4 messages, got {len(chat.messages)}"
    print(f"[OK] Follow-up answered, {len(chat.messages)} messages in history")

    # Wait to avoid rate limits
    print("[Waiting 5s to avoid rate limits...]")
    time.sleep(5)

    # Ask another follow-up that references previous context
    print("Asking context-dependent question: 'Were any of those files on the Desktop?'")
    answer2 = chat.ask("Were any of those files on the Desktop?")

    print("\n--- ANSWER 2 ---")
    print(answer2[:400] + "..." if len(answer2) > 400 else answer2)
    print("--- END ---\n")

    assert len(chat.messages) == 6, f"Expected 6 messages, got {len(chat.messages)}"
    print(f"[OK] Context-dependent question answered, {len(chat.messages)} messages")

    print("\n[PASS] Multi-turn chat works!\n")
    return chat


def test_chat_clear(chat):
    """Test clearing conversation history."""
    print("=" * 60)
    print("Test 3: Clear History")
    print("=" * 60)

    initial_count = len(chat.messages)
    print(f"Messages before clear: {initial_count}")

    chat.clear()

    after_count = len(chat.messages)
    print(f"Messages after clear: {after_count}")

    assert after_count == 2, "Clear should keep initial capture message pair"
    assert chat.capture_loaded, "Capture should still be loaded"

    print("[PASS] Clear works correctly\n")


def main():
    """Run all tests."""
    if not check_prerequisites():
        print("\n[ABORT] Prerequisites not met. Fix errors above and retry.")
        sys.exit(1)

    try:
        raw_data = test_extraction()
        chat = test_chat_session(raw_data)
        test_chat_clear(chat)

        print("=" * 60)
        print("ALL TESTS PASSED!")
        print("=" * 60)
        print("\nYou can now use the chat agent:")
        print("  python procmon_chat_agent.py")
        print("\nOr use the Python API directly:")
        print("  from ai_chat import ProcmonChat")
        print("  chat = ProcmonChat()")
        print("  chat.load_capture(raw_data)")
        print("  chat.ask('What happened?')")

    except Exception as e:
        print(f"\n[FAIL] Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
