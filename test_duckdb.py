"""
Test script for DuckDB integration.

Tests:
1. Basic SQL query execution via PSDuckDB
2. CSV file querying
3. Natural language to SQL translation
"""

import os
import sys
import csv
from pathlib import Path

# Create a simple test CSV
TEST_CSV = Path(__file__).parent / "test_data.csv"


def create_test_csv():
    """Create a simple test CSV file."""
    data = [
        {"Process Name": "notepad.exe", "Operation": "CreateFile", "Path": "C:\\test.txt", "Result": "SUCCESS"},
        {"Process Name": "notepad.exe", "Operation": "WriteFile", "Path": "C:\\test.txt", "Result": "SUCCESS"},
        {"Process Name": "chrome.exe", "Operation": "TCP Connect", "Path": "google.com:443", "Result": "SUCCESS"},
        {"Process Name": "explorer.exe", "Operation": "RegSetValue", "Path": "HKLM\\SOFTWARE\\Test", "Result": "SUCCESS"},
        {"Process Name": "malware.exe", "Operation": "CreateFile", "Path": "C:\\Windows\\System32\\evil.dll", "Result": "SUCCESS"},
    ]

    with open(TEST_CSV, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

    print(f"[OK] Created test CSV: {TEST_CSV}")
    return str(TEST_CSV)


def test_basic_duckdb():
    """Test basic DuckDB query execution."""
    print("\n=== Test 1: Basic DuckDB Query ===")

    try:
        from duckdb_query import run_sql

        # Simple calculation
        result = run_sql("SELECT 1 + 1 as answer")
        print(f"Query: SELECT 1 + 1 as answer")
        print(f"Result: {result}")

        if result and result[0].get("answer") == 2:
            print("[PASS] Basic query works!")
            return True
        else:
            print("[FAIL] Unexpected result")
            return False

    except Exception as e:
        print(f"[FAIL] Error: {e}")
        return False


def test_csv_query(csv_file: str):
    """Test querying a CSV file."""
    print("\n=== Test 2: CSV Query ===")

    try:
        from duckdb_query import run_sql

        csv_path = str(Path(csv_file).resolve()).replace("\\", "/")
        query = f"SELECT * FROM '{csv_path}'"

        print(f"Query: {query}")
        result = run_sql(query)

        print(f"Results: {len(result)} rows")
        for row in result[:3]:
            print(f"  {row}")

        if result:
            print("[PASS] CSV query works!")
            return True
        else:
            print("[FAIL] No results")
            return False

    except Exception as e:
        print(f"[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_filtered_query(csv_file: str):
    """Test filtered CSV query."""
    print("\n=== Test 3: Filtered Query ===")

    try:
        from duckdb_query import run_sql

        csv_path = str(Path(csv_file).resolve()).replace("\\", "/")
        query = f"""
SELECT "Process Name", Operation, Path
FROM '{csv_path}'
WHERE Operation = 'CreateFile'
"""

        print(f"Query: {query.strip()}")
        result = run_sql(query)

        print(f"Results: {len(result)} rows")
        for row in result:
            print(f"  {row}")

        if result and len(result) == 2:  # notepad.exe and malware.exe
            print("[PASS] Filtered query works!")
            return True
        else:
            print(f"[FAIL] Expected 2 rows, got {len(result)}")
            return False

    except Exception as e:
        print(f"[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_nl_to_sql(csv_file: str):
    """Test natural language to SQL translation."""
    print("\n=== Test 4: NL to SQL Translation ===")

    # Check if API key is set
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("[SKIP] ANTHROPIC_API_KEY not set")
        return None

    try:
        from nl_to_sql import NLToSQL

        translator = NLToSQL(csv_file)

        question = "Which processes created files?"
        sql = translator.translate(question)

        print(f"Question: {question}")
        print(f"Generated SQL: {sql}")

        if sql and not sql.startswith("ERROR:"):
            print("[PASS] NL to SQL works!")
            return True
        else:
            print("[FAIL] Translation failed")
            return False

    except Exception as e:
        print(f"[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_sql_chat(csv_file: str):
    """Test full SQL chat workflow."""
    print("\n=== Test 5: SQL Chat ===")

    # Check if API key is set
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("[SKIP] ANTHROPIC_API_KEY not set")
        return None

    try:
        from sql_chat import SQLChat

        chat = SQLChat(csv_file)

        question = "What malicious activity do you see?"
        print(f"Question: {question}")

        response = chat.ask(question, show_sql=True)
        print(f"Response:\n{response[:500]}...")

        if response:
            print("\n[PASS] SQL Chat works!")
            return True
        else:
            print("[FAIL] No response")
            return False

    except Exception as e:
        print(f"[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("ProcmonAI DuckDB Integration Tests")
    print("=" * 60)

    # Create test data
    csv_file = create_test_csv()

    results = []

    # Run tests
    results.append(("Basic DuckDB", test_basic_duckdb()))
    results.append(("CSV Query", test_csv_query(csv_file)))
    results.append(("Filtered Query", test_filtered_query(csv_file)))
    results.append(("NL to SQL", test_nl_to_sql(csv_file)))
    results.append(("SQL Chat", test_sql_chat(csv_file)))

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    passed = 0
    failed = 0
    skipped = 0

    for name, result in results:
        if result is True:
            print(f"  [PASS] {name}")
            passed += 1
        elif result is False:
            print(f"  [FAIL] {name}")
            failed += 1
        else:
            print(f"  [SKIP] {name}")
            skipped += 1

    print(f"\nTotal: {passed} passed, {failed} failed, {skipped} skipped")

    # Cleanup
    if TEST_CSV.exists():
        TEST_CSV.unlink()
        print(f"\n[cleanup] Removed {TEST_CSV}")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
