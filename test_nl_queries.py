"""
Test suite for natural language to SQL queries.

Tests various question types against a real Procmon CSV to verify
the system prompt generates correct SQL queries.
"""

import os
import sys

# Test CSV path
TEST_CSV = "C:/ProgramData/Procmon/events_20251129_084639_software_install.csv"


def test_query(translator, question: str, expected_min_results: int = 0, description: str = ""):
    """Run a query and show results."""
    from duckdb_query import run_sql

    print(f"\n{'='*70}")
    print(f"Q: {question}")
    if description:
        print(f"   ({description})")
    print("-" * 70)

    try:
        sql = translator.translate(question)
        print(f"SQL: {sql[:200]}{'...' if len(sql) > 200 else ''}")

        if sql.startswith("ERROR:"):
            print(f"[FAIL] Translation error: {sql}")
            return False

        results = run_sql(sql)
        print(f"Results: {len(results)} rows")

        # Show sample results
        for r in results[:5]:
            # Truncate long values
            truncated = {k: (str(v)[:60] + '...' if len(str(v)) > 60 else v) for k, v in r.items()}
            print(f"  {truncated}")
        if len(results) > 5:
            print(f"  ... and {len(results) - 5} more")

        if len(results) >= expected_min_results:
            print(f"[PASS] Got {len(results)} results (expected >= {expected_min_results})")
            return True
        else:
            print(f"[WARN] Got {len(results)} results (expected >= {expected_min_results})")
            return False

    except Exception as e:
        print(f"[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    # Check API key - try to get from User environment if not in current session
    if not os.getenv("ANTHROPIC_API_KEY"):
        import subprocess
        result = subprocess.run(
            ["powershell", "-Command", "[Environment]::GetEnvironmentVariable('ANTHROPIC_API_KEY', 'User')"],
            capture_output=True, text=True
        )
        if result.stdout.strip():
            os.environ["ANTHROPIC_API_KEY"] = result.stdout.strip()
        else:
            print("ERROR: ANTHROPIC_API_KEY not set")
            print("Run: $env:ANTHROPIC_API_KEY = 'your-key'")
            sys.exit(1)

    # Check test file
    from pathlib import Path
    if not Path(TEST_CSV).exists():
        print(f"ERROR: Test CSV not found: {TEST_CSV}")
        sys.exit(1)

    print("=" * 70)
    print("NL to SQL Query Test Suite")
    print(f"CSV: {TEST_CSV}")
    print("=" * 70)

    from nl_to_sql import NLToSQL
    translator = NLToSQL(TEST_CSV)

    results = []

    # === FILE QUERIES ===
    print("\n" + "=" * 70)
    print("FILE QUERIES")
    print("=" * 70)

    results.append(test_query(
        translator,
        "What files did CCleaner create?",
        expected_min_results=50,
        description="Should find 147+ exe/dll files"
    ))

    results.append(test_query(
        translator,
        "Show me all executables that were installed",
        expected_min_results=10,
        description="Should find exe files in Program Files"
    ))

    results.append(test_query(
        translator,
        "What DLLs were created in Program Files?",
        expected_min_results=50,
        description="Should find CCleaner DLLs"
    ))

    results.append(test_query(
        translator,
        "Were any files created in the Temp folder?",
        expected_min_results=10,
        description="Should find temp installer files"
    ))

    # === REGISTRY QUERIES ===
    print("\n" + "=" * 70)
    print("REGISTRY QUERIES")
    print("=" * 70)

    results.append(test_query(
        translator,
        "What registry keys were modified?",
        expected_min_results=100,
        description="Should find 200+ RegSetValue operations"
    ))

    results.append(test_query(
        translator,
        "Show me the CCleaner registry settings",
        expected_min_results=50,
        description="Should find Piriform\\CCleaner keys"
    ))

    results.append(test_query(
        translator,
        "What was registered in the uninstall keys?",
        expected_min_results=5,
        description="Should find Uninstall\\CCleaner entries"
    ))

    # === PERSISTENCE QUERIES ===
    print("\n" + "=" * 70)
    print("PERSISTENCE QUERIES")
    print("=" * 70)

    results.append(test_query(
        translator,
        "What persistence mechanisms were set up?",
        expected_min_results=1,
        description="Should find shell extensions, app paths, start menu"
    ))

    results.append(test_query(
        translator,
        "Were any Run keys created?",
        expected_min_results=0,
        description="CCleaner doesn't use Run keys in this install"
    ))

    results.append(test_query(
        translator,
        "Were any shell context menu entries added?",
        expected_min_results=2,
        description="Should find Recycle Bin shell extensions"
    ))

    results.append(test_query(
        translator,
        "What was added to the Start Menu?",
        expected_min_results=2,
        description="Should find CCleaner shortcuts"
    ))

    results.append(test_query(
        translator,
        "Were any App Paths registered?",
        expected_min_results=2,
        description="Should find ccleaner.exe App Path"
    ))

    # === PROCESS QUERIES ===
    print("\n" + "=" * 70)
    print("PROCESS QUERIES")
    print("=" * 70)

    results.append(test_query(
        translator,
        "What processes were spawned?",
        expected_min_results=2,
        description="Should find CCleaner64.exe and CCUpdate.exe"
    ))

    results.append(test_query(
        translator,
        "What DLLs were loaded?",
        expected_min_results=100,
        description="Should find 136+ DLLs"
    ))

    # === SUMMARY QUERIES ===
    print("\n" + "=" * 70)
    print("SUMMARY QUERIES")
    print("=" * 70)

    results.append(test_query(
        translator,
        "How many files were created?",
        expected_min_results=1,
        description="Should return a count"
    ))

    results.append(test_query(
        translator,
        "What are the top operations by count?",
        expected_min_results=3,
        description="Should return operation counts"
    ))

    results.append(test_query(
        translator,
        "Give me a summary of registry changes",
        expected_min_results=1,
        description="Should summarize registry operations"
    ))

    # === RESULTS ===
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)

    passed = sum(1 for r in results if r)
    total = len(results)

    print(f"\nPassed: {passed}/{total}")
    print(f"Failed: {total - passed}/{total}")

    if passed == total:
        print("\n[SUCCESS] All tests passed!")
    else:
        print(f"\n[NEEDS WORK] {total - passed} tests need attention")

    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
