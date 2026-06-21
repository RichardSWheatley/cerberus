#!/usr/bin/env python3
"""
CERBERUS — CI Pipeline Entry Point

Full pipeline:
  1. Deterministic pattern scan (instant, guaranteed)
  2. AI deep analysis via Claude (contextual, cross-function)
  3. Unity test generation targeting all findings
  4. Compile and run Unity tests
  5. Generate PR comment / annotations / SARIF

Usage:
  # Full pipeline on a file
  python -m cerberus.cli analyze src/device.c

  # Scan only (no AI, no tests — fast gate)
  python -m cerberus.cli scan src/device.c

  # Update knowledge base
  python -m cerberus.cli kb-update

  # Analyze all changed C files in a PR (git diff)
  python -m cerberus.cli pr
"""

import argparse
import json
import os
import sys
import subprocess
from pathlib import Path
from dataclasses import asdict

from cerberus.scanner import scan_file, scan_source, Finding
from cerberus.ai_engine import run_ai_analysis
from cerberus.test_gen import generate_unity_tests
from cerberus.test_runner import compile_and_run, find_unity_dir
from cerberus.reporter import (
    generate_pr_comment,
    generate_github_annotations,
    generate_json_summary,
    generate_sarif,
)
from cerberus.kb_updater import load_kb, update_kb, is_update_due


def get_pr_changed_files() -> list[str]:
    """Get list of changed .c/.h files in the current PR."""
    base = os.environ.get("GITHUB_BASE_REF", "main")
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"origin/{base}...HEAD", "--", "*.c", "*.h"],
            capture_output=True, text=True, check=True,
        )
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError:
        # Fallback: diff against HEAD~1
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "HEAD~1", "--", "*.c", "*.h"],
                capture_output=True, text=True, check=True,
            )
            return [f.strip() for f in result.stdout.splitlines() if f.strip()]
        except subprocess.CalledProcessError:
            return []


def run_analyze(filepath: str, args) -> dict:
    """Run the full analysis pipeline on a single file."""
    filepath = str(Path(filepath).resolve() if Path(filepath).exists() else filepath)
    source = Path(filepath).read_text(errors="replace")

    print(f"\n{'='*60}")
    print(f"  ⛨  CERBERUS — Three-Headed Code Guardian")
    print(f"  Target: {filepath}")
    print(f"{'='*60}\n")

    # ── Head 1: Deterministic scan ──
    print("[HEAD 1] Pattern Scanner — deterministic, guaranteed...")
    scanner_findings = [asdict(f) for f in scan_file(filepath)]
    crit_count = sum(1 for f in scanner_findings if f["severity"] == "critical")
    high_count = sum(1 for f in scanner_findings if f["severity"] == "high")
    print(f"            → {len(scanner_findings)} findings "
          f"({crit_count} critical, {high_count} high)")

    if args.scan_only:
        print("\n[scan-only — Head 1 only, skipping AI and tests]")
        return {
            "file": filepath,
            "scanner_findings": scanner_findings,
            "verdict": "block" if crit_count > 0 else "request_changes" if high_count > 0 else "approve",
        }

    # ── Step 2: Load KB context ──
    print("[      ] Loading knowledge base...")
    kb_dir = Path(args.kb_dir) if args.kb_dir else None
    kb_context = load_kb(kb_dir)
    if kb_context:
        print("         → KB loaded with recent advisories")
    else:
        print("         → No KB data (run 'kb-update' to populate)")

    # ── Step 3: AI deep analysis ──
    print("[HEAD 2] AI Deep Analysis — contextual, cross-function...")
    ai_result = run_ai_analysis(source, filepath, scanner_findings, kb_context)
    ai_finding_count = len(ai_result.get("findings", []))
    verdict = ai_result.get("verdict", "request_changes")
    print(f"         → {ai_finding_count} additional findings")
    print(f"         → Verdict: {verdict.upper()}")
    print(f"         → Risk score: {ai_result.get('metrics', {}).get('risk_score', '?')}/10")

    # ── Step 4: Generate Unity tests ──
    all_findings = scanner_findings + ai_result.get("findings", [])
    test_summary = None

    if not args.no_tests:
        print("[HEAD 3] Unity Test Forge — regression tests targeting findings...")
        test_dir = Path(args.test_dir or "test_output")
        test_dir.mkdir(parents=True, exist_ok=True)

        module_name = Path(filepath).stem
        test_file = str(test_dir / f"test_{module_name}.c")

        test_code = generate_unity_tests(source, filepath, all_findings, test_file)
        print(f"         → Written to {test_file}")

        # ── Step 5: Compile and run tests ──
        unity_dir = args.unity_dir or find_unity_dir()
        if unity_dir:
            print("[TRIAL ] Compile & execute — proof by fire...")
            unity_dir = str(unity_dir)
            binary = str(test_dir / f"test_{module_name}")
            summary = compile_and_run(
                test_file, [filepath], unity_dir, binary,
                extra_cflags=args.cflags.split() if args.cflags else None,
            )
            if summary.compile_error:
                print(f"         ⚠️  Compilation failed:")
                for line in summary.compile_error.splitlines()[:10]:
                    print(f"         {line}")
            else:
                print(f"         → {summary.total} tests: "
                      f"{summary.passed} passed, {summary.failed} failed, "
                      f"{summary.ignored} ignored")
            test_summary = {
                "total": summary.total,
                "passed": summary.passed,
                "failed": summary.failed,
                "ignored": summary.ignored,
                "compile_error": summary.compile_error,
                "results": [
                    {"test_name": r.test_name, "result": r.result, "message": r.message}
                    for r in summary.results
                ],
            }
        else:
            print("[TRIAL ] Unity framework not found — skipping test execution")
            print("      Set --unity-dir or UNITY_PATH, or run setup_unity.sh")
    else:
        print("[HEAD 3] Test generation skipped (--no-tests)")
        print("[TRIAL ] —")

    # ── Generate reports ──
    output_dir = Path(args.output_dir or "analysis_output")
    output_dir.mkdir(parents=True, exist_ok=True)

    module_name = Path(filepath).stem

    # PR Comment
    pr_comment = generate_pr_comment(filepath, scanner_findings, ai_result, test_summary)
    (output_dir / f"{module_name}_pr_comment.md").write_text(pr_comment)

    # GitHub annotations
    annotations = generate_github_annotations(filepath, all_findings)
    if os.environ.get("GITHUB_ACTIONS"):
        print(annotations)  # GitHub Actions picks these up from stdout

    # JSON summary
    json_summary = generate_json_summary(filepath, scanner_findings, ai_result, test_summary)
    (output_dir / f"{module_name}_summary.json").write_text(json_summary)

    # SARIF
    sarif = generate_sarif(filepath, all_findings)
    (output_dir / f"{module_name}.sarif").write_text(sarif)

    print(f"\n  Reports written to {output_dir}/")
    print(f"  Verdict: {verdict.upper()} — {ai_result.get('verdict_reason', '')}")

    return {
        "file": filepath,
        "scanner_findings": scanner_findings,
        "ai_result": ai_result,
        "test_summary": test_summary,
        "verdict": verdict,
    }


def cmd_analyze(args):
    """Handle the 'analyze' command."""
    results = []
    for filepath in args.files:
        if not Path(filepath).exists():
            print(f"ERROR: File not found: {filepath}", file=sys.stderr)
            continue
        result = run_analyze(filepath, args)
        results.append(result)

    # Exit code based on worst verdict
    verdicts = [r["verdict"] for r in results]
    if "block" in verdicts:
        sys.exit(2)
    elif "request_changes" in verdicts:
        sys.exit(1)
    sys.exit(0)


def cmd_scan(args):
    """Handle the 'scan' command — deterministic only, fast gate."""
    args.scan_only = True
    args.no_tests = True
    cmd_analyze(args)


def cmd_pr(args):
    """Handle the 'pr' command — analyze all changed C files."""
    changed = get_pr_changed_files()
    if not changed:
        print("No changed .c/.h files found in this PR.")
        sys.exit(0)

    print(f"Found {len(changed)} changed C/H files:")
    for f in changed:
        print(f"  {f}")

    args.files = changed
    cmd_analyze(args)


def cmd_kb_update(args):
    """Handle the 'kb-update' command."""
    print("Updating knowledge base...")
    kb_dir = Path(args.kb_dir) if args.kb_dir else None
    result = update_kb(kb_dir)
    if result["success"]:
        print(f"  ✓ Updated {result['sources_updated']} sources, "
              f"{result['items_count']} items")
        print(f"  Next update due: {result['next_update']}")
    else:
        print(f"  ✗ Failed: {result.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)


def cmd_kb_check(args):
    """Check if KB update is due."""
    kb_dir = Path(args.kb_dir) if args.kb_dir else None
    if is_update_due(kb_dir):
        print("Knowledge base update is DUE")
        sys.exit(1)
    else:
        print("Knowledge base is current")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        prog="cerberus",
        description="CERBERUS — deterministic scan + AI analysis + Unity tests",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # analyze
    p_analyze = sub.add_parser("analyze", help="Full pipeline: scan → AI → tests → report")
    p_analyze.add_argument("files", nargs="+", help="C source files to analyze")
    p_analyze.add_argument("--no-tests", action="store_true", help="Skip Unity test generation/execution")
    p_analyze.add_argument("--unity-dir", help="Path to Unity src/ directory")
    p_analyze.add_argument("--test-dir", default="test_output", help="Directory for generated tests")
    p_analyze.add_argument("--output-dir", default="analysis_output", help="Directory for reports")
    p_analyze.add_argument("--kb-dir", help="Directory containing knowledge base files")
    p_analyze.add_argument("--cflags", help="Extra compiler flags (space-separated)")
    p_analyze.set_defaults(func=cmd_analyze, scan_only=False)

    # scan (fast gate)
    p_scan = sub.add_parser("scan", help="Deterministic scan only (fast, no AI)")
    p_scan.add_argument("files", nargs="+", help="C source files to scan")
    p_scan.add_argument("--output-dir", default="analysis_output")
    p_scan.add_argument("--kb-dir", help="KB directory")
    p_scan.set_defaults(func=cmd_scan)

    # pr
    p_pr = sub.add_parser("pr", help="Analyze all changed C files in current PR")
    p_pr.add_argument("--no-tests", action="store_true")
    p_pr.add_argument("--unity-dir", help="Path to Unity src/ directory")
    p_pr.add_argument("--test-dir", default="test_output")
    p_pr.add_argument("--output-dir", default="analysis_output")
    p_pr.add_argument("--kb-dir", help="KB directory")
    p_pr.add_argument("--cflags", help="Extra compiler flags")
    p_pr.set_defaults(func=cmd_pr, scan_only=False)

    # kb-update
    p_kb = sub.add_parser("kb-update", help="Update knowledge base (biweekly)")
    p_kb.add_argument("--kb-dir", help="KB directory")
    p_kb.set_defaults(func=cmd_kb_update)

    # kb-check
    p_kbc = sub.add_parser("kb-check", help="Check if KB update is due")
    p_kbc.add_argument("--kb-dir", help="KB directory")
    p_kbc.set_defaults(func=cmd_kb_check)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
