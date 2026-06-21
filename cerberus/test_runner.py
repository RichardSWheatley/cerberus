"""
Unity test runner — compiles and executes generated test files.

Handles:
- Locating Unity framework source (unity.c, unity.h)
- Compiling test file + source + unity.c
- Running the test binary
- Parsing Unity output format into structured results
"""

import subprocess
import re
import os
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Tuple

UNITY_OUTPUT_RE = re.compile(
    r'^(?P<file>[^:]+):(?P<line>\d+):(?P<test>\w+):(?P<result>PASS|FAIL|IGNORE)(?::(?P<msg>.+))?$'
)
UNITY_SUMMARY_RE = re.compile(
    r'^-+\s*$|^(?P<total>\d+)\s+Tests\s+(?P<fail>\d+)\s+Failures\s+(?P<ignore>\d+)\s+Ignored'
)


@dataclass
class TestResult:
    test_name: str
    result: str  # PASS, FAIL, IGNORE
    file: str = ""
    line: int = 0
    message: str = ""


@dataclass
class RunSummary:
    total: int = 0
    passed: int = 0
    failed: int = 0
    ignored: int = 0
    compile_error: Optional[str] = None
    results: List[TestResult] = None
    returncode: int = 0

    def __post_init__(self):
        if self.results is None:
            self.results = []


def find_unity_dir() -> Optional[Path]:
    """Locate the Unity framework directory."""
    search_paths = [
        Path("unity/src"),
        Path("../unity/src"),
        Path(os.environ.get("UNITY_PATH", ""), "src"),
        Path("/usr/local/include/unity"),
        Path.home() / "Unity" / "src",
    ]
    for p in search_paths:
        if (p / "unity.h").exists():
            return p
    return None


def compile_tests(
    test_file: str,
    source_files: List[str],
    unity_dir: str,
    output_binary: str = "test_runner",
    extra_cflags: Optional[List[str]] = None,
) -> Tuple[bool, str]:
    """
    Compile the Unity test file with source files and Unity framework.

    Returns:
        (success: bool, output: str) — compiler output on failure
    """
    unity_c = str(Path(unity_dir) / "unity.c")
    include_dir = str(Path(unity_dir))

    cmd = [
        os.environ.get("CC", "gcc"),
        "-Wall", "-Wextra", "-Wno-unused-parameter",
        f"-I{include_dir}",
        "-o", output_binary,
        test_file,
        unity_c,
    ] + source_files

    if extra_cflags:
        cmd.extend(extra_cflags)

    # Add common defines for test builds
    cmd.extend([
        "-DUNITY_INCLUDE_DOUBLE",
        "-DUNITY_OUTPUT_COLOR",
    ])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode != 0:
        return False, result.stderr + result.stdout

    return True, ""


def run_tests(binary: str = "./test_runner", timeout: int = 30) -> RunSummary:
    """
    Execute the compiled test binary and parse Unity output.

    Returns:
        RunSummary with individual test results and totals
    """
    try:
        result = subprocess.run(
            [binary],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return RunSummary(
            compile_error=f"Test execution timed out after {timeout}s (possible infinite loop or deadlock)",
            returncode=-1,
        )
    except FileNotFoundError:
        return RunSummary(
            compile_error=f"Test binary not found: {binary}",
            returncode=-1,
        )

    output = result.stdout + result.stderr
    summary = RunSummary(returncode=result.returncode)

    for line in output.splitlines():
        m = UNITY_OUTPUT_RE.match(line.strip())
        if m:
            tr = TestResult(
                test_name=m.group("test"),
                result=m.group("result"),
                file=m.group("file"),
                line=int(m.group("line")),
                message=m.group("msg") or "",
            )
            summary.results.append(tr)
            if tr.result == "PASS":
                summary.passed += 1
            elif tr.result == "FAIL":
                summary.failed += 1
            elif tr.result == "IGNORE":
                summary.ignored += 1

        sm = UNITY_SUMMARY_RE.match(line.strip())
        if sm and sm.group("total"):
            summary.total = int(sm.group("total"))
            summary.failed = int(sm.group("fail"))
            summary.ignored = int(sm.group("ignore"))
            summary.passed = summary.total - summary.failed - summary.ignored

    if summary.total == 0:
        summary.total = len(summary.results)

    return summary


def compile_and_run(
    test_file: str,
    source_files: List[str],
    unity_dir: str,
    output_binary: str = "./test_runner",
    extra_cflags: Optional[List[str]] = None,
    timeout: int = 30,
) -> RunSummary:
    """Full pipeline: compile then run. Returns summary."""
    ok, err = compile_tests(test_file, source_files, unity_dir, output_binary, extra_cflags)
    if not ok:
        return RunSummary(compile_error=err, returncode=-1)

    return run_tests(output_binary, timeout)
