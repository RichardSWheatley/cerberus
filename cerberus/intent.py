"""
CERBERUS Intent Analyzer

Not "is this code technically wrong" but "does this code do what the
developer intended?"

Infers intent from:
  - Function/variable names and naming patterns
  - Comments, docstrings, Doxygen blocks
  - API contracts (parameter names, return type semantics)
  - Surrounding code patterns (error handling style, naming conventions)
  - Commit messages (if available via git)
  - Header/spec references in comments

Then checks whether the implementation matches the inferred intent.

This catches a class of bugs that neither pattern scanning nor traditional
static analysis can find — the code is "valid C" but doesn't do what the
name/comment/contract promises.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path


@dataclass
class IntentFinding:
    id: str
    severity: str
    title: str
    location: str
    line: int
    stated_intent: str
    actual_behavior: str
    mismatch: str
    recommendation: str


# ── Intent inference from naming patterns ──────────────────────

INTENT_PATTERNS = [
    {
        "id": "INTENT-INIT-NO-ZERO",
        "pattern": r'\b(\w+_init|initialize_\w+|_setup)\s*\([^)]*\)\s*\{',
        "check": "body_missing",
        "body_expect": r'memset|= 0|= NULL|= false|= FALSE|bzero|\{0\}',
        "severity": "medium",
        "title": "Init function may not zero-initialize state",
        "intent": "Function name implies full initialization of state",
        "mismatch": "Function body does not memset/zero the state struct. Callers assume post-init state is clean.",
        "fix": "Add memset(pState, 0, sizeof(*pState)) at function entry, or verify every field is explicitly set.",
    },
    {
        "id": "INTENT-DEINIT-NO-FREE",
        "pattern": r'\b(\w+_deinit|_deinitialize|_destroy|_cleanup|_close|_shutdown)\s*\([^)]*\)\s*\{',
        "check": "body_missing",
        "body_expect": r'\bfree\b|\bk_free\b|= NULL|= 0|disable|power.*down|clk.*off',
        "severity": "medium",
        "title": "Deinit/destroy function may not release resources",
        "intent": "Function name implies full teardown and resource release",
        "mismatch": "Function body has no free(), no NULL-ing of pointers, no disable/power-down sequence. Resources may leak.",
        "fix": "Ensure all allocated resources are freed, peripheral clocks disabled, and state NULLed.",
    },
    {
        "id": "INTENT-VALIDATE-NO-CHECK",
        "pattern": r'\b(\w+_validate|_verify|_check|is_valid_\w+)\s*\([^)]*\)\s*\{',
        "check": "body_missing",
        "body_expect": r'if\s*\(|return.*!=|return.*==|return.*false|return.*true|AM_HAL_STATUS',
        "severity": "medium",
        "title": "Validation function may not actually validate",
        "intent": "Function name promises input validation",
        "mismatch": "Function body has no conditional checks or may always return success. Callers trust its verdict.",
        "fix": "Ensure the function checks all stated invariants and returns a meaningful pass/fail.",
    },
    {
        "id": "INTENT-LOCK-NO-UNLOCK",
        "pattern": r'\b(\w+_lock|_acquire|_enter_critical)\s*\([^)]*\)\s*\{',
        "check": "paired_function_missing",
        "pair_pattern": r'_unlock|_release|_exit_critical',
        "scope": "same_function_after",
        "severity": "high",
        "title": "Lock acquired but unlock may be missing on error paths",
        "intent": "Lock/unlock must be paired on ALL paths including error returns",
        "mismatch": "Function acquires a lock but has early return paths that may skip the unlock.",
        "fix": "Use goto-cleanup pattern or ensure every return path releases the lock.",
    },
    {
        "id": "INTENT-ENABLE-NO-DISABLE",
        "pattern": r'\b(\w+_enable)\s*\([^)]*\)',
        "check": "api_pair_exists",
        "pair_pattern": r'_disable\b',
        "severity": "low",
        "title": "Enable API exists without corresponding disable",
        "intent": "Enable/disable should be paired for proper lifecycle management",
        "mismatch": "An enable function exists but no corresponding disable function is visible in the same module.",
        "fix": "Implement the disable counterpart, or document that disable is handled differently.",
    },
    {
        "id": "INTENT-TIMEOUT-INFINITE",
        "pattern": r'while\s*\([^)]*(?:status|busy|pending|ready|done|complete|flag)[^)]*\)',
        "check": "body_missing",
        "body_expect": r'timeout|ui32Timeout|break|return.*ERR|return.*TIMEOUT|k_busy_wait|--\s*\w*[Tt]ries',
        "severity": "high",
        "title": "Polling loop with no timeout",
        "intent": "Polling for hardware status should have a bounded timeout",
        "mismatch": "Loop polls a status/flag condition with no decrementing counter, timeout check, or watchdog. Hardware hang causes infinite loop.",
        "fix": "Add a timeout counter: uint32_t timeout = MAX_RETRIES; while (condition && --timeout) { ... } if (!timeout) return AM_HAL_STATUS_TIMEOUT;",
    },
    {
        "id": "INTENT-RETURN-IGNORED",
        "pattern": r'^\s+am_hal_\w+\s*\([^;]*\)\s*;',
        "check": "return_value_ignored",
        "severity": "medium",
        "title": "HAL function return value (status code) ignored",
        "intent": "am_hal_* functions return status codes that indicate success/failure",
        "mismatch": "Return value of HAL function call is discarded. If the operation failed, the caller proceeds as if it succeeded — silent data corruption or misconfiguration.",
        "fix": "Capture and check: uint32_t status = am_hal_xxx(); if (status != AM_HAL_STATUS_SUCCESS) { /* handle */ }",
    },
    {
        "id": "INTENT-COMMENT-MISMATCH",
        "pattern": r'//\s*(?:disable|turn off|power down|shut down|stop|clear|reset)',
        "check": "next_line_contradicts",
        "contradiction": r'enable|turn.*on|power.*up|start|set\b',
        "severity": "high",
        "title": "Comment says disable/off but code enables/starts",
        "intent": "Comment describes the intended operation",
        "mismatch": "The code immediately following the comment does the OPPOSITE of what the comment describes. Either the comment is stale or the code is wrong — both are dangerous.",
        "fix": "Verify which is correct: the comment (intent) or the code (implementation). Fix the wrong one.",
    },
    {
        "id": "INTENT-SIZEOF-WRONG-ARG",
        "pattern": r'\b(?:memcpy|memset|memmove)\s*\(\s*(\w+)\s*,\s*[^,]+,\s*sizeof\s*\(\s*(?!\1\b)(\w+)\s*\)\s*\)',
        "check": "sizeof_target_mismatch",
        "severity": "high",
        "title": "sizeof() argument doesn't match destination buffer",
        "intent": "memcpy/memset size should match the target buffer",
        "mismatch": "sizeof() is called on a different variable than the destination. The intent was likely sizeof(destination) but a different name was used — copy size may be wrong.",
        "fix": "Use sizeof(destination_variable) or sizeof(*destination_pointer) to match the target.",
    },
]

# ── Comment/docstring extraction ──────────────────────────────

def extract_function_comments(source: str) -> Dict[str, str]:
    """Extract Doxygen/comment blocks immediately preceding each function."""
    functions_with_comments = {}
    lines = source.splitlines()

    func_re = re.compile(
        r'^[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*\{?\s*$'
    )

    for i, line in enumerate(lines):
        m = func_re.match(line.strip())
        if not m:
            continue
        fname = m.group(1)
        # Walk backwards to find comment block
        comment_lines = []
        j = i - 1
        while j >= 0:
            stripped = lines[j].strip()
            if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*') or stripped.startswith('**'):
                comment_lines.insert(0, stripped)
                j -= 1
            elif stripped == '':
                j -= 1
            else:
                break
        if comment_lines:
            functions_with_comments[fname] = '\n'.join(comment_lines)

    return functions_with_comments


def extract_functions_with_bodies(source: str) -> List[Dict[str, Any]]:
    """Extract function name, start line, and body."""
    functions = []
    pattern = re.compile(
        r'^[ \t]*(?:static\s+|inline\s+|extern\s+|volatile\s+|const\s+)*'
        r'(?:(?:unsigned|signed|long|short|struct|enum|union|uint32_t|void|int|bool)\s+)*'
        r'[\w\*]+\s+(\w+)\s*\(([^)]*)\)\s*\{',
        re.MULTILINE,
    )
    for m in pattern.finditer(source):
        name = m.group(1)
        start_pos = m.start()
        start_line = source[:start_pos].count('\n') + 1
        brace_count = 0
        body_start = m.end() - 1
        for idx in range(body_start, len(source)):
            if source[idx] == '{':
                brace_count += 1
            elif source[idx] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_line = source[:idx].count('\n') + 1
                    body = source[body_start:idx + 1]
                    functions.append({
                        "name": name,
                        "start_line": start_line,
                        "end_line": end_line,
                        "body": body,
                        "params": m.group(2),
                    })
                    break
    return functions


# ── Intent checking engine ────────────────────────────────────

def check_intent(source: str, filepath: str = "<stdin>") -> List[IntentFinding]:
    """Run all intent checks on a source file."""
    findings = []
    counter = 0

    stripped = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group().count('\n'), source, flags=re.DOTALL)
    lines = source.splitlines()  # Keep comments for intent checks
    stripped_lines = stripped.splitlines()
    functions = extract_functions_with_bodies(stripped)

    for rule in INTENT_PATTERNS:
        pattern = re.compile(rule["pattern"], re.MULTILINE)

        if rule["check"] == "body_missing":
            # Check if function body contains expected pattern
            for func in functions:
                header = stripped_lines[func["start_line"] - 1] if func["start_line"] <= len(stripped_lines) else ""
                if not pattern.search(header) and not pattern.search(func["name"]):
                    continue
                expect_re = re.compile(rule["body_expect"])
                if not expect_re.search(func["body"]):
                    counter += 1
                    findings.append(IntentFinding(
                        id=f"I{counter:03d}",
                        severity=rule["severity"],
                        title=rule["title"],
                        location=f"{func['name']}()",
                        line=func["start_line"],
                        stated_intent=rule["intent"],
                        actual_behavior=rule["mismatch"],
                        mismatch=f"Function '{func['name']}' name implies {rule['intent'].lower()} but body lacks expected pattern.",
                        recommendation=rule["fix"],
                    ))

        elif rule["check"] == "return_value_ignored":
            for i, line in enumerate(stripped_lines):
                if pattern.search(line):
                    # Check it's not assigned to anything
                    if not re.search(r'=\s*am_hal_|if\s*\(\s*am_hal_|status.*=|ret.*=|err.*=', line):
                        counter += 1
                        findings.append(IntentFinding(
                            id=f"I{counter:03d}",
                            severity=rule["severity"],
                            title=rule["title"],
                            location=f"line {i + 1}",
                            line=i + 1,
                            stated_intent=rule["intent"],
                            actual_behavior=rule["mismatch"],
                            mismatch=f"am_hal_*() return value discarded at line {i+1}.",
                            recommendation=rule["fix"],
                        ))

        elif rule["check"] == "next_line_contradicts":
            contra_re = re.compile(rule["contradiction"], re.IGNORECASE)
            for i, line in enumerate(lines):
                if pattern.search(line.lower()):
                    if i + 1 < len(lines) and contra_re.search(lines[i + 1]):
                        counter += 1
                        findings.append(IntentFinding(
                            id=f"I{counter:03d}",
                            severity=rule["severity"],
                            title=rule["title"],
                            location=f"line {i + 1}-{i + 2}",
                            line=i + 1,
                            stated_intent=f"Comment: '{line.strip()}'",
                            actual_behavior=f"Next line: '{lines[i+1].strip()}'",
                            mismatch="Comment and code contradict each other.",
                            recommendation=rule["fix"],
                        ))

        elif rule["check"] == "sizeof_target_mismatch":
            for i, line in enumerate(stripped_lines):
                m = pattern.search(line)
                if m:
                    dst = m.group(1)
                    sizeof_arg = m.group(2)
                    if dst != sizeof_arg:
                        counter += 1
                        findings.append(IntentFinding(
                            id=f"I{counter:03d}",
                            severity=rule["severity"],
                            title=rule["title"],
                            location=f"line {i + 1}",
                            line=i + 1,
                            stated_intent=f"memcpy/memset destination is '{dst}', sizeof should match",
                            actual_behavior=f"sizeof({sizeof_arg}) used instead of sizeof({dst})",
                            mismatch=f"sizeof argument '{sizeof_arg}' doesn't match destination '{dst}'.",
                            recommendation=rule["fix"],
                        ))

        elif rule["check"] == "body_missing" and rule.get("scope") == "same_function_after":
            # Simplified check — just flag the pattern
            pass

    return findings


def scan_intent(filepath: str) -> List[IntentFinding]:
    """Run intent analysis on a file."""
    source = Path(filepath).read_text(errors="replace")
    return check_intent(source, filepath)
