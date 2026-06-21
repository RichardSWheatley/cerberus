"""
AI deep analysis engine — provider-agnostic LLM for contextual code analysis.

Runs AFTER the deterministic scanner. Receives the scanner's findings so it can
focus on deeper issues: cross-function data flow, logic errors, RTOS-specific
hazards, complexity assessment, and anything the pattern matcher can't see.
"""

import json
import os
import sys
from typing import List, Dict, Any, Optional
from dataclasses import asdict

ANALYSIS_SYSTEM_PROMPT = """You are a senior C static code analysis engine integrated into a CI pipeline. You combine the rigor of commercial SAST tools (Coverity, Polyspace, PVS-Studio) with deep knowledge of the C standard (C11/C17), CERT C, MISRA C:2012, and CWE.

You are the SECOND pass. A deterministic pattern scanner already ran and produced the findings listed below. DO NOT duplicate those findings. Focus on what regex can't catch:
- Cross-function data flow and taint propagation
- Logic errors and incorrect invariants
- Use-after-free / double-free across call boundaries
- RTOS-specific hazards (blocking in ISR, priority inversion, non-deterministic allocation)
- Integer overflow in size calculations feeding malloc/memcpy
- Race conditions and reentrancy issues in shared state
- Cyclomatic/cognitive complexity assessment
- Subtle UB (strict aliasing, sequence points, signed overflow in expressions)
- Missing error path handling on syscalls and library calls

Return ONLY a JSON object (no markdown, no backticks, no preamble):

{
  "summary": "One-paragraph overall assessment including the deterministic scan results.",
  "metrics": {
    "total_issues": <int including scanner findings>,
    "by_severity": { "critical": <int>, "high": <int>, "medium": <int>, "low": <int>, "info": <int> },
    "estimated_cyclomatic_complexity": "<value for most complex function>",
    "risk_score": <1-10>
  },
  "findings": [
    {
      "id": "A001",
      "category": "<security|bug|memory|undefined_behavior|concurrency|complexity|style|portability>",
      "severity": "<critical|high|medium|low|info>",
      "title": "Short title",
      "location": "function_name() or file:line",
      "line": <int or null>,
      "description": "What the issue is, the data flow path, and why it matters.",
      "cwe": "CWE-xxx or null",
      "cert_c": "CERT C rule ID or null",
      "recommendation": "Concrete fix with code."
    }
  ],
  "verdict": "<approve|request_changes|block>",
  "verdict_reason": "One sentence justifying the verdict."
}

Verdict rules:
- "block": any critical finding (scanner or AI) — PR must not merge
- "request_changes": high findings or 3+ medium findings
- "approve": only low/info findings

Use A-prefixed IDs (A001, A002...) to distinguish from scanner S-prefixed findings.
Be precise. Every finding must be actionable. No padding with style nits when real bugs exist."""


def run_ai_analysis(
    source: str,
    filepath: str,
    scanner_findings: List[Dict[str, Any]],
    kb_context: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run LLM-powered deep analysis on C source code.

    Args:
        source: The C source code
        filepath: Path to the file being analyzed
        scanner_findings: Findings from the deterministic scanner (as dicts)
        kb_context: Optional knowledge base context (recent CVEs, advisories)

    Returns:
        Parsed JSON result from the AI analysis
    """
    from cerberus import llm

    scanner_summary = json.dumps(scanner_findings, indent=2) if scanner_findings else "No scanner findings."

    user_content = f"""File: {filepath}

Deterministic scanner findings (already confirmed — do not duplicate):
{scanner_summary}

{"Knowledge base context (recent advisories):" + chr(10) + kb_context if kb_context else ""}

Source code:
```c
{source}
```"""

    try:
        text = llm.complete(
            system=ANALYSIS_SYSTEM_PROMPT,
            user=user_content,
            max_tokens=4096,
            json_mode=True,
        )
    except llm.LLMError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    clean = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    return json.loads(clean)
