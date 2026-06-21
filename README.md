# ⛨ CERBERUS

**Three-Headed Code Guardian**

Hybrid static analysis pipeline for C codebases. Runs on every PR — nothing merges without passing all three heads.

## The Three Heads

```
PR opened / push
       │
       ▼
┌──────────────────────┐
│  HEAD 1               │  Deterministic pattern scanner.
│  The Sentinel         │  Banned functions, buffer overflows, off-by-one,
│                       │  malloc without NULL check, format strings,
│  (instant, 0 API)     │  heap-in-ISR, RTOS hazards.
└───────┬──────────────┘  Guaranteed floor. Cannot miss. Cannot hallucinate.
        │
        ▼
┌──────────────────────┐
│  HEAD 2               │  AI deep analysis via Claude.
│  The Oracle           │  Cross-function data flow, taint propagation,
│                       │  logic errors, complexity, UB, concurrency,
│  (Claude Sonnet)      │  RTOS-specific hazards.
└───────┬──────────────┘  Informed by the Knowledge Base.
        │
        ▼
┌──────────────────────┐
│  HEAD 3               │  Unity test generation + execution.
│  The Executioner      │  Regression tests targeting every finding.
│                       │  Boundary tests, NULL tests, overflow tests.
│  (compile + run)      │  Proof by fire — are the bugs reachable?
└───────┬──────────────┘
        │
        ▼
┌──────────────────────┐
│  VERDICT              │  PR comment with collapsible findings.
│                       │  GitHub annotations inline on the diff.
│  approve / request    │  SARIF for the Security tab.
│  changes / block      │  JSON summary for downstream tooling.
└──────────────────────┘
```

## Verdicts

| Verdict | Condition | Exit Code |
|---------|-----------|-----------|
| **BLOCK** | Any critical finding | 2 |
| **REQUEST CHANGES** | High findings or 3+ medium | 1 |
| **APPROVE** | Only low/info findings | 0 |

## Commands

```bash
# Full pipeline — all three heads
python -m cerberus.cli analyze src/device.c src/transport.c

# Head 1 only — deterministic scan (no API key, fast gate)
python -m cerberus.cli scan src/device.c

# Analyze all changed C files in current PR
python -m cerberus.cli pr

# Update knowledge base (biweekly)
python -m cerberus.cli kb-update

# Check if KB update is due
python -m cerberus.cli kb-check
```

## Setup

```bash
# 1. Install
pip install anthropic

# 2. Set API key
export ANTHROPIC_API_KEY="sk-ant-..."

# 3. Install Unity test framework
bash setup_unity.sh

# 4. Unleash
python -m cerberus.cli analyze your_code.c --unity-dir unity/src
```

## GitHub Actions

Copy `.github/workflows/cerberus.yml` to your repo. Add `ANTHROPIC_API_KEY` as a repository secret.

The workflow:
- **On PR** (changes to `.c`/`.h`): all three heads run, findings posted as PR comment, SARIF uploaded to Security tab
- **Biweekly cron** (1st and 15th): refreshes the Knowledge Base with latest CWEs, CVEs, CERT C, Zephyr advisories
- **Manual dispatch**: run either mode on demand

## Knowledge Base

Six sources tracked on a biweekly cycle:

| Source | Coverage |
|--------|----------|
| CWE Database | Weakness taxonomy, Top 25 changes |
| CERT C | Coding standard rule updates |
| NVD / CVE | High-severity CVEs for C libs and RTOS |
| MISRA C | Amendments and TCs to MISRA C:2012 |
| GCC/Clang | New warnings, sanitizer improvements |
| Zephyr Security | Project-specific advisories |

The KB feeds into Head 2 as context — analysis findings reflect the current threat landscape, not just training data.

## Output Formats

| File | Purpose |
|------|---------|
| `*_pr_comment.md` | GitHub PR review comment |
| `*_summary.json` | Machine-readable full results |
| `*.sarif` | GitHub Security tab integration |
| `test_*.c` | Generated Unity test files |
| stdout annotations | GitHub Actions inline annotations |

## Head 1 Pattern Coverage

The deterministic scanner catches without AI:

- **Banned functions**: `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `atoi`, `atol`, `atof`, `scanf` (without width), `strtok`
- **Buffer overflows**: `read`/`recv` with size exceeding buffer
- **Memory**: `malloc` without NULL check, `free` without NULLing pointer
- **Bounds**: off-by-one (`<=`) in loop conditions
- **Format strings**: printf-family with non-literal format
- **RTOS**: heap allocation in ISR-pattern functions
- **Safety**: function pointer calls without NULL guard, signed/unsigned comparison
- **Style**: global mutable state, missing include guards

## Extending Head 1

Add patterns to `cerberus/scanner.py`:

```python
# In BANNED_FUNCTIONS — simple function bans:
"dangerous_func": {
    "severity": "high",
    "cwe": "CWE-xxx",
    "title": "Use of dangerous_func()",
    "desc": "Why it's dangerous.",
    "fix": "What to use instead.",
}

# In PATTERNS — regex-based rules:
{
    "regex": r'your_pattern_here',
    "category": "security",
    "severity": "high",
    "title": "What it catches",
    "cwe": "CWE-xxx",
    "desc": "Why it matters.",
    "fix": "How to fix it.",
}
```

## License

MIT
