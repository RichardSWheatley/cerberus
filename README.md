# ⛨ CERBERUS G.U.A.R.D.

**Gated Unified Analysis, Regression & Defense**

A three-headed C static analysis pipeline. Runs on every PR — nothing merges
without passing all three heads. Built for embedded/RTOS C where the commercial
tools have blind spots.

---

## The Three Heads

```
PR opened / push
       │
       ▼
┌──────────────────────┐
│  HEAD 1               │  Deterministic pattern scanner (94 checks) plus a
│  The Sentinel         │  traceable MISRA C:2012 / CERT C rule catalog.
│                       │  Banned functions, buffer overflows, off-by-one,
│  (instant, 0 API)     │  heap/printf/sleep-in-ISR, DMA cache coherence,
└───────┬──────────────┘  MMIO volatile. Guaranteed floor. Cannot hallucinate.
        │
        ▼
┌──────────────────────┐
│  INTENT LAYER         │  Does the code do what its names/comments/contracts
│                       │  promise? Ignored HAL return values, comment-vs-code
│  (semantic)           │  contradictions, init-without-zero, lock-without-unlock.
└───────┬──────────────┘
        │
        ▼
┌──────────────────────┐
│  HEAD 2               │  AI deep analysis via Claude. Cross-function data
│  The Oracle           │  flow, taint propagation, the undecidable MISRA/CERT
│                       │  rules (use-after-free, null-deref, wraparound),
│  (Claude Sonnet)      │  complexity, RTOS hazards. Informed by Knowledge Base.
└───────┬──────────────┘
        │
        ▼
┌──────────────────────┐
│  HEAD 3               │  Unity test generation + execution.
│  The Executioner      │  Regression tests targeting every finding.
│                       │  Boundary, NULL, overflow tests.
│  (compile + run)      │  Proof by fire — are the bugs actually reachable?
└───────┬──────────────┘
        │
        ▼
┌──────────────────────┐
│  CONVERGENCE LOOP     │  Iterates the heads until they reach consensus.
│                       │  Test PASS promotes a finding to confirmed; test
│                       │  FAIL on an unproven finding suppresses it. Loops
│                       │  until classifications stop changing. Full audit trail.
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

---

## Verdicts

| Verdict | Condition | Exit Code |
|---------|-----------|-----------|
| **BLOCK** | Any critical finding | 2 |
| **REQUEST CHANGES** | High findings or 3+ medium | 1 |
| **APPROVE** | Only low/info findings | 0 |

---

## Commands

```bash
# Full pipeline — all heads + intent + convergence
python -m cerberus.cli analyze src/device.c --unity-dir unity/src

# Head 1 only — deterministic scan + MISRA/CERT catalog (no API key, free)
python -m cerberus.cli scan src/device.c

# Analyze every changed C file in the current PR
python -m cerberus.cli pr --unity-dir unity/src

# Knowledge base (biweekly CVE/CWE/CERT/MISRA refresh)
python -m cerberus.cli kb-update
python -m cerberus.cli kb-check
```

---

## Setup

```bash
pip install anthropic              # Head 2/3 only; Head 1 is pure stdlib
export ANTHROPIC_API_KEY="sk-ant-..."
bash setup_unity.sh                # clones ThrowTheSwitch/Unity for Head 3

python -m cerberus.cli scan yourfile.c                       # free mode
python -m cerberus.cli analyze yourfile.c --unity-dir unity/src   # all heads
```

See **INSTALL.md** for the full walkthrough.

---

## What's free vs what needs the API key

| Capability | Needs API key? |
|------------|----------------|
| Head 1 pattern scanner (94 checks) | No |
| MISRA C:2012 / CERT C decidable rules | No |
| Intent layer (most checks) | No |
| Head 2 AI deep analysis | Yes |
| Head 3 Unity test generation | Yes |
| Convergence loop (full) | Yes |
| Knowledge base updates | Yes |

`scan` mode runs free, forever. `analyze` adds the AI heads and test proof.

---

## Standards Coverage

Every finding is tagged with its rule ID (`MISRA R.15.6`, `CERT INT34-C`,
`CWE-120`) and the official rule text, so it's auditable like the commercial
tools.

MISRA classifies each rule **decidable** (checkable by inspecting the code) or
**undecidable** (needs whole-program dataflow). G.U.A.R.D. implements the
decidable rules deterministically in Head 1 and routes the undecidable ones to
Head 2.

| Catalog | Implemented | Head 1 (deterministic) | Head 2 (AI) |
|---------|-------------|------------------------|-------------|
| MISRA C:2012 | 36 rules + directives | 27 | 8 |
| CERT C | 11 rules | 6 | 5 |

**Honest scope:** the decidable MISRA/CERT catalog — the high-frequency rules
that fire most on real embedded C — is yours for free and matches what the paid
tools flag day to day. The full ~159-rule MISRA catalog with formal symbolic
execution (for *compliance certification*) is still the domain of paid tools.
G.U.A.R.D. targets *defect-catching*, not certification.

---

## Where G.U.A.R.D. beats the commercial tools

The embedded/RTOS layer. SonarCloud, Coverity, and PVS-Studio largely ignore:

- Heap / printf / sleep / mutex / float / watchdog operations in ISR context
- DMA transfers without cache maintenance (clean/invalidate)
- MMIO register access without `volatile`
- Packed-struct unaligned access hazards on ARMv6-M/v7-M

Plus the **intent layer** (comment-vs-code contradiction, ignored HAL return
values) and the **closed test loop** — G.U.A.R.D. doesn't just flag a bug, it
generates a Unity test that proves the bug is reachable, then runs it.

---

## GitHub Actions

Copy `.github/workflows/cerberus.yml`, add `ANTHROPIC_API_KEY` as a repository
secret, and commit. It runs:

- **On every PR** touching `.c`/`.h` — all heads, posts findings as a PR
  comment, uploads SARIF to the Security tab
- **Biweekly cron** (1st & 15th) — refreshes the knowledge base
- **Manual dispatch** — any mode on demand

---

## Module Map

```
cerberus/
├── scanner.py       Head 1 — 94 deterministic pattern checks
├── misra.py         MISRA C:2012 + CERT C traceable rule catalog
├── intent.py        Intent layer — name/comment/contract mismatch detection
├── ai_engine.py     Head 2 — Claude deep analysis
├── test_gen.py      Head 3 — Unity test generation
├── test_runner.py   Head 3 — compile + execute + parse results
├── convergence.py   Iterative consensus loop across all heads
├── kb_updater.py    Biweekly CWE/CVE/CERT/MISRA knowledge base
├── reporter.py      PR comment / SARIF / annotations / JSON
└── cli.py           Entry point
```

---

## Head 1 Pattern Coverage

29 banned functions, plus memory safety, buffer/bounds, integer safety, control
flow, API misuse, concurrency, RTOS/embedded hazards, security, portability,
complexity metrics, and a MISRA/CERT subset. Extend it by adding entries to
`BANNED_FUNCTIONS` or `PATTERNS` in `cerberus/scanner.py`, or rules to
`MISRA_RULES` / `CERT_RULES` in `cerberus/misra.py`.

---

## License

MIT
