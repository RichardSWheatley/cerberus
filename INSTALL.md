# CERBERUS G.U.A.R.D. — Installation & Usage

**G**ated **U**nified **A**nalysis, **R**egression & **D**efense

A three-headed C static analysis pipeline:
- **Head 1** — deterministic pattern scanner (94 checks) + MISRA C:2012 / CERT C catalog
- **Head 2** — AI deep analysis (any LLM provider) for undecidable / dataflow rules
- **Head 3** — Unity test generation + execution (proof the bug is reachable)
- **Intent layer** — does the code do what its names/comments/contracts promise?
- **Convergence loop** — iterates all heads until they reach consensus

---

## 1. Requirements

- Python 3.9+
- `gcc` (for Head 3 Unity test compilation)
- An API key for your chosen LLM provider (Head 2/3 only — Head 1 needs none)
- `git` (to clone Unity framework)

---

## 2. Install

```bash
# Clone or unpack cerberus into your project (or anywhere on PATH)
cd cerberus

# Python dependency (only needed for Head 2/3 — Head 1 is pure stdlib)
pip install anthropic        # or openai / google-generativeai for other providers

# Set your API key (Head 2/3 only)
export CERBERUS_LLM_PROVIDER="anthropic"   # anthropic | openai | google | openai_compatible
export CERBERUS_LLM_API_KEY="..."          # or provider-native var (ANTHROPIC_API_KEY, OPENAI_API_KEY, ...)

# Install the Unity test framework (Head 3 only)
bash setup_unity.sh          # clones ThrowTheSwitch/Unity into ./unity
```

That's it. No build step — it's pure Python.

---

## 3. Run

### Head 1 only — deterministic, instant, no API key

```bash
# Scan a single file
python -m cerberus.cli scan path/to/file.c

# This is the "free forever" mode — pattern scanner + MISRA/CERT catalog.
# Exit code: 0 = clean, 1 = high findings, 2 = critical findings.
```

### Full pipeline — all three heads + convergence

```bash
python -m cerberus.cli analyze path/to/file.c --unity-dir unity/src
```

### Analyze every changed C file in the current PR

```bash
python -m cerberus.cli pr --unity-dir unity/src
```

### Knowledge base (biweekly CVE/CWE/CERT refresh)

```bash
python -m cerberus.cli kb-update      # fetch latest advisories
python -m cerberus.cli kb-check       # is an update due? (exit 1 = yes)
```

---

## 4. Output

Reports land in `analysis_output/`:

| File | Purpose |
|------|---------|
| `<module>_pr_comment.md` | GitHub PR review comment |
| `<module>_summary.json` | Full machine-readable results |
| `<module>.sarif` | GitHub Security tab integration |
| `test_<module>.c` | Generated Unity tests (in `test_output/`) |

Every finding is tagged with its rule ID (`MISRA R.15.6`, `CERT INT34-C`,
`CWE-120`) so it's auditable.

---

## 5. GitHub Actions (automatic on every PR)

Copy `.github/workflows/cerberus.yml` into your repo, then:

1. Go to **Settings → Secrets and variables → Actions**
2. Add a secret named `CERBERUS_LLM_API_KEY` (and set `CERBERUS_LLM_PROVIDER` if not Anthropic)
3. Commit the workflow

The workflow runs:
- **On every PR** touching `.c`/`.h` — all heads, posts findings as a PR comment, uploads SARIF
- **Biweekly cron** (1st & 15th) — refreshes the knowledge base
- **Manual dispatch** — run any mode on demand

---

## 6. Module Map

```
cerberus/
├── scanner.py       Head 1 — 94 deterministic pattern checks
├── misra.py         MISRA C:2012 + CERT C traceable rule catalog
├── intent.py        Intent layer — name/comment/contract mismatch detection
├── llm.py          Vendor-agnostic LLM provider abstraction
├── ai_engine.py     Head 2 — AI deep analysis
├── test_gen.py      Head 3 — Unity test generation
├── test_runner.py   Head 3 — compile + execute + parse results
├── convergence.py   Iterative consensus loop across all heads
├── kb_updater.py    Biweekly CWE/CVE/CERT/MISRA knowledge base
├── reporter.py      PR comment / SARIF / annotations / JSON
└── cli.py           Entry point
```

---

## 7. What's free vs what needs the API key

| Capability | Needs API key? |
|------------|----------------|
| Head 1 pattern scanner (94 checks) | No |
| MISRA C:2012 / CERT C decidable rules | No |
| Intent layer (most checks) | No |
| Head 2 AI deep analysis | Yes (any provider) |
| Head 3 Unity test generation | Yes |
| Convergence loop (full) | Yes |
| Knowledge base updates | Yes |

Run `scan` mode with zero API cost forever. Use `analyze` when you want the
AI heads and test proof.
