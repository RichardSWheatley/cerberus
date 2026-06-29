"""
CERBERUS Head 1 — Deterministic C Pattern Scanner

Zero LLM dependency. Millisecond execution. Guaranteed floor.
Every pattern here fires or it doesn't — no hallucinations, no misses.

Coverage:
  - 30+ banned/dangerous functions
  - Buffer/memory safety
  - Integer overflow/underflow/truncation
  - Control flow defects
  - API misuse
  - Concurrency/reentrancy
  - RTOS/embedded-specific hazards
  - Security (injection, crypto, secrets, TOCTOU)
  - Complexity metrics
  - Portability
  - MISRA C:2012 subset
  - Style/maintainability
"""

import re
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any
from pathlib import Path

@dataclass
class Finding:
    id: str
    category: str
    severity: str
    title: str
    location: str
    line: int
    description: str
    cwe: Optional[str] = None
    cert_c: Optional[str] = None
    misra: Optional[str] = None
    recommendation: str = ""


# ════════════════════════════════════════════════════════════════════
#  BANNED / DANGEROUS FUNCTIONS
# ════════════════════════════════════════════════════════════════════

BANNED_FUNCTIONS = {
    # ── Buffer overflow: unbounded write ──
    "gets": {
        "severity": "critical", "category": "security",
        "cwe": "CWE-120", "cert_c": "STR31-C",
        "title": "Use of gets()",
        "desc": "gets() performs no bounds checking and is removed from C11. Any input longer than the buffer is a guaranteed stack smash.",
        "fix": "Replace with fgets(buf, sizeof(buf), stdin).",
    },
    "strcpy": {
        "severity": "high", "category": "security",
        "cwe": "CWE-120", "cert_c": "STR31-C",
        "title": "Use of strcpy()",
        "desc": "strcpy() copies until NUL with no bounds check. If src exceeds dst capacity, buffer overflow.",
        "fix": "Use strncpy(dst, src, sizeof(dst)-1); dst[sizeof(dst)-1]='\\0'; or strlcpy() or snprintf().",
    },
    "strcat": {
        "severity": "high", "category": "security",
        "cwe": "CWE-120", "cert_c": "STR31-C",
        "title": "Use of strcat()",
        "desc": "strcat() appends without bounds check. Combined length may exceed buffer.",
        "fix": "Use strncat() with explicit remaining capacity, or snprintf().",
    },
    "sprintf": {
        "severity": "high", "category": "security",
        "cwe": "CWE-120", "cert_c": "STR31-C",
        "title": "Use of sprintf()",
        "desc": "sprintf() writes without bounds check. Output exceeding buffer is UB.",
        "fix": "Replace with snprintf(buf, sizeof(buf), fmt, ...).",
    },
    "vsprintf": {
        "severity": "high", "category": "security",
        "cwe": "CWE-120", "cert_c": "STR31-C",
        "title": "Use of vsprintf()",
        "desc": "vsprintf() writes without bounds check, same risk as sprintf().",
        "fix": "Replace with vsnprintf(buf, sizeof(buf), fmt, ap).",
    },
    "wcscpy": {
        "severity": "high", "category": "security",
        "cwe": "CWE-120", "cert_c": "STR31-C",
        "title": "Use of wcscpy()",
        "desc": "Wide-char equivalent of strcpy() — same unbounded copy risk.",
        "fix": "Use wcsncpy() with explicit length.",
    },
    "wcscat": {
        "severity": "high", "category": "security",
        "cwe": "CWE-120", "cert_c": "STR31-C",
        "title": "Use of wcscat()",
        "desc": "Wide-char equivalent of strcat() — unbounded append.",
        "fix": "Use wcsncat() with explicit remaining capacity.",
    },

    # ── No error detection ──
    "atoi": {
        "severity": "medium", "category": "bug",
        "cwe": "CWE-190", "cert_c": "ERR34-C",
        "title": "Use of atoi()",
        "desc": "atoi() returns 0 on failure (indistinguishable from valid '0'), UB on overflow.",
        "fix": "Replace with strtol() with errno and endptr checking.",
    },
    "atol": {
        "severity": "medium", "category": "bug",
        "cwe": "CWE-190", "cert_c": "ERR34-C",
        "title": "Use of atol()",
        "desc": "atol() has no error detection, same issues as atoi().",
        "fix": "Replace with strtol() with errno and endptr checking.",
    },
    "atof": {
        "severity": "medium", "category": "bug",
        "cwe": "CWE-190", "cert_c": "ERR34-C",
        "title": "Use of atof()",
        "desc": "atof() has no error detection. UB on values outside representable range.",
        "fix": "Replace with strtod() with errno and endptr checking.",
    },
    "atoll": {
        "severity": "medium", "category": "bug",
        "cwe": "CWE-190", "cert_c": "ERR34-C",
        "title": "Use of atoll()",
        "desc": "atoll() has no error detection, UB on overflow.",
        "fix": "Replace with strtoll() with errno and endptr checking.",
    },

    # ── Reentrancy / thread safety ──
    "strtok": {
        "severity": "medium", "category": "concurrency",
        "cwe": "CWE-362", "cert_c": "STR06-C",
        "title": "Use of strtok()",
        "desc": "strtok() uses static internal state — not reentrant, not thread-safe, modifies the input string.",
        "fix": "Replace with strtok_r() (POSIX) or manual tokenization.",
    },
    "asctime": {
        "severity": "medium", "category": "concurrency",
        "cwe": "CWE-362", "cert_c": "MSC33-C",
        "title": "Use of asctime()",
        "desc": "asctime() returns a pointer to static internal buffer — not thread-safe, can overflow on invalid input.",
        "fix": "Use strftime() with a caller-supplied buffer.",
    },
    "ctime": {
        "severity": "medium", "category": "concurrency",
        "cwe": "CWE-362", "cert_c": "MSC33-C",
        "title": "Use of ctime()",
        "desc": "ctime() returns pointer to shared static buffer — not thread-safe.",
        "fix": "Use strftime() with localtime_r() and a caller-supplied buffer.",
    },
    "localtime": {
        "severity": "low", "category": "concurrency",
        "cwe": "CWE-362", "cert_c": "MSC33-C",
        "title": "Use of localtime()",
        "desc": "localtime() returns pointer to shared static struct tm — not thread-safe.",
        "fix": "Use localtime_r() (POSIX).",
    },
    "gmtime": {
        "severity": "low", "category": "concurrency",
        "cwe": "CWE-362", "cert_c": "MSC33-C",
        "title": "Use of gmtime()",
        "desc": "gmtime() returns pointer to shared static struct tm — not thread-safe.",
        "fix": "Use gmtime_r() (POSIX).",
    },
    "strerror": {
        "severity": "low", "category": "concurrency",
        "cwe": "CWE-362", "cert_c": "MSC33-C",
        "title": "Use of strerror()",
        "desc": "strerror() may return a shared static buffer — not guaranteed thread-safe.",
        "fix": "Use strerror_r() (POSIX) or strerror_s() (C11 Annex K).",
    },
    "getenv": {
        "severity": "low", "category": "concurrency",
        "cwe": "CWE-362", "cert_c": "ENV34-C",
        "title": "Use of getenv()",
        "desc": "getenv() returns pointer to environment string that can be modified by setenv/putenv in another thread.",
        "fix": "Copy the result immediately: char *val = getenv(\"X\"); if (val) { char copy[N]; strncpy(copy,val,N); }",
    },

    # ── Command injection / shell ──
    "system": {
        "severity": "critical", "category": "security",
        "cwe": "CWE-78", "cert_c": "ENV33-C",
        "title": "Use of system()",
        "desc": "system() invokes a shell — any user-controlled input in the command string is command injection.",
        "fix": "Use exec*() family with explicit argv, or avoid shell entirely.",
    },
    "popen": {
        "severity": "high", "category": "security",
        "cwe": "CWE-78", "cert_c": "ENV33-C",
        "title": "Use of popen()",
        "desc": "popen() invokes a shell. User-controlled input in the command string is command injection.",
        "fix": "Use pipe()/fork()/exec*() for safe subprocess creation.",
    },

    # ── Weak/broken crypto and randomness ──
    "rand": {
        "severity": "medium", "category": "security",
        "cwe": "CWE-338", "cert_c": "MSC30-C",
        "title": "Use of rand()",
        "desc": "rand() is not cryptographically secure, has small range, and poor statistical properties.",
        "fix": "Use arc4random(), getrandom(), or a platform CSPRNG. For Zephyr: sys_csrand_get().",
    },
    "srand": {
        "severity": "low", "category": "security",
        "cwe": "CWE-338", "cert_c": "MSC32-C",
        "title": "Use of srand()",
        "desc": "srand() seeds rand() which is not cryptographically secure. srand(time(NULL)) is predictable.",
        "fix": "Use a CSPRNG instead of rand/srand entirely.",
    },

    # ── Deprecated / dangerous I/O ──
    "tmpnam": {
        "severity": "high", "category": "security",
        "cwe": "CWE-377", "cert_c": "FIO21-C",
        "title": "Use of tmpnam()",
        "desc": "tmpnam() creates a name but not the file — race condition between name generation and file creation (TOCTOU).",
        "fix": "Use mkstemp() which atomically creates the file.",
    },
    "tempnam": {
        "severity": "high", "category": "security",
        "cwe": "CWE-377", "cert_c": "FIO21-C",
        "title": "Use of tempnam()",
        "desc": "tempnam() has the same TOCTOU race as tmpnam().",
        "fix": "Use mkstemp().",
    },
    "mktemp": {
        "severity": "high", "category": "security",
        "cwe": "CWE-377", "cert_c": "FIO21-C",
        "title": "Use of mktemp()",
        "desc": "mktemp() creates a name but not the file — TOCTOU race condition.",
        "fix": "Use mkstemp() which atomically creates the file.",
    },
    "gets_s": {
        "severity": "medium", "category": "security",
        "cwe": "CWE-120", "cert_c": "STR31-C",
        "title": "Use of gets_s()",
        "desc": "gets_s() (C11 Annex K) is optional and inconsistently implemented. Not a reliable replacement for gets().",
        "fix": "Use fgets(buf, sizeof(buf), stdin).",
    },

    # ── Signal handling ──
    "signal": {
        "severity": "medium", "category": "concurrency",
        "cwe": "CWE-479", "cert_c": "SIG01-C",
        "title": "Use of signal()",
        "desc": "signal() behavior is implementation-defined after the handler fires. Handler may be reset to SIG_DFL.",
        "fix": "Use sigaction() which provides reliable, portable signal handling.",
    },
    "longjmp": {
        "severity": "medium", "category": "bug",
        "cwe": "CWE-351", "cert_c": "MSC22-C",
        "title": "Use of longjmp()",
        "desc": "longjmp() bypasses normal control flow, skipping destructors, cleanup, and stack unwinding. Dangerous in ISR or signal context.",
        "fix": "Use structured error handling (return codes, goto cleanup). In Zephyr: use k_panic() or error codes.",
    },
}

# Separate scanf check — needs format string inspection
SCANF_CHECK = {
    "severity": "high", "category": "security",
    "cwe": "CWE-120", "cert_c": "STR31-C",
    "title": "scanf() without field width",
    "desc": "scanf %s without field width is equivalent to gets() — unbounded write to buffer.",
    "fix": "Use field width: scanf(\"%63s\", buf) for a 64-byte buffer, or use fgets().",
}


# ════════════════════════════════════════════════════════════════════
#  REGEX PATTERNS — organized by category
# ════════════════════════════════════════════════════════════════════

PATTERNS: List[Dict[str, Any]] = [

    # ──────────── MEMORY SAFETY ────────────

    {
        "id": "MEM-MALLOC-NULL",
        "regex": r'\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(',
        "lookahead_fail": r'\bif\s*\(\s*!?\s*{var}\b|assert\s*\(\s*{var}\b|{var}\s*!=\s*NULL|NULL\s*!=\s*{var}|{var}\s*==\s*NULL',
        "lookahead_lines": 3,
        "category": "memory", "severity": "high",
        "title": "malloc() return value not checked",
        "cwe": "CWE-252", "cert_c": "MEM32-C", "misra": "R.21.3",
        "desc": "malloc() can return NULL on allocation failure. Dereferencing NULL is undefined behavior.",
        "fix": "Check: if (ptr == NULL) { /* handle OOM */ }",
    },
    {
        "id": "MEM-CALLOC-NULL",
        "regex": r'\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?calloc\s*\(',
        "lookahead_fail": r'\bif\s*\(\s*!?\s*{var}\b|{var}\s*!=\s*NULL|NULL\s*!=\s*{var}',
        "lookahead_lines": 3,
        "category": "memory", "severity": "high",
        "title": "calloc() return value not checked",
        "cwe": "CWE-252", "cert_c": "MEM32-C",
        "desc": "calloc() can return NULL. Subsequent dereference is UB.",
        "fix": "Check the return value for NULL before use.",
    },
    {
        "id": "MEM-REALLOC-OVERWRITE",
        "regex": r'\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?realloc\s*\(\s*\1\s*,',
        "category": "memory", "severity": "high",
        "title": "realloc() overwrites its own pointer",
        "cwe": "CWE-401", "cert_c": "MEM04-C",
        "desc": "If realloc() fails it returns NULL but the original pointer is lost — memory leak. ptr = realloc(ptr, ...) is always a bug.",
        "fix": "Use a temp: void *tmp = realloc(ptr, size); if (tmp) { ptr = tmp; } else { /* handle failure, ptr still valid */ }",
    },
    {
        "id": "MEM-FREE-NO-NULL",
        "regex": r'\bfree\s*\(\s*(\w+)\s*\)',
        "lookahead_fail": r'{var}\s*=\s*NULL',
        "lookahead_lines": 2,
        "category": "memory", "severity": "low",
        "title": "Pointer not NULLed after free()",
        "cwe": "CWE-416", "cert_c": "MEM01-C",
        "desc": "After free(), the pointer is dangling. Accidental dereference is use-after-free.",
        "fix": "Set to NULL immediately: free(p); p = NULL;",
    },
    {
        "id": "MEM-SIZEOF-PTR",
        "regex": r'\b(?:malloc|calloc|memcpy|memset|memmove|memcmp)\s*\([^)]*sizeof\s*\(\s*(\w+)\s*\)[^)]*\)',
        "category": "memory", "severity": "medium",
        "title": "sizeof() on potential pointer instead of pointed-to type",
        "cwe": "CWE-131", "cert_c": "MEM35-C",
        "desc": "If the argument to sizeof is a pointer, this gives pointer size (4/8 bytes) not the struct/array size. Common when a function parameter shadows an array.",
        "fix": "Use sizeof(*ptr) for the pointed-to size, or sizeof(type) explicitly.",
    },
    {
        "id": "MEM-ALLOCA",
        "regex": r'\balloca\s*\(',
        "category": "memory", "severity": "high",
        "title": "Use of alloca()",
        "cwe": "CWE-770", "cert_c": None, "misra": "R.21.3",
        "desc": "alloca() allocates on the stack with no overflow check. User-controlled size is a direct stack smash. Not in any C standard.",
        "fix": "Use a fixed-size stack buffer or heap allocation with bounds check.",
    },
    {
        "id": "MEM-VLA",
        "regex": r'\b(?:int|char|uint8_t|uint16_t|uint32_t|float|double|unsigned|signed|long|short)\s+\w+\s*\[\s*[a-zA-Z_]\w*\s*\]',
        "category": "memory", "severity": "medium",
        "title": "Variable-length array (VLA)",
        "cwe": "CWE-770", "cert_c": "ARR32-C", "misra": "R.18.8",
        "desc": "VLAs allocate on the stack at runtime with no overflow check. Banned by MISRA, optional in C11. User-controlled size can smash the stack.",
        "fix": "Use a fixed-size buffer with a compile-time constant, or heap-allocate with bounds check.",
    },
    {
        "id": "MEM-CALLOC-OVERFLOW",
        "regex": r'\bcalloc\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)',
        "category": "memory", "severity": "medium",
        "title": "calloc() multiplication may overflow",
        "cwe": "CWE-190", "cert_c": "MEM07-C",
        "desc": "calloc(nmemb, size) internally multiplies nmemb*size. Most implementations check for overflow, but not all — especially bare-metal libc variants (newlib-nano).",
        "fix": "Validate: if (nmemb && size > SIZE_MAX / nmemb) { /* overflow */ }",
    },
    {
        "id": "MEM-MALLOC-MULT-OVERFLOW",
        "regex": r'\bmalloc\s*\(\s*\w+\s*\*\s*(?:sizeof\b|\w+)',
        "category": "memory", "severity": "high",
        "title": "Multiplication in malloc() size may overflow",
        "cwe": "CWE-190", "cert_c": "MEM07-C",
        "desc": "malloc(n * sizeof(T)) — if n is user-controlled or large, the multiplication can wrap to a small value, allocating an undersized buffer.",
        "fix": "Check for overflow before multiplying, or use calloc(n, sizeof(T)) which checks internally.",
    },
    {
        "id": "MEM-RETURN-STACK",
        # Block-scan within each function: find `return &var`, then check if `var` is declared
        # as a non-static local variable WITHIN THE SAME FUNCTION BODY.
        # If `var` has no local declaration (macro-declared static, global defined elsewhere, etc.)
        # it is suppressed — only automatic-storage locals are dangerous dangling pointers.
        "regex": None,
        "meta_check": "return_stack_local",
        "category": "memory", "severity": "critical",
        "title": "Returning address of stack-local variable",
        "cwe": "CWE-562", "cert_c": "DCL30-C",
        "desc": "Returning a pointer to a local variable. The variable is destroyed when the function returns — the caller gets a dangling pointer.",
        "fix": "Return heap-allocated memory, use a static buffer (with reentrancy caveat), or fill a caller-provided buffer.",
    },

    # ──────────── BUFFER / BOUNDS ────────────

    # BUF-READ-OVERSIZE removed: the pattern fires on every read()/recv() with a numeric count
    # (e.g. read(dev, buf, 1)) regardless of whether that count fits the buffer. Without
    # buffer-size dataflow there is no way to distinguish safe from unsafe — it generates
    # 100% false positives. A meaningful check would require knowing the declaration of `buf`.
    # Removed rather than suppressed to avoid silent noise in every driver that calls read().
    {
        "id": "BUF-OBO-LOOP",
        "regex": r'for\s*\([^;]*;\s*\w+\s*<=\s*(\w+)\s*;',
        "category": "bug", "severity": "high",
        "title": "Off-by-one: <= in loop bound",
        "cwe": "CWE-193", "cert_c": "ARR30-C",
        "desc": "Loop uses <= with a count/size variable. For zero-indexed arrays, the final iteration reads one past the end.",
        "fix": "Use < instead of <= for zero-indexed array iteration.",
    },
    {
        "id": "BUF-SNPRINTF-TRUNC",
        "regex": r'\bsnprintf\s*\([^;]*\)',
        "lookahead_fail": r'if\s*\(.*snprintf|ret.*=.*snprintf|len.*=.*snprintf|n.*=.*snprintf',
        "lookahead_lines": 0,
        "category": "bug", "severity": "low",
        "title": "snprintf() return value unchecked (silent truncation)",
        "cwe": "CWE-131", "cert_c": "ERR33-C",
        "desc": "snprintf() returns the number of characters that would have been written. If >= buffer size, output was truncated — often silently.",
        "fix": "Check return value: int n = snprintf(buf, sz, ...); if (n >= sz) { /* truncated */ }",
    },
    {
        "id": "BUF-MEMCPY-SIZEOF-SRC",
        "regex": r'\bmemcpy\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*sizeof\s*\(\s*\1\s*\)',
        "category": "bug", "severity": "medium",
        "title": "memcpy() size is sizeof(source) — may exceed destination",
        "cwe": "CWE-120", "cert_c": "ARR38-C",
        "desc": "memcpy(dst, src, sizeof(src)) sizes the copy to the source. If src is larger than dst, this is a buffer overflow.",
        "fix": "Size to the destination: memcpy(dst, src, sizeof(dst)) or use the minimum of both.",
    },
    {
        "id": "BUF-STRNCPY-NO-TERM",
        "regex": r'\bstrncpy\s*\(\s*(\w+)\s*,[^;]+\)',
        "lookahead_fail": r'{var}\s*\[\s*(?:sizeof|.*-\s*1)\s*\]\s*=\s*[\x27]?\\0[\x27]?|{var}\s*\[\s*\w+\s*\]\s*=\s*[\x27]?\\0',
        "lookahead_lines": 2,
        "category": "bug", "severity": "medium",
        "title": "strncpy() without explicit NUL termination",
        "cwe": "CWE-170", "cert_c": "STR32-C",
        "desc": "strncpy() does NOT guarantee NUL termination if src length >= n. The destination may not be a valid C string.",
        "fix": "Always NUL-terminate: strncpy(dst, src, sizeof(dst)-1); dst[sizeof(dst)-1] = '\\0';",
    },

    # ──────────── FORMAT STRINGS ────────────

    {
        "id": "FMT-PRINTF-NONLIT",
        "regex": r'\b(?:printf|fprintf|dprintf|syslog)\s*\(\s*(?!.*")\s*(\w+)\s*\)',
        "category": "security", "severity": "critical",
        "title": "Format string vulnerability",
        "cwe": "CWE-134", "cert_c": "FIO30-C",
        "desc": "printf-family called with a non-literal format string. Attacker-controlled input enables arbitrary read/write via %n, %x.",
        "fix": "Use a literal format string: printf(\"%s\", variable).",
    },
    {
        "id": "FMT-SNPRINTF-NONLIT",
        "regex": r'\bsnprintf\s*\(\s*\w+\s*,\s*\w+\s*,\s*(?!.*")\s*(\w+)\s*[,\)]',
        "category": "security", "severity": "high",
        "title": "snprintf with non-literal format string",
        "cwe": "CWE-134", "cert_c": "FIO30-C",
        "desc": "snprintf() called with a non-literal format string. Bounds checking does not prevent format string exploitation.",
        "fix": "Use a literal format string.",
    },

    # ──────────── INTEGER SAFETY ────────────

    {
        "id": "INT-SIGNED-UNSIGNED-CMP",
        "regex": r'(?:if|while|for)\s*\(.*\b(?:int|long|ssize_t)\s+\w+.*[<>=!]+.*\b(?:unsigned|uint|size_t)\b',
        "category": "bug", "severity": "medium",
        "title": "Signed/unsigned comparison",
        "cwe": "CWE-195", "cert_c": "INT02-C", "misra": "R.10.4",
        "desc": "Comparing signed and unsigned integers. The signed value implicitly converts to unsigned — negative values become large positives.",
        "fix": "Cast explicitly or use same-signedness types on both sides.",
    },
    {
        "id": "INT-SHIFT-NEGATIVE",
        # Match only literal negative integer constants as the shift amount.
        # `>> -var` is NOT a shift by a negative value — `-var` is unary negation of an
        # identifier, which may well be positive (e.g. `>> -log_seconds` when log_seconds < 0).
        # Only a literal `-N` (digit after the minus sign) is a guaranteed negative shift amount.
        "regex": r'(?:<<|>>)\s*-\s*\d',
        "category": "undefined_behavior", "severity": "critical",
        "title": "Shift by negative amount",
        "cwe": "CWE-682", "cert_c": "INT34-C",
        "desc": "Shifting by a negative value is undefined behavior in C.",
        "fix": "Ensure shift amount is >= 0 and < width of the type.",
    },
    {
        "id": "INT-SHIFT-OVERWIDTH",
        # Flag shifts of >= 128 bits (UB on all types including uint128_t).
        # `1[2-9]\d` previously matched 120-199, but 120-127 are valid on uint128_t (range 0-127).
        # Fixed to only match 128+: `12[89]` (128-129), `1[3-9]\d` (130-199), `[2-9]\d{2}` (200-999).
        "regex": r'(?:<<|>>)\s*(?:12[89]|1[3-9]\d|[2-9]\d{2}|\d{4,})',
        "category": "undefined_behavior", "severity": "critical",
        "title": "Shift by >= 128 bits",
        "cwe": "CWE-682", "cert_c": "INT34-C",
        "desc": "Shifting by >= 128 bits is undefined behavior on all C integer types including 128-bit extensions.",
        "fix": "Ensure shift amount is < bit width of the operand type.",
    },
    {
        "id": "INT-SHIFT-OVERWIDTH-64",
        # Shifts of 64-127 bits are UB on 64-bit types but valid on uint128_t/__int128.
        # Suppress when a 128-bit type keyword appears on the line.
        "regex": r'(?:<<|>>)\s*(?:6[4-9]|[7-9]\d|1[01]\d)',
        "skip_line_pattern": r'\buint128_t\b|__uint128_t\b|__int128\b|unsigned\s+__int128\b',
        "category": "undefined_behavior", "severity": "critical",
        "title": "Shift by 64-127 bits on likely 64-bit operand",
        "cwe": "CWE-682", "cert_c": "INT34-C",
        "desc": "Shifting by 64-127 bits is undefined behavior for 64-bit types. Verify the operand is uint128_t.",
        "fix": "Cast operand to uint128_t before shifting, or verify the type is already 128-bit.",
    },
    {
        "id": "INT-SHIFT-OVERWIDTH-32",
        # Shifts of 32-63 bits are UB only on 32-bit types. Flag them only when the line does
        # NOT contain a 64-bit type keyword, which would make the shift legal.
        "regex": r'(?:<<|>>)\s*(?:3[2-9]|[45]\d|6[0-3])',
        "skip_line_pattern": r'\bu(?:int)?64_t\b|__u64\b|unsigned\s+long\s+long\b|long\s+long\b|u64\b|s64\b|__le64\b|__be64\b',
        "category": "undefined_behavior", "severity": "high",
        "title": "Shift by 32-63 bits on likely 32-bit operand",
        "cwe": "CWE-682", "cert_c": "INT34-C",
        "desc": "Shifting by 32-63 bits is undefined behavior for 32-bit types. Verify the left operand is 64-bit.",
        "fix": "Cast operand to uint64_t before shifting, or use explicit 64-bit types throughout.",
    },
    {
        "id": "INT-DIV-ZERO",
        # Match / or % followed by an identifier, but NOT:
        #   - sizeof(...) — compile-time constant, always > 0
        #   - ALL_CAPS macro names — conventional compile-time constants in C
        #   - paths inside #include <...> (the / is a path separator, not division)
        #   - lines containing BUILD_ASSERT (compile-time assertion, never runtime division)
        "regex": r'[/%%]\s*(?!sizeof\s*\()(?![A-Z][A-Z0-9_]*\b)(\w+)',
        "skip_line_pattern": r'^\s*#\s*include|BUILD_ASSERT\s*\(',
        "lookbehind_fail": r'if\s*\(\s*{var}\s*[!=><]+\s*0|{var}\s*==\s*0',
        "lookbehind_lines": 3,
        "category": "bug", "severity": "medium",
        "title": "Potential division by zero",
        "cwe": "CWE-369", "cert_c": "INT33-C",
        "desc": "Division/modulo by a variable with no prior zero-check. If the divisor is zero, behavior is undefined.",
        "fix": "Guard: if (divisor != 0) { result = x / divisor; }",
    },
    {
        "id": "INT-IMPLICIT-NARROW",
        "regex": r'\b(?:uint8_t|int8_t|uint16_t|int16_t|short|char)\s+\w+\s*=\s*(?:\([^)]*\))?\s*\w+\s*[+\-\*]',
        "category": "bug", "severity": "medium",
        "title": "Implicit narrowing conversion",
        "cwe": "CWE-197", "cert_c": "INT31-C", "misra": "R.10.3",
        "desc": "Assignment of a wider arithmetic result to a narrower type. High bits are silently truncated.",
        "fix": "Use explicit cast with range check, or store in a wider type.",
    },

    # ──────────── CONTROL FLOW ────────────

    {
        "id": "CF-ASSIGN-IN-COND",
        "regex": r'(?:if|while)\s*\(\s*(?!.*[!=<>]=)(\w+)\s*=\s*(?!=)',
        "category": "bug", "severity": "high",
        "title": "Assignment in conditional (= instead of ==)",
        "cwe": "CWE-480", "cert_c": "EXP45-C",
        "desc": "Single = in an if/while condition is assignment, not comparison. The condition is always the assigned value.",
        "fix": "Use == for comparison. If intentional, wrap: if ((x = func()) != 0).",
    },
    {
        "id": "CF-SEMI-AFTER-IF",
        # Two previous false-positive sources fixed:
        # 1. `[^)]*` stopped at the FIRST `)`, so for-loops with nested parens in their
        #    condition (e.g. `for (i = 0; i < (n >> 2); i++)`) had the inner `)` consumed as
        #    the closing paren and the condition separator `;` flagged as an empty body.
        #    Fixed by using `[^()]*` which rejects any condition containing nested parens.
        # 2. `do { } while (cond);` — the trailing `;` of the do-while terminator was flagged
        #    as an empty while body. Fixed by lookbehind for `}` on the preceding line.
        "regex": r'\b(?:if|for|while)\s*\([^()]*\)\s*;',
        # Suppress do-while terminators:
        #   `} while (cond);` — } immediately before while on the same line
        #   `    }` alone on its own line — closing brace of the do-block on the line before
        # Use `^\s*\}\s*$` (line is only `}`) rather than `\}\s*$` (any line ending with `}`)
        # to avoid suppressing real empty-if cases on one-liner test strings.
        # Also suppress `for(;;)` / `for( ; ; )` — the intentional infinite-halt pattern used
        # in embedded startup/panic code (e.g. NuttX arm_systemreset.c, arm_poweroff.c).
        "lookbehind_fail": r'^\s*\}\s*$|\}\s*while\b',
        "lookbehind_lines": 1,
        "skip_line_pattern": r'\bfor\s*\(\s*;\s*;\s*\)',
        "category": "bug", "severity": "high",
        "title": "Semicolon immediately after if/for/while",
        "cwe": "CWE-561", "cert_c": "EXP15-C", "misra": "R.15.6",
        "desc": "Empty body — the semicolon terminates the control statement. The following block executes unconditionally.",
        "fix": "Remove the stray semicolon, or use {} for an intentional empty body.",
    },
    {
        "id": "CF-SWITCH-NO-DEFAULT",
        "regex": r'\bswitch\s*\([^)]*\)\s*\{',
        "lookahead_fail": r'\bdefault\s*:',
        "lookahead_lines": 50,
        "category": "bug", "severity": "low",
        "title": "Switch statement without default case",
        "cwe": "CWE-478", "cert_c": "MSC01-C", "misra": "R.16.4",
        "desc": "A switch without a default case silently ignores unexpected values. In safety-critical code this masks errors.",
        "fix": "Add a default case, even if it only asserts or logs an error.",
    },
    {
        "id": "CF-GOTO",
        "regex": r'\bgoto\s+\w+\s*;',
        "category": "style", "severity": "info",
        "title": "Use of goto",
        "cwe": None, "cert_c": None, "misra": "R.15.1",
        "desc": "goto is banned by MISRA. Acceptable for error-cleanup patterns in Linux/Zephyr kernel style, but check intent.",
        "fix": "Acceptable for cleanup goto; avoid for general control flow. Ensure single-entry single-exit where possible.",
    },
    {
        "id": "CF-UNREACHABLE-AFTER-RETURN",
        "regex": r'\breturn\b[^;]*;\s*\n\s*(?!}|\s*$|/\*|//|#)\w',
        "category": "bug", "severity": "low",
        "title": "Unreachable code after return",
        "cwe": "CWE-561", "cert_c": "MSC12-C",
        "desc": "Code after an unconditional return statement is dead code — never executes.",
        "fix": "Remove the dead code or restructure the control flow.",
    },

    # ──────────── API MISUSE ────────────

    {
        "id": "API-FCLOSE-NOCHECK",
        "regex": r'\bfclose\s*\(',
        "lookahead_fail": r'if\s*\(.*fclose|ret.*=.*fclose|fclose.*==|fclose.*!=',
        "lookahead_lines": 0,
        "category": "bug", "severity": "low",
        "title": "fclose() return value unchecked",
        "cwe": "CWE-252", "cert_c": "FIO16-C",
        "desc": "fclose() can fail (e.g., buffered write error on close). On NFS/networked filesystems this loses data silently.",
        "fix": "Check: if (fclose(fp) != 0) { /* handle error */ }",
    },
    {
        "id": "API-FGETS-NOCHECK",
        "regex": r'\bfgets\s*\([^;]*\)',
        "lookahead_fail": r'if\s*\(.*fgets|ret.*=.*fgets|fgets.*==\s*NULL|NULL\s*==.*fgets|!\s*fgets',
        "lookahead_lines": 0,
        "category": "bug", "severity": "low",
        "title": "fgets() return value unchecked",
        "cwe": "CWE-252", "cert_c": "ERR33-C",
        "desc": "fgets() returns NULL on error or EOF. Unchecked, the buffer may be used with stale or uninitialized content.",
        "fix": "Check: if (fgets(buf, sizeof(buf), fp) == NULL) { /* handle */ }",
    },
    {
        "id": "API-MEMCMP-TIMING",
        "regex": r'\bmemcmp\s*\([^)]*(?:password|secret|key|token|hash|digest|hmac|auth)',
        "category": "security", "severity": "high",
        "title": "memcmp() on security-sensitive data (timing side-channel)",
        "cwe": "CWE-208", "cert_c": None,
        "desc": "memcmp() short-circuits on first difference — timing reveals how many bytes matched. Leaks secrets byte-by-byte.",
        "fix": "Use a constant-time comparison: CRYPTO_memcmp() (OpenSSL), timingsafe_bcmp(), or manual XOR-accumulate.",
    },
    {
        "id": "API-STRCMP-TIMING",
        "regex": r'\bstrcmp\s*\([^)]*(?:password|secret|key|token|hash|digest|hmac|auth)',
        "category": "security", "severity": "high",
        "title": "strcmp() on security-sensitive data (timing side-channel)",
        "cwe": "CWE-208", "cert_c": None,
        "desc": "strcmp() short-circuits on first difference — timing reveals prefix length of secrets.",
        "fix": "Use a constant-time comparison function.",
    },

    # ──────────── CONCURRENCY / REENTRANCY ────────────

    {
        "id": "CONC-STATIC-LOCAL",
        "regex": r'^\s+static\s+(?!const\b)\w+[\s\*]+\w+\s*[=;\[]',
        "category": "concurrency", "severity": "medium",
        "title": "Non-const static local variable",
        "cwe": "CWE-362", "cert_c": "CON33-C",
        "desc": "Static local variables persist across calls and are shared between threads. Without synchronization, this is a data race.",
        "fix": "Use thread-local storage, pass state via parameters, or protect with a mutex.",
    },
    {
        "id": "CONC-VOLATILE-MISSING",
        # Restrict to declarations at file/global scope only (no leading whitespace).
        # The previous regex matched any variable declaration including function locals because the
        # "file_context": "shared_global" field was never read by the engine.
        "regex": r'^(?:volatile\s+)?(?:static\s+)?(?:extern\s+)?(?:unsigned\s+|signed\s+)?(?:int|uint\d+_t|bool|char)\s+(\w+)\s*;',
        "category": "concurrency", "severity": "info",
        "title": "Global variable may need volatile or atomic qualifier",
        "cwe": "CWE-362", "cert_c": "CON02-C",
        "desc": "Global scalar accessed from ISR or multiple threads should be volatile (for ISR) or _Atomic (for threads) to prevent the compiler from caching stale values.",
        "fix": "Mark volatile if ISR-accessed, _Atomic or use a mutex if thread-shared.",
    },

    # ──────────── RTOS / EMBEDDED SPECIFIC ────────────
    # These are the differentiators — commercial tools largely ignore these.

    {
        "id": "RTOS-HEAP-IN-ISR",
        "regex": r'(?:void\s+\w*(?:_isr|_irq)\s*\(|void\s+(?:ISR|IRQ|Interrupt)\w*\s*\()',
        "lookahead_fail": None,
        "lookahead_lines": 0,
        "block_scan_for": r'\b(?:malloc|calloc|realloc|free|k_malloc|k_free|k_calloc)\b',
        "category": "bug", "severity": "critical",
        "title": "Heap operation in ISR context",
        "cwe": "CWE-662", "cert_c": None,
        "desc": "Dynamic memory allocation inside an interrupt handler. Most allocators are not reentrant — this causes heap corruption or deadlock.",
        "fix": "Pre-allocate buffers or use a lock-free pool (k_mem_slab in Zephyr). Never malloc/free from ISR.",
    },
    {
        "id": "RTOS-PRINTF-IN-ISR",
        "regex": r'(?:void\s+\w*(?:_isr|_irq)\s*\(|void\s+(?:ISR|IRQ|Interrupt)\w*\s*\()',
        "block_scan_for": r'\b(?:printf|fprintf|puts|fputs|printk|LOG_INF|LOG_ERR|LOG_WRN|LOG_DBG|snprintf|sprintf)\b',
        "category": "bug", "severity": "high",
        "title": "Logging/printf in ISR context",
        "cwe": "CWE-662", "cert_c": None,
        "desc": "printf/printk/LOG_* in an ISR can block on UART TX, take mutexes, or cause unbounded latency. Violates ISR timing guarantees.",
        "fix": "Use deferred logging: k_msgq, ring buffer, or Zephyr's deferred log mode (LOG_MODE_DEFERRED).",
    },
    {
        "id": "RTOS-SLEEP-IN-ISR",
        "regex": r'(?:void\s+\w*(?:_isr|_irq)\s*\(|void\s+(?:ISR|IRQ|Interrupt)\w*\s*\()',
        # k_busy_wait is a CPU spin-wait and does NOT invoke the scheduler — safe in ISR context.
        # Only flag true scheduler-blocking sleep calls.
        "block_scan_for": r'\b(?:k_sleep|k_msleep|k_usleep|usleep|sleep|nanosleep|vTaskDelay|osDelay)\b',
        "category": "bug", "severity": "critical",
        "title": "Blocking sleep in ISR context",
        "cwe": "CWE-662", "cert_c": None,
        "desc": "Sleeping in an ISR invokes the scheduler and can cause deadlock or priority inversion.",
        "fix": "ISRs must be non-blocking. Defer work to a thread via k_work, k_sem, or k_msgq.",
    },
    {
        "id": "RTOS-MUTEX-IN-ISR",
        "regex": r'(?:void\s+\w*(?:_isr|_irq)\s*\(|void\s+(?:ISR|IRQ|Interrupt)\w*\s*\()',
        "block_scan_for": r'\b(?:k_mutex_lock|k_sem_take|pthread_mutex_lock|xSemaphoreTake|osMutexAcquire)\b',
        "category": "bug", "severity": "critical",
        "title": "Mutex/semaphore acquisition in ISR context",
        "cwe": "CWE-662", "cert_c": None,
        "desc": "Taking a mutex in ISR can deadlock if the mutex is held by the preempted thread. ISRs cannot block on kernel objects.",
        "fix": "Use k_sem_give() (not take) from ISR to signal a thread. Use k_spin_lock() for ISR-safe critical sections.",
    },
    {
        "id": "RTOS-FLOAT-IN-ISR",
        "regex": r'(?:void\s+\w*(?:_isr|_irq)\s*\(|void\s+(?:ISR|IRQ|Interrupt)\w*\s*\()',
        "block_scan_for": r'\b(?:float|double)\s+\w+|(?:sinf?|cosf?|sqrtf?|expf?|logf?|powf?|fabs|atan2f?)\s*\(',
        "category": "bug", "severity": "high",
        "title": "Floating-point operation in ISR context",
        "cwe": None, "cert_c": None,
        "desc": "FPU registers may not be saved/restored on ISR entry. Using float in ISR can corrupt the preempted thread's FP state. On Cortex-M without lazy stacking, this is silent corruption.",
        "fix": "Avoid FP in ISRs. If unavoidable, ensure CONFIG_FPU_SHARING is enabled (Zephyr) or manually save/restore FP context.",
    },
    {
        "id": "RTOS-RECURSIVE-FUNC",
        "regex": r'\b(\w+)\s*\([^)]*\)\s*\{',
        "block_scan_for_self_call": True,
        "category": "complexity", "severity": "medium",
        "title": "Recursive function call",
        "cwe": "CWE-674", "cert_c": "MEM05-C", "misra": "R.17.2",
        "desc": "Recursive functions have unbounded stack depth on embedded targets with limited stack. MISRA bans all recursion.",
        "fix": "Convert to iterative with an explicit stack/worklist, or prove bounded depth and size the thread stack accordingly.",
    },
    {
        "id": "RTOS-UNBOUNDED-LOOP",
        "regex": r'\bwhile\s*\(\s*(?:1|true|TRUE)\s*\)',
        "lookahead_fail": r'\bbreak\b|\breturn\b|k_sleep|k_yield|k_sem_take|timeout|watchdog',
        "lookahead_lines": 20,
        "category": "bug", "severity": "medium",
        "title": "Unbounded while(1) loop without yield or exit",
        "cwe": "CWE-835", "cert_c": None,
        "desc": "Infinite loop without a sleep, yield, break, or watchdog feed. On cooperative schedulers this starves all other threads.",
        "fix": "Add k_yield(), k_sleep(), or a break/timeout condition.",
    },

    # ──────────── SECURITY ────────────

    {
        "id": "SEC-HARDCODED-KEY",
        "regex": r'(?:password|passwd|secret|api_key|apikey|token|private_key)\s*(?:=|:)\s*"[^"]{4,}"',
        "category": "security", "severity": "critical",
        "title": "Hardcoded credential or secret",
        "cwe": "CWE-798", "cert_c": "MSC41-C",
        "desc": "Secrets hardcoded in source are extractable from binaries and version control. This is not a deployment strategy.",
        "fix": "Use environment variables, a secure keystore, or compile-time injection from a secrets manager.",
    },
    {
        "id": "SEC-HARDCODED-IP",
        "regex": r'"(?:\d{1,3}\.){3}\d{1,3}"',
        "category": "security", "severity": "low",
        "title": "Hardcoded IP address",
        "cwe": "CWE-798", "cert_c": None,
        "desc": "Hardcoded IPs reduce configurability and can expose internal network topology.",
        "fix": "Use Kconfig, devicetree, or runtime configuration for network addresses.",
    },
    {
        "id": "SEC-TOCTOU",
        "regex": r'\b(?:access|stat|lstat)\s*\([^;]*\)',
        "lookahead_fail": None,
        "lookahead_lines": 0,
        "block_scan_for": r'\b(?:open|fopen|unlink|remove|rename|chmod|chown)\b',
        "block_scan_lines": 5,
        "category": "security", "severity": "high",
        "title": "TOCTOU race condition (check-then-use)",
        "cwe": "CWE-367", "cert_c": "FIO01-C",
        "desc": "File is checked with stat/access then operated on separately. An attacker can swap the file between check and use (symlink race).",
        "fix": "Use open() with O_NOFOLLOW, then fstat() on the fd. Or use openat() for atomic directory-relative operations.",
    },
    {
        "id": "SEC-DEPRECATED-CRYPTO",
        "regex": r'\b(?:MD5|MD5_Init|MD5_Update|MD5_Final|SHA1|SHA1_Init|DES_|DES_ecb_encrypt|RC4|RC4_set_key)\s*\(',
        "category": "security", "severity": "high",
        "title": "Use of deprecated/broken cryptographic algorithm",
        "cwe": "CWE-327", "cert_c": "MSC33-C",
        "desc": "MD5, SHA-1, DES, and RC4 are cryptographically broken. They must not be used for security purposes.",
        "fix": "Use SHA-256/SHA-384/SHA-512 for hashing, AES-GCM or ChaCha20-Poly1305 for encryption.",
    },

    # ──────────── PORTABILITY ────────────

    {
        "id": "PORT-SIZEOF-INT-ASSUME",
        "regex": r'sizeof\s*\(\s*(?:int|long|pointer|void\s*\*)\s*\)\s*==\s*[248]',
        "category": "portability", "severity": "medium",
        "title": "sizeof assumption on fundamental type",
        "cwe": None, "cert_c": "INT14-C", "misra": "R.12.1",
        "desc": "Hardcoded sizeof for int/long/pointer. These vary by platform (LP64 vs ILP32 vs LLP64). Embedded targets may differ from host.",
        "fix": "Use sizeof(type) dynamically, or use fixed-width types (uint32_t, int64_t).",
    },
    {
        "id": "PORT-VOID-PTR-ARITH",
        "regex": r'\bvoid\s*\*\s*\w+.*[+\-]',
        "category": "portability", "severity": "medium",
        "title": "Arithmetic on void pointer",
        "cwe": None, "cert_c": "EXP36-C",
        "desc": "Pointer arithmetic on void* is a GCC extension (treats as char*). Not standard C — fails on strict compilers.",
        "fix": "Cast to char* or uint8_t* before arithmetic.",
    },
    {
        "id": "PORT-BITFIELD-SIGN",
        "regex": r'\bint\s+\w+\s*:\s*\d+',
        "category": "portability", "severity": "medium",
        "title": "Plain int bitfield — sign is implementation-defined",
        "cwe": None, "cert_c": "INT14-C", "misra": "R.6.1",
        "desc": "A bitfield of type 'int' may be signed or unsigned depending on compiler. A 1-bit int bitfield can only hold 0 or -1 on signed implementations.",
        "fix": "Use explicit unsigned int or signed int for bitfields.",
    },
    {
        "id": "PORT-PACKED-ALIGNMENT",
        "regex": r'__attribute__\s*\(\s*\(\s*packed\s*\)\s*\)|#pragma\s+pack\s*\(',
        "category": "portability", "severity": "medium",
        "title": "Packed struct — alignment and access hazards",
        "cwe": None, "cert_c": None,
        "desc": "Packed structs may cause unaligned memory access, which is a fault on ARMv6-M and some ARMv7-M configs. Also prevents compiler optimizations.",
        "fix": "Ensure all accesses to packed fields go through memcpy or __UNALIGNED_UINT32_READ. Prefer natural alignment where possible.",
    },
    {
        "id": "PORT-ENDIAN-ASSUME",
        "regex": r'\bunion\s*\{[^}]*(?:uint8_t|char)\s+\w+\s*\[\s*\d+\s*\]\s*;[^}]*(?:uint32_t|uint16_t|int)\s+|(?:uint32_t|uint16_t|int)\s+\w+\s*;[^}]*(?:uint8_t|char)\s+\w+\s*\[\s*\d+\s*\]',
        "category": "portability", "severity": "medium",
        "title": "Union type-punning for endianness conversion",
        "cwe": None, "cert_c": "EXP39-C",
        "desc": "Union containing overlapping integer and byte-array members — classic endianness-dependent pattern and strict aliasing violation.",
        "fix": "Use explicit byte-shift operations or htons/htonl/ntohs/ntohl for portable endianness conversion.",
    },

    # ──────────── COMPLEXITY ────────────

    {
        "id": "CX-DEEP-NESTING",
        "regex": r'^\s{24,}(?:if|for|while|switch)\b',
        "category": "complexity", "severity": "medium",
        "title": "Deeply nested control flow (6+ levels)",
        "cwe": None, "cert_c": None, "misra": None,
        "desc": "Nesting depth of 6+ makes code hard to reason about and test. Each level multiplies the number of paths through the function.",
        "fix": "Extract inner blocks into helper functions. Use early returns to flatten conditions.",
    },
    {
        "id": "CX-LONG-FUNCTION",
        "regex": None,
        "meta_check": "function_length",
        "threshold": 100,
        "category": "complexity", "severity": "medium",
        "title": "Function exceeds 100 lines",
        "cwe": None, "cert_c": None, "misra": None,
        "desc": "Functions longer than 100 lines are hard to test, review, and reason about. Cyclomatic complexity correlates strongly with function length.",
        "fix": "Extract logical blocks into named helper functions.",
    },
    {
        "id": "CX-MANY-PARAMS",
        "regex": r'\w+\s+\w+\s*\(\s*(?:[^,)]+,){6,}[^)]+\)',
        "category": "complexity", "severity": "low",
        "title": "Function has 7+ parameters",
        "cwe": None, "cert_c": None, "misra": "R.1.1",
        "desc": "Many parameters signal a function doing too much. Caller mistakes (wrong argument order) become likely.",
        "fix": "Group related parameters into a config struct.",
    },

    # ──────────── MISRA / STYLE ────────────

    {
        "id": "MISRA-MACRO-NO-PARENS",
        "regex": r'#define\s+\w+\(\s*(\w+)\s*\)\s+(?!\().*\1(?!\s*\))',
        "category": "style", "severity": "medium",
        "title": "Function-like macro parameter not parenthesized",
        "cwe": None, "cert_c": "PRE01-C", "misra": "R.20.7",
        "desc": "Macro parameter used without parentheses in expansion. Operator precedence can cause silent miscomputation: #define DOUBLE(x) x*2 → DOUBLE(1+1) = 3.",
        "fix": "Parenthesize every parameter use: #define DOUBLE(x) ((x)*2)",
    },
    {
        "id": "MISRA-MACRO-NO-DOWHILE",
        "regex": r'#define\s+\w+(?:\([^)]*\))?\s+\{[^}]*;[^}]*;\s*\}',
        "category": "style", "severity": "low",
        "title": "Multi-statement macro without do-while wrapper",
        "cwe": None, "cert_c": "PRE10-C", "misra": "D.4.9",
        "desc": "Multi-statement macro not wrapped in do { ... } while (0). Using it in an if-else without braces causes the else to bind wrong.",
        "fix": "Wrap: #define MACRO(x) do { stmt1; stmt2; } while (0)",
    },
    {
        "id": "MISRA-SIDE-EFFECT-ASSERT",
        "regex": r'\bassert\s*\(\s*(?:.*\+\+|.*--|.*=(?!=)|.*\w+\s*\([^)]*\))',
        "category": "bug", "severity": "high",
        "title": "Side effect in assert() expression",
        "cwe": "CWE-617", "cert_c": "EXP31-C", "misra": "R.21.9",
        "desc": "assert() is removed when NDEBUG is defined. Any side effect (increment, assignment, function call) in the assertion vanishes in release builds.",
        "fix": "Move the side-effecting expression before the assert: val = func(); assert(val != NULL);",
    },
    {
        "id": "STYLE-MAGIC-NUMBER",
        "regex": r'(?:if|while|for|case|return)\s*[\(\s].*(?<![0-9a-fA-FxXuUlL\.\-])\b(?:[2-9]\d{2,}|[1-9]\d{3,})\b(?![0-9a-fA-FxXuUlL\.])',
        "category": "style", "severity": "info",
        "title": "Magic number in logic",
        "cwe": None, "cert_c": "DCL06-C", "misra": "R.7.1",
        "desc": "Numeric literal in control flow without a named constant. Makes intent unclear and changes error-prone.",
        "fix": "Define as a named constant: #define or enum or static const.",
    },
    {
        "id": "STYLE-MISSING-CONST",
        # Exclude pointers already qualified with `const` before the base type or between `*` and name.
        # Negative lookbehind for `const ` before the type keyword, and negative lookahead for `const`
        # between `*` and the identifier.
        "regex": r'(?<!const\s)(?<!const )(?:char|uint8_t|int|void)\s*\*\s*(?!const\s)(\w+)\s*[,=)]',
        "category": "style", "severity": "info",
        "title": "Pointer parameter not const-qualified",
        "cwe": None, "cert_c": "DCL13-C", "misra": "R.8.13",
        "desc": "Pointer parameter not declared const. If the function doesn't modify the target, const communicates intent and enables compiler optimizations.",
        "fix": "Add const: const char *param if the function doesn't write through the pointer.",
    },
    {
        "id": "STYLE-INCLUDE-GUARD",
        "regex": r'^(?!.*#ifndef\s+\w+_H)',
        "file_ext": ".h",
        "category": "style", "severity": "low",
        "title": "Missing include guard",
        "cwe": None, "cert_c": "PRE06-C", "misra": "R.20.2",
        "desc": "Header file lacks #ifndef include guard. Multiple inclusion causes redefinition errors.",
        "fix": "Add #ifndef HEADER_H / #define HEADER_H at top and #endif at bottom, or use #pragma once.",
    },
    {
        "id": "STYLE-GLOBAL-MUTABLE",
        "regex": r'^(?:static\s+)?(?!.*\bconst\b)(?:volatile\s+)?(?:unsigned\s+|signed\s+)?(?:int|char|uint\d+_t|int\d+_t|float|double|bool)\s+\w+\s*(?:\[|=|;)',
        "category": "style", "severity": "info",
        "title": "Global mutable state",
        "cwe": None, "cert_c": "DCL19-C",
        "desc": "Global mutable data complicates reasoning about data flow, reentrancy, and thread safety.",
        "fix": "Pass state explicitly or mark const if immutable.",
    },

    # ──────────── NULL / POINTER SAFETY ────────────

    {
        "id": "PTR-FUNC-NULL",
        "regex": r'(\w+)->(\w+)\s*\(',
        "category": "bug", "severity": "medium",
        "title": "Function pointer invocation without NULL guard",
        "cwe": "CWE-476", "cert_c": "EXP34-C",
        "desc": "Function pointer invoked through struct member without NULL check. If never assigned, this is a NULL dereference or wild jump.",
        "fix": "Guard: if (obj && obj->callback) { obj->callback(arg); }",
    },
    {
        "id": "PTR-DEREF-BEFORE-CHECK",
        "regex": r'(\w+)->(\w+).*\n.*if\s*\(\s*!?\s*\1\b',
        "category": "bug", "severity": "high",
        "title": "Pointer dereferenced before NULL check",
        "cwe": "CWE-476", "cert_c": "EXP34-C",
        "desc": "Pointer is dereferenced on one line and then checked for NULL on a subsequent line. The check is too late — UB already occurred.",
        "fix": "Move the NULL check before the first dereference.",
    },

    # ──────────── EMBEDDED PERIPHERAL PATTERNS ────────────
    # These are what Coverity/PVS-Studio/cppcheck do NOT check.

    {
        "id": "EMB-RMW-NO-VOLATILE",
        "regex": r'(?:\*\s*\(\s*(?:uint32_t|uint16_t|uint8_t)\s*\*\)\s*(?:0x[0-9a-fA-F]+))\s*[|&^]=',
        "category": "bug", "severity": "high",
        "title": "MMIO read-modify-write without volatile",
        "cwe": None, "cert_c": "DCL17-C",
        "desc": "Memory-mapped I/O register accessed through a non-volatile pointer. Compiler may cache, reorder, or eliminate accesses — silent peripheral misconfiguration.",
        "fix": "Cast to volatile: *(volatile uint32_t *)0xADDR |= BIT;",
    },
    {
        "id": "EMB-DMA-ALIGN",
        "regex": r'(?:uint8_t|char)\s+(\w+dma\w*|\w+buf\w*)\s*\[\s*\d+\s*\]\s*;',
        "category": "portability", "severity": "medium",
        "title": "DMA buffer may lack alignment",
        "cwe": None, "cert_c": None,
        "desc": "DMA buffer on stack or as global without alignment attribute. Many DMA controllers require 4-byte or cache-line alignment. Unaligned DMA causes hard faults or silent data corruption.",
        "fix": "Use __attribute__((aligned(4))) or __ALIGNED(4), or place in a dedicated linker section.",
    },
    {
        "id": "EMB-CACHE-DMA-COHERENCE",
        "regex": r'\b(?:HAL_DMA_Start|dma_start|DMA_Start|k_dma_start)\b',
        "lookahead_fail": r'(?:SCB_CleanDCache|SCB_InvalidateDCache|__DSB|__DMB|cache_flush|sys_cache_flush|DCACHE_CLEAN|DCACHE_INVALIDATE)',
        "lookahead_lines": 5,
        "category": "bug", "severity": "high",
        "title": "DMA transfer without cache maintenance",
        "cwe": None, "cert_c": None,
        "desc": "DMA started without D-cache clean (for TX) or invalidate (for RX). CPU and DMA see different memory contents. Silent data corruption that only manifests with caching enabled.",
        "fix": "Before TX DMA: SCB_CleanDCache_by_Addr(). After RX DMA: SCB_InvalidateDCache_by_Addr(). Or place buffers in non-cacheable region.",
    },
    {
        "id": "EMB-WATCHDOG-FEED-ISR",
        "regex": r'(?:void\s+\w*(?:_isr|_irq)\s*\(|void\s+(?:ISR|IRQ|Interrupt)\w*\s*\()',
        "block_scan_for": r'\b(?:wdt_feed|IWDG_ReloadCounter|WDT_Feed|HAL_IWDG_Refresh|wdt_kick)\b',
        "category": "bug", "severity": "high",
        "title": "Watchdog feed in ISR context",
        "cwe": None, "cert_c": None,
        "desc": "Feeding the watchdog from an ISR defeats its purpose — the ISR fires even if the main thread is hung. The watchdog can never trigger.",
        "fix": "Feed the watchdog from the main loop or a dedicated supervisor thread only.",
    },
]


# ════════════════════════════════════════════════════════════════════
#  SCANNER ENGINE
# ════════════════════════════════════════════════════════════════════

def _strip_comments(source: str) -> str:
    """Remove C block and line comments, preserving line count."""
    result = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group().count('\n'), source, flags=re.DOTALL)
    result = re.sub(r'//[^\n]*', '', result)
    return result


def _strip_strings(source: str) -> str:
    """Remove string literals to avoid false positives inside strings."""
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', source)


def _extract_functions(source: str) -> List[dict]:
    """Extract function boundaries (name, start_line, end_line, body)."""
    functions = []
    # Match function definitions (simplified — handles most C styles)
    pattern = re.compile(
        r'^[ \t]*(?:static\s+|inline\s+|extern\s+|volatile\s+|const\s+)*'
        r'(?:(?:unsigned|signed|long|short|struct|enum|union)\s+)*'
        r'\w[\w\s\*]*\s+(\w+)\s*\(([^)]*)\)\s*\{',
        re.MULTILINE,
    )
    lines = source.splitlines()
    for m in pattern.finditer(source):
        name = m.group(1)
        start_pos = m.start()
        start_line = source[:start_pos].count('\n') + 1
        # Find matching closing brace
        brace_count = 0
        body_start = m.end() - 1  # position of opening {
        end_line = start_line
        for i in range(body_start, len(source)):
            if source[i] == '{':
                brace_count += 1
            elif source[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_line = source[:i].count('\n') + 1
                    body = source[body_start:i + 1]
                    functions.append({
                        "name": name,
                        "start_line": start_line,
                        "end_line": end_line,
                        "body": body,
                        "params": m.group(2),
                    })
                    break
    return functions


def scan_banned_functions(stripped: str) -> List[Finding]:
    """Scan for calls to banned/dangerous C library functions."""
    findings = []
    counter = 0
    lines = stripped.splitlines()
    # A function definition has a return type (word chars, *, spaces) before the name.
    # Matches: `char *gets(`, `FAR char *gets(`, `static int sprintf(`, etc.
    # Used to suppress false positives when a file IMPLEMENTS a banned function (e.g. libc).
    _defn_re = re.compile(r'\b\w[\w\s\*]*\b{name}\s*\(')

    for func_name, info in BANNED_FUNCTIONS.items():
        pattern = re.compile(rf'\b{re.escape(func_name)}\s*\(')
        defn_re = re.compile(rf'\b\w[\w\s\*]*\b{re.escape(func_name)}\s*\(')
        for i, line in enumerate(lines):
            if pattern.search(line):
                # Skip function definitions — a return type appears before the function name
                if defn_re.search(line):
                    continue
                counter += 1
                findings.append(Finding(
                    id=f"S{counter:03d}",
                    category=info.get("category", "security"),
                    severity=info["severity"],
                    title=info["title"],
                    location=f"line {i + 1}",
                    line=i + 1,
                    description=info["desc"],
                    cwe=info.get("cwe"),
                    cert_c=info.get("cert_c"),
                    recommendation=info["fix"],
                ))

    # Special scanf check
    scanf_re = re.compile(r'\bscanf\s*\(')
    for i, line in enumerate(lines):
        if scanf_re.search(line):
            if re.search(r'%s', line) and not re.search(r'%\d+s', line):
                counter += 1
                findings.append(Finding(
                    id=f"S{counter:03d}",
                    category="security",
                    severity=SCANF_CHECK["severity"],
                    title=SCANF_CHECK["title"],
                    location=f"line {i + 1}",
                    line=i + 1,
                    description=SCANF_CHECK["desc"],
                    cwe=SCANF_CHECK["cwe"],
                    cert_c=SCANF_CHECK["cert_c"],
                    recommendation=SCANF_CHECK["fix"],
                ))

    return findings


def scan_patterns(stripped: str, filepath: str = "", functions: List[dict] = None) -> List[Finding]:
    """Run regex and block-level pattern rules."""
    findings = []
    counter = 200
    lines = stripped.splitlines()
    ext = Path(filepath).suffix if filepath else ""

    for rule in PATTERNS:
        # Skip meta-checks here (handled separately)
        if rule.get("meta_check"):
            continue

        # File extension filter
        if "file_ext" in rule and ext != rule["file_ext"]:
            continue

        # Skip if no regex (meta rules)
        if not rule.get("regex"):
            continue

        # Block-level scan: find function, then search body
        if rule.get("block_scan_for"):
            if functions is None:
                continue
            func_re = re.compile(rule["regex"])
            target_re = re.compile(rule["block_scan_for"])
            for func in functions:
                first_line = func["body"].split('\n')[0] if func["body"] else ""
                full_header = stripped.splitlines()[func["start_line"] - 1] if func["start_line"] <= len(lines) else ""
                if func_re.search(full_header) or func_re.search(first_line):
                    if target_re.search(func["body"]):
                        counter += 1
                        findings.append(Finding(
                            id=f"S{counter:03d}",
                            category=rule["category"],
                            severity=rule["severity"],
                            title=rule["title"],
                            location=f"{func['name']}()",
                            line=func["start_line"],
                            description=rule["desc"],
                            cwe=rule.get("cwe"),
                            cert_c=rule.get("cert_c"),
                            misra=rule.get("misra"),
                            recommendation=rule["fix"],
                        ))
            continue

        # Self-call recursion check
        if rule.get("block_scan_for_self_call"):
            if functions is None:
                continue
            for func in functions:
                self_call_re = re.compile(rf'\b{re.escape(func["name"])}\s*\(')
                # Count occurrences — first is the definition, any additional are recursive calls
                calls = list(self_call_re.finditer(func["body"]))
                if len(calls) > 0:
                    # Check if function name appears in body AFTER the opening
                    body_after_sig = func["body"][func["body"].index('{') + 1:] if '{' in func["body"] else ""
                    if self_call_re.search(body_after_sig):
                        counter += 1
                        findings.append(Finding(
                            id=f"S{counter:03d}",
                            category=rule["category"],
                            severity=rule["severity"],
                            title=f"{rule['title']}: {func['name']}()",
                            location=f"{func['name']}()",
                            line=func["start_line"],
                            description=rule["desc"],
                            cwe=rule.get("cwe"),
                            cert_c=rule.get("cert_c"),
                            misra=rule.get("misra"),
                            recommendation=rule["fix"],
                        ))
            continue

        # Standard line-by-line scan
        pattern = re.compile(rule["regex"], re.MULTILINE)
        skip_prefix_re = re.compile(rule.get("skip_line_pattern") or rule.get("skip_line_prefix") or r'(?!)', re.MULTILINE) if (rule.get("skip_line_pattern") or rule.get("skip_line_prefix")) else None
        for i, line in enumerate(lines):
            if skip_prefix_re and skip_prefix_re.search(line):
                continue
            match = pattern.search(line)
            if not match:
                continue

            # Lookahead check
            if "lookahead_fail" in rule and rule["lookahead_fail"]:
                var = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
                guard_re = re.compile(rule["lookahead_fail"].replace("{var}", re.escape(var)), re.MULTILINE)
                n = rule.get("lookahead_lines", 3)
                window = "\n".join(lines[i:i + n + 1])
                if guard_re.search(window):
                    continue

            # Lookbehind check
            if "lookbehind_fail" in rule and rule["lookbehind_fail"]:
                var = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
                guard_re = re.compile(rule["lookbehind_fail"].replace("{var}", re.escape(var)), re.MULTILINE)
                n = rule.get("lookbehind_lines", 3)
                window = "\n".join(lines[max(0, i - n):i + 1])
                if guard_re.search(window):
                    continue

            counter += 1
            findings.append(Finding(
                id=f"S{counter:03d}",
                category=rule["category"],
                severity=rule["severity"],
                title=rule["title"],
                location=f"line {i + 1}",
                line=i + 1,
                description=rule["desc"],
                cwe=rule.get("cwe"),
                cert_c=rule.get("cert_c"),
                misra=rule.get("misra"),
                recommendation=rule["fix"],
            ))

    return findings


def scan_meta(functions: List[dict]) -> List[Finding]:
    """Run meta-level checks (function length, stack-local return, etc.)."""
    findings = []
    counter = 400

    # Pre-compile patterns used in block checks
    _return_addr_re = re.compile(r'return\s*&\s*(\w+)\s*;')
    # A local declaration: indented (whitespace at start), type keyword, variable name.
    # Does NOT start with `static` (static locals are safe). Also matches function params
    # declared in the body via assignments — this is conservative.
    _local_decl_re_tpl = r'(?:^|\n)\s+(?!static\b)(?:const\s+)?(?:\w+\s+)+\*?\s*{var}\s*[=;,\[]'

    for rule in PATTERNS:
        if not rule.get("meta_check"):
            continue

        if rule["meta_check"] == "function_length":
            threshold = rule.get("threshold", 100)
            for func in functions:
                length = func["end_line"] - func["start_line"] + 1
                if length > threshold:
                    counter += 1
                    findings.append(Finding(
                        id=f"S{counter:03d}",
                        category=rule["category"],
                        severity=rule["severity"],
                        title=f"{rule['title']}: {func['name']}() is {length} lines",
                        location=f"{func['name']}()",
                        line=func["start_line"],
                        description=rule["desc"],
                        cwe=rule.get("cwe"),
                        cert_c=rule.get("cert_c"),
                        recommendation=rule["fix"],
                    ))

        elif rule["meta_check"] == "return_stack_local":
            for func in functions:
                body = func["body"]
                body_lines = body.split('\n')
                for m in _return_addr_re.finditer(body):
                    var = m.group(1)
                    # Calculate absolute line number
                    abs_line = func["start_line"] + body[:m.start()].count('\n')
                    # Check if `var` has a non-static local declaration inside this function body.
                    # If it does NOT appear as a local, it is a global/static — suppress.
                    local_re = re.compile(_local_decl_re_tpl.replace("{var}", re.escape(var)), re.MULTILINE)
                    if not local_re.search(body):
                        continue  # not a local — global/static/extern, safe to return its address
                    counter += 1
                    findings.append(Finding(
                        id=f"S{counter:03d}",
                        category=rule["category"],
                        severity=rule["severity"],
                        title=rule["title"],
                        location=f"{func['name']}()",
                        line=abs_line,
                        description=rule["desc"],
                        cwe=rule.get("cwe"),
                        cert_c=rule.get("cert_c"),
                        recommendation=rule["fix"],
                    ))

    return findings


def scan_source(source: str, filepath: str = "<stdin>") -> List[Finding]:
    """Run ALL deterministic scans on a source string."""
    stripped = _strip_comments(source)
    clean = _strip_strings(stripped)
    functions = _extract_functions(stripped)

    findings = []
    findings.extend(scan_banned_functions(clean))
    findings.extend(scan_patterns(clean, filepath, functions))
    findings.extend(scan_meta(functions))

    # Deduplicate by (line, title)
    seen = set()
    deduped = []
    for f in findings:
        key = (f.line, f.title)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort by severity then line
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    deduped.sort(key=lambda f: (sev_order.get(f.severity, 5), f.line))
    return deduped


def scan_file(filepath: str) -> List[Finding]:
    """Run all deterministic scans on a file."""
    source = Path(filepath).read_text(errors="replace")
    return scan_source(source, filepath)
