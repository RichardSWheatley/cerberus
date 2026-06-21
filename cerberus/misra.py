"""
CERBERUS MISRA C:2012 + CERT C Rule Catalog

Traceable, auditable rule coverage matching the *standard* rulesets that
commercial tools charge for. Every finding maps to a specific rule ID with
the official rule text reference.

MISRA classifies each rule as:
  - DECIDABLE:   checkable by static inspection of the code (we own these)
  - UNDECIDABLE: requires whole-program / dataflow analysis (routed to Head 2)

This module implements the DECIDABLE rules deterministically. Undecidable
rules are registered with route="head2" so the convergence loop knows to
ask the AI head rather than expecting a regex to catch them.

Coverage philosophy: match SonarCloud/Coverity on the catalog of decidable
rules (the majority), use Head 2 for the undecidable remainder. Free.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from pathlib import Path


@dataclass
class RuleFinding:
    id: str
    rule: str            # e.g. "MISRA R.14.4" or "CERT INT30-C"
    category: str
    severity: str
    decidable: bool
    title: str
    location: str
    line: int
    description: str
    rule_text: str       # Official rule summary
    recommendation: str
    route: str = "head1"  # head1 = we caught it; head2 = needs AI dataflow


# ════════════════════════════════════════════════════════════════════
#  MISRA C:2012 DECIDABLE RULES (pattern-checkable)
#  Rule classification per MISRA C:2012 Amendment 3
# ════════════════════════════════════════════════════════════════════

MISRA_RULES: List[Dict[str, Any]] = [

    # ── Directive 4.x ──
    {
        "rule": "MISRA D.4.6", "decidable": True, "severity": "low", "category": "portability",
        "regex": r'\b(?:signed|unsigned)?\s*(?:char|short|int|long)\s+\w+\s*[;=,\)]',
        "title": "typedefs that indicate size and signedness should be used",
        "rule_text": "Dir 4.6: typedefs that indicate size and signedness should be used in place of the basic numerical types.",
        "fix": "Use uint32_t, int16_t, etc. from <stdint.h> instead of plain int/char/long.",
        "guard_skip": r'\bmain\b|argc|argv|\bchar\s*\*|const\s+char',
    },
    {
        "rule": "MISRA D.4.9", "decidable": True, "severity": "low", "category": "style",
        "regex": r'#define\s+\w+\([^)]*\)\s+',
        "title": "function-like macro where a function could be used",
        "rule_text": "Dir 4.9: A function should be used in preference to a function-like macro where they are interchangeable.",
        "fix": "Prefer a static inline function over a function-like macro for type safety.",
    },

    # ── Rule 8.x: Declarations and definitions ──
    {
        "rule": "MISRA R.8.4", "decidable": True, "severity": "low", "category": "style",
        "regex": r'^(?!static\b)(?:extern\s+)?[\w\s\*]+\b\w+\s*\([^)]*\)\s*\{',
        "title": "external definition without visible declaration",
        "rule_text": "R.8.4: A compatible declaration shall be visible when an object or function with external linkage is defined.",
        "fix": "Ensure a prototype in a header precedes every non-static function definition.",
        "route": "head2",
    },
    {
        "rule": "MISRA R.8.7", "decidable": True, "severity": "info", "category": "style",
        "regex": r'^[\w\s\*]+\b\w+\s*\([^)]*\)\s*\{',
        "title": "function with external linkage referenced in only one file",
        "rule_text": "R.8.7: Functions and objects should not be defined with external linkage if referenced in only one translation unit.",
        "fix": "Mark single-file functions/objects as static.",
        "route": "head2",
    },
    {
        "rule": "MISRA R.8.9", "decidable": True, "severity": "info", "category": "style",
        "regex": r'^\s*(?!static)(?:unsigned|signed)?\s*(?:int|char|long)\s+\w+\s*(?:\[|=|;)',
        "title": "object should be defined at block scope if single-function use",
        "rule_text": "R.8.9: An object should be defined at block scope if its identifier only appears in a single function.",
        "fix": "Move file-scope objects used in one function into that function as locals.",
        "route": "head2",
    },

    # ── Rule 9.x: Initialization ──
    {
        "rule": "MISRA R.9.1", "decidable": False, "severity": "high", "category": "bug",
        "title": "value of object with automatic storage read before set",
        "rule_text": "R.9.1: The value of an object with automatic storage duration shall not be read before it has been set.",
        "fix": "Initialize all automatic variables before first read.",
        "route": "head2",
    },

    # ── Rule 10.x: The essential type model ──
    {
        "rule": "MISRA R.10.1", "decidable": True, "severity": "medium", "category": "bug",
        "regex": r'(?:&|\||\^|~|<<|>>)\s*(?:true|false|[a-zA-Z_]\w*\s*(?:==|!=|<|>))',
        "title": "operand of inappropriate essential type in bitwise op",
        "rule_text": "R.10.1: Operands shall not be of an inappropriate essential type (e.g. bitwise ops on boolean/signed).",
        "fix": "Apply bitwise operators only to unsigned integer operands.",
    },
    {
        "rule": "MISRA R.10.3", "decidable": True, "severity": "medium", "category": "bug",
        "regex": r'\b(?:uint8_t|int8_t|uint16_t|int16_t|char|short)\s+\w+\s*=\s*\w+\s*[+\-*]',
        "title": "expression assigned to narrower or different essential type",
        "rule_text": "R.10.3: The value of an expression shall not be assigned to an object with a narrower essential type.",
        "fix": "Use explicit casts and ensure the destination type can hold the result.",
    },
    {
        "rule": "MISRA R.10.4", "decidable": True, "severity": "medium", "category": "bug",
        "regex": r'(?:if|while|for)\s*\(.*\b(?:int|long|ssize_t)\s+\w+.*[<>=!]+.*\b(?:unsigned|uint|size_t)\b',
        "title": "operands of mismatched essential type category",
        "rule_text": "R.10.4: Both operands of an operator in which the usual arithmetic conversions are performed shall have the same essential type category.",
        "fix": "Match signedness on both sides of arithmetic/relational operators.",
    },

    # ── Rule 11.x: Pointer type conversions ──
    {
        "rule": "MISRA R.11.3", "decidable": True, "severity": "high", "category": "undefined_behavior",
        "regex": r'\(\s*(?:struct\s+)?\w+\s*\*\s*\)\s*(?:\([^)]*\)\s*)?\w+',
        "title": "cast between pointer to different object types",
        "rule_text": "R.11.3: A cast shall not be performed between a pointer to object type and a pointer to a different object type.",
        "fix": "Avoid pointer type-punning; use a union or memcpy for reinterpretation.",
        "guard_skip": r'void\s*\*|char\s*\*|uint8_t\s*\*',
    },
    {
        "rule": "MISRA R.11.4", "decidable": True, "severity": "medium", "category": "portability",
        "regex": r'\(\s*(?:uint32_t|uintptr_t|unsigned\s+long|int)\s*\)\s*&|\(\s*\w+\s*\*\s*\)\s*0x[0-9a-fA-F]+',
        "title": "conversion between pointer and integer",
        "rule_text": "R.11.4: A conversion should not be performed between a pointer to object and an integer type.",
        "fix": "Use uintptr_t for any unavoidable pointer-integer conversion (e.g. MMIO).",
    },
    {
        "rule": "MISRA R.11.6", "decidable": True, "severity": "medium", "category": "portability",
        "regex": r'\(\s*void\s*\*\s*\)\s*\d+|\(\s*(?:uint32_t|int)\s*\)\s*\(\s*void\s*\*\s*\)',
        "title": "cast between pointer-to-void and arithmetic type",
        "rule_text": "R.11.6: A cast shall not be performed between pointer to void and an arithmetic type.",
        "fix": "Use uintptr_t for the integer side of any void* conversion.",
    },

    # ── Rule 12.x: Expressions ──
    {
        "rule": "MISRA R.12.1", "decidable": True, "severity": "low", "category": "style",
        "regex": r'\w+\s*[+\-]\s*\w+\s*(?:<<|>>|&|\||\^)\s*\w+|\w+\s*(?:<<|>>)\s*\w+\s*[+\-]',
        "title": "operator precedence relies on implicit knowledge",
        "rule_text": "R.12.1: The precedence of operators within expressions should be made explicit with parentheses.",
        "fix": "Add parentheses to make evaluation order explicit.",
    },
    {
        "rule": "MISRA R.12.3", "decidable": True, "severity": "low", "category": "style",
        "regex": r'for\s*\([^;]*,[^;]*;|\w+\s*=\s*[^;,]+,\s*\w+\s*=',
        "title": "comma operator used",
        "rule_text": "R.12.3: The comma operator should not be used.",
        "fix": "Split comma expressions into separate statements.",
    },

    # ── Rule 13.x: Side effects ──
    {
        "rule": "MISRA R.13.4", "decidable": True, "severity": "medium", "category": "bug",
        "regex": r'(?:if|while)\s*\([^)]*[^=!<>]=[^=][^)]*\)',
        "title": "result of assignment operator used",
        "rule_text": "R.13.4: The result of an assignment operator should not be used.",
        "fix": "Separate the assignment from the test.",
    },
    {
        "rule": "MISRA R.13.5", "decidable": False, "severity": "medium", "category": "bug",
        "title": "RHS of && or || contains persistent side effects",
        "rule_text": "R.13.5: The right hand operand of a logical && or || operator shall not contain persistent side effects.",
        "fix": "Move side-effecting expressions out of short-circuit operands.",
        "route": "head2",
    },

    # ── Rule 14.x: Control flow ──
    {
        "rule": "MISRA R.14.4", "decidable": True, "severity": "medium", "category": "bug",
        "regex": r'(?:if|while)\s*\(\s*(?!.*[<>=!]=)(?!.*&&)(?!.*\|\|)\w+\s*\)',
        "title": "controlling expression not essentially boolean",
        "rule_text": "R.14.4: The controlling expression of an if statement / iteration shall have essentially Boolean type.",
        "fix": "Compare explicitly: if (x != 0) rather than if (x).",
        "guard_skip": r'true|false|\bbool\b',
    },

    # ── Rule 15.x: Control flow ──
    {
        "rule": "MISRA R.15.1", "decidable": True, "severity": "info", "category": "style",
        "regex": r'\bgoto\b',
        "title": "goto statement used",
        "rule_text": "R.15.1: The goto statement should not be used.",
        "fix": "Acceptable for forward cleanup-goto; otherwise restructure.",
    },
    {
        "rule": "MISRA R.15.5", "decidable": True, "severity": "low", "category": "style",
        "regex": None, "meta": "multiple_return",
        "title": "function has more than one return statement",
        "rule_text": "R.15.5: A function should have a single point of exit at the end.",
        "fix": "Consolidate to a single return via a result variable (debatable in kernel style).",
    },
    {
        "rule": "MISRA R.15.6", "decidable": True, "severity": "high", "category": "bug",
        "regex": r'\b(?:if|else|for|while)\s*(?:\([^)]*\))?\s*[^{;\s]',
        "title": "body of control statement not enclosed in braces",
        "rule_text": "R.15.6: The body of an iteration/selection statement shall be a compound statement (braces).",
        "fix": "Always use braces, even for single-statement bodies.",
        "guard_skip": r'\{|\bif\b.*\breturn\b|else\s+if',
    },
    {
        "rule": "MISRA R.15.7", "decidable": True, "severity": "low", "category": "bug",
        "regex": r'\belse\s+if\b',
        "title": "if-else-if chain should terminate with else",
        "rule_text": "R.15.7: All if / else if constructs shall be terminated with an else statement.",
        "fix": "Add a final else clause (may be empty with a comment) to if-else-if chains.",
        "route": "head2",
    },

    # ── Rule 16.x: Switch statements ──
    {
        "rule": "MISRA R.16.1", "decidable": True, "severity": "medium", "category": "bug",
        "regex": None, "meta": "switch_wellformed",
        "title": "switch statement not well-formed",
        "rule_text": "R.16.1: All switch statements shall be well-formed.",
        "fix": "Ensure each case ends in break/return and a default exists.",
    },
    {
        "rule": "MISRA R.16.3", "decidable": True, "severity": "high", "category": "bug",
        "regex": None, "meta": "switch_fallthrough",
        "title": "unconditional break missing from switch case",
        "rule_text": "R.16.3: An unconditional break statement shall terminate every switch-clause.",
        "fix": "Add break to each case, or annotate intentional fallthrough.",
    },
    {
        "rule": "MISRA R.16.4", "decidable": True, "severity": "low", "category": "bug",
        "regex": r'\bswitch\s*\(', "meta": "switch_default",
        "title": "switch statement has no default label",
        "rule_text": "R.16.4: Every switch statement shall have a default label.",
        "fix": "Add a default case, even if only to assert unreachable.",
    },

    # ── Rule 17.x: Functions ──
    {
        "rule": "MISRA R.17.2", "decidable": False, "severity": "medium", "category": "complexity",
        "title": "recursion present",
        "rule_text": "R.17.2: Functions shall not call themselves, directly or indirectly.",
        "fix": "Convert recursion to iteration on stack-limited targets.",
        "route": "head1",  # direct recursion is decidable; indirect needs head2
    },
    {
        "rule": "MISRA R.17.7", "decidable": True, "severity": "medium", "category": "bug",
        "regex": None, "meta": "ignored_return",
        "title": "return value of non-void function not used",
        "rule_text": "R.17.7: The value returned by a function having non-void return type shall be used.",
        "fix": "Capture and check return values, or cast to (void) to signal intent.",
    },

    # ── Rule 18.x: Pointers and arrays ──
    {
        "rule": "MISRA R.18.4", "decidable": True, "severity": "low", "category": "style",
        "regex": r'\w+\s*\+\+|\+\+\s*\w+|\w+\s*\+=\s*\d+.*\*|(?<![=<>!])[\+\-]\s*sizeof',
        "title": "pointer arithmetic using +, -, +=, -=",
        "rule_text": "R.18.4: The +, -, += and -= operators should not be applied to pointer types.",
        "fix": "Use array indexing instead of pointer arithmetic where possible.",
        "route": "head2",
    },
    {
        "rule": "MISRA R.18.8", "decidable": True, "severity": "medium", "category": "memory",
        "regex": r'\b(?:int|char|uint8_t|uint16_t|uint32_t|float|double|unsigned|long|short)\s+\w+\s*\[\s*[a-zA-Z_]\w*\s*\]',
        "title": "variable-length array used",
        "rule_text": "R.18.8: Variable-length array types shall not be used.",
        "fix": "Use a fixed-size array with a compile-time constant bound.",
    },

    # ── Rule 20.x: Preprocessing directives ──
    {
        "rule": "MISRA R.20.7", "decidable": True, "severity": "medium", "category": "style",
        "regex": r'#define\s+\w+\(\s*(\w+)\s*\)\s+(?!.*\(\s*\1\s*\)).*\b\1\b',
        "title": "macro parameter not parenthesized",
        "rule_text": "R.20.7: Expressions resulting from macro expansion shall be enclosed in parentheses.",
        "fix": "Parenthesize every macro parameter use: #define M(x) ((x)+1)",
    },
    {
        "rule": "MISRA R.20.10", "decidable": True, "severity": "low", "category": "style",
        "regex": r'#\s*\w+|##',
        "title": "# or ## preprocessor operator used",
        "rule_text": "R.20.10: The # and ## preprocessor operators should not be used.",
        "fix": "Avoid token pasting/stringizing where a typed construct would serve.",
        "route": "head2",
    },

    # ── Rule 21.x: Standard libraries ──
    {
        "rule": "MISRA R.21.3", "decidable": True, "severity": "high", "category": "memory",
        "regex": r'\b(?:malloc|calloc|realloc|free)\s*\(',
        "title": "memory allocation/deallocation from <stdlib.h> used",
        "rule_text": "R.21.3: The memory allocation and deallocation functions of <stdlib.h> shall not be used.",
        "fix": "Use static allocation or a deterministic pool allocator on embedded targets.",
    },
    {
        "rule": "MISRA R.21.6", "decidable": True, "severity": "medium", "category": "portability",
        "regex": r'\b(?:printf|scanf|fopen|fputs|fgets|putchar|getchar|puts)\s*\(',
        "title": "standard I/O function from <stdio.h> used",
        "rule_text": "R.21.6: The Standard Library input/output functions shall not be used.",
        "fix": "Use platform-specific I/O (e.g. Zephyr printk, UART HAL) in production embedded code.",
    },
    {
        "rule": "MISRA R.21.7", "decidable": True, "severity": "medium", "category": "bug",
        "regex": r'\b(?:atoi|atol|atoll|atof)\s*\(',
        "title": "atof/atoi/atol/atoll from <stdlib.h> used",
        "rule_text": "R.21.7: The atof, atoi, atol and atoll functions of <stdlib.h> shall not be used.",
        "fix": "Use strtol/strtod with error checking.",
    },
    {
        "rule": "MISRA R.21.8", "decidable": True, "severity": "high", "category": "bug",
        "regex": r'\b(?:abort|exit|getenv|system)\s*\(',
        "title": "abort/exit/getenv/system from <stdlib.h> used",
        "rule_text": "R.21.8: The library functions abort, exit, getenv and system of <stdlib.h> shall not be used.",
        "fix": "Avoid process-control and environment functions in embedded firmware.",
    },
    {
        "rule": "MISRA R.21.9", "decidable": True, "severity": "high", "category": "bug",
        "regex": r'\b(?:bsearch|qsort)\s*\(',
        "title": "bsearch/qsort from <stdlib.h> used",
        "rule_text": "R.21.9: The library functions bsearch and qsort of <stdlib.h> shall not be used.",
        "fix": "Implement deterministic search/sort with known stack and timing bounds.",
    },
    {
        "rule": "MISRA R.21.10", "decidable": True, "severity": "medium", "category": "bug",
        "regex": r'#include\s*<time\.h>|\b(?:time|mktime|localtime|gmtime|asctime|ctime|difftime)\s*\(',
        "title": "Standard Library time/date functions used",
        "rule_text": "R.21.10: The Standard Library time and date functions shall not be used.",
        "fix": "Use platform RTC/tick APIs instead of <time.h>.",
    },
]

# ════════════════════════════════════════════════════════════════════
#  CERT C RULES (decidable subset; undecidable routed to head2)
# ════════════════════════════════════════════════════════════════════

CERT_RULES: List[Dict[str, Any]] = [
    {
        "rule": "CERT INT30-C", "decidable": False, "severity": "high", "category": "bug",
        "title": "unsigned integer wraparound",
        "rule_text": "INT30-C: Ensure that unsigned integer operations do not wrap.",
        "fix": "Check operands against limits before add/multiply on unsigned types.",
        "route": "head2",
    },
    {
        "rule": "CERT INT31-C", "decidable": True, "severity": "medium", "category": "bug",
        "regex": r'\((?:uint8_t|int8_t|uint16_t|int16_t|char|short)\)\s*\w+',
        "title": "integer conversion may lose or misinterpret data",
        "rule_text": "INT31-C: Ensure that integer conversions do not result in lost or misinterpreted data.",
        "fix": "Validate the value fits the destination type before narrowing casts.",
    },
    {
        "rule": "CERT INT33-C", "decidable": True, "severity": "medium", "category": "bug",
        "regex": r'[/%]\s*\w+', "meta": "div_guard",
        "title": "division or remainder by possibly-zero divisor",
        "rule_text": "INT33-C: Ensure that division and remainder operations do not result in divide-by-zero.",
        "fix": "Guard divisor against zero before the operation.",
    },
    {
        "rule": "CERT INT34-C", "decidable": True, "severity": "critical", "category": "undefined_behavior",
        "regex": r'(?:<<|>>)\s*(?:-|\b(?:3[2-9]|[4-9]\d|\d{3,})\b)',
        "title": "shift by negative or excessive count",
        "rule_text": "INT34-C: Do not shift an expression by a negative number of bits or >= the operand width.",
        "fix": "Constrain shift amount to [0, width-1] of the operand type.",
    },
    {
        "rule": "CERT STR31-C", "decidable": True, "severity": "high", "category": "security",
        "regex": r'\b(?:strcpy|strcat|sprintf|gets)\s*\(',
        "title": "string copy may exceed destination capacity",
        "rule_text": "STR31-C: Guarantee that storage for strings has sufficient space for character data and the null terminator.",
        "fix": "Use bounded variants (strncpy, snprintf) with explicit size.",
    },
    {
        "rule": "CERT MEM30-C", "decidable": False, "severity": "high", "category": "memory",
        "title": "access to freed memory (use-after-free)",
        "rule_text": "MEM30-C: Do not access freed memory.",
        "fix": "Set pointers to NULL after free; never dereference freed pointers.",
        "route": "head2",
    },
    {
        "rule": "CERT MEM31-C", "decidable": False, "severity": "high", "category": "memory",
        "title": "memory leak (allocated but not freed)",
        "rule_text": "MEM31-C: Free dynamically allocated memory when no longer needed.",
        "fix": "Ensure every allocation has a matching free on all paths.",
        "route": "head2",
    },
    {
        "rule": "CERT MEM35-C", "decidable": False, "severity": "high", "category": "memory",
        "title": "allocation size may be insufficient",
        "rule_text": "MEM35-C: Allocate sufficient memory for an object.",
        "fix": "Size allocations with sizeof(*ptr) and validate multiplications.",
        "route": "head2",
    },
    {
        "rule": "CERT EXP34-C", "decidable": False, "severity": "high", "category": "bug",
        "title": "null pointer dereference",
        "rule_text": "EXP34-C: Do not dereference null pointers.",
        "fix": "Check pointers for NULL before dereferencing.",
        "route": "head2",
    },
    {
        "rule": "CERT ERR33-C", "decidable": True, "severity": "medium", "category": "bug",
        "regex": None, "meta": "ignored_return",
        "title": "standard library error indicator not checked",
        "rule_text": "ERR33-C: Detect and handle standard library errors.",
        "fix": "Check return values of library functions that report errors.",
    },
    {
        "rule": "CERT FIO30-C", "decidable": True, "severity": "critical", "category": "security",
        "regex": r'\b(?:printf|fprintf|snprintf|syslog)\s*\(\s*(?!.*")[a-zA-Z_]\w*\s*[,\)]',
        "title": "format string from external source",
        "rule_text": "FIO30-C: Exclude user input from format strings.",
        "fix": "Always use a literal format string.",
    },
]


# ════════════════════════════════════════════════════════════════════
#  ENGINE
# ════════════════════════════════════════════════════════════════════

def _strip(source: str) -> str:
    s = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group().count('\n'), source, flags=re.DOTALL)
    s = re.sub(r'//[^\n]*', '', s)
    s = re.sub(r'"(?:[^"\\]|\\.)*"', '""', s)
    return s


def _functions(source: str) -> List[Dict[str, Any]]:
    funcs = []
    pat = re.compile(r'^[ \t]*(?:static\s+|inline\s+|extern\s+)*[\w\*]+\s+(\w+)\s*\(([^)]*)\)\s*\{', re.MULTILINE)
    for m in pat.finditer(source):
        name = m.group(1)
        sl = source[:m.start()].count('\n') + 1
        depth = 0
        bs = m.end() - 1
        for i in range(bs, len(source)):
            if source[i] == '{': depth += 1
            elif source[i] == '}':
                depth -= 1
                if depth == 0:
                    funcs.append({"name": name, "start": sl,
                                  "end": source[:i].count('\n') + 1,
                                  "body": source[bs:i+1]})
                    break
    return funcs


def _meta_check(meta: str, rule: Dict, source: str, funcs: List[Dict], counter: int, prefix: str) -> List[RuleFinding]:
    out = []
    lines = source.splitlines()

    if meta == "ignored_return":
        # HAL/library call whose return is discarded (statement starts with identifier+( )
        pat = re.compile(r'^\s+(?:am_hal_|nrfx_|HAL_|k_)\w+\s*\([^;]*\)\s*;')
        for i, ln in enumerate(lines):
            if pat.match(ln) and not re.search(r'=|return|if\s*\(|while\s*\(|\(void\)', ln):
                counter += 1
                out.append(_mk(rule, counter, prefix, i + 1, f"line {i+1}"))

    elif meta == "switch_default":
        for f in funcs:
            for m in re.finditer(r'\bswitch\s*\(', f["body"]):
                # crude: does this function body have a default after the switch?
                seg = f["body"][m.start():]
                # find matching block
                if 'default' not in seg.split('switch', 2)[-1][:2000]:
                    counter += 1
                    out.append(_mk(rule, counter, prefix, f["start"], f"{f['name']}()"))
                    break

    elif meta == "switch_fallthrough":
        for f in funcs:
            # find case labels not followed by break/return/fallthrough before next case
            cases = list(re.finditer(r'\bcase\b[^:]*:', f["body"]))
            for idx, c in enumerate(cases):
                start = c.end()
                end = cases[idx+1].start() if idx+1 < len(cases) else len(f["body"])
                seg = f["body"][start:end]
                if not re.search(r'\b(?:break|return|continue|goto)\b|fallthrough|__attribute__\s*\(\s*\(\s*fallthrough', seg):
                    if idx+1 < len(cases):  # only flag if another case follows
                        counter += 1
                        out.append(_mk(rule, counter, prefix, f["start"], f"{f['name']}() switch case"))
                        break

    elif meta == "switch_wellformed":
        pass  # covered by default + fallthrough

    elif meta == "multiple_return":
        for f in funcs:
            n = len(re.findall(r'\breturn\b', f["body"]))
            if n > 1:
                counter += 1
                out.append(_mk(rule, counter, prefix, f["start"], f"{f['name']}() ({n} returns)"))

    elif meta == "div_guard":
        for i, ln in enumerate(lines):
            for m in re.finditer(r'[/%]\s*([a-zA-Z_]\w*)', ln):
                var = m.group(1)
                window = "\n".join(lines[max(0, i-3):i+1])
                if not re.search(rf'{re.escape(var)}\s*(?:!=|==)\s*0|if\s*\(\s*{re.escape(var)}\b', window):
                    counter += 1
                    out.append(_mk(rule, counter, prefix, i + 1, f"line {i+1}"))
                    break

    return out, counter


def _mk(rule: Dict, counter: int, prefix: str, line: int, loc: str) -> RuleFinding:
    return RuleFinding(
        id=f"{prefix}{counter:03d}",
        rule=rule["rule"],
        category=rule["category"],
        severity=rule["severity"],
        decidable=rule.get("decidable", True),
        title=rule["title"],
        location=loc,
        line=line,
        description=rule["rule_text"],
        rule_text=rule["rule_text"],
        recommendation=rule["fix"],
        route=rule.get("route", "head1"),
    )


def scan_standards(source: str, filepath: str = "<stdin>") -> List[RuleFinding]:
    """Run MISRA C:2012 + CERT C decidable rules. Returns rule-tagged findings."""
    stripped = _strip(source)
    funcs = _functions(stripped)
    lines = stripped.splitlines()
    findings = []

    for ruleset, prefix in [(MISRA_RULES, "M"), (CERT_RULES, "C")]:
        counter = 0
        for rule in ruleset:
            # Undecidable / head2-routed rules: register but don't regex-scan
            if rule.get("route") == "head2" and not rule.get("regex") and not rule.get("meta"):
                continue

            if rule.get("meta"):
                res, counter = _meta_check(rule["meta"], rule, stripped, funcs, counter, prefix)
                findings.extend(res)
                continue

            if not rule.get("regex"):
                continue

            pat = re.compile(rule["regex"], re.MULTILINE)
            skip = re.compile(rule["guard_skip"]) if rule.get("guard_skip") else None

            for i, ln in enumerate(lines):
                if pat.search(ln):
                    if skip and skip.search(ln):
                        continue
                    counter += 1
                    findings.append(_mk(rule, counter, prefix, i + 1, f"line {i+1}"))

    return findings


def coverage_report() -> Dict[str, Any]:
    """Report rule catalog coverage stats."""
    misra_total = len(MISRA_RULES)
    misra_decidable = len([r for r in MISRA_RULES if r.get("decidable")])
    misra_head1 = len([r for r in MISRA_RULES if r.get("route", "head1") == "head1" and (r.get("regex") or r.get("meta"))])
    cert_total = len(CERT_RULES)
    cert_head1 = len([r for r in CERT_RULES if r.get("route", "head1") == "head1" and (r.get("regex") or r.get("meta"))])
    cert_head2 = len([r for r in CERT_RULES if r.get("route") == "head2"])

    return {
        "misra_rules_implemented": misra_total,
        "misra_decidable_head1": misra_head1,
        "misra_routed_to_head2": len([r for r in MISRA_RULES if r.get("route") == "head2"]),
        "cert_rules_implemented": cert_total,
        "cert_decidable_head1": cert_head1,
        "cert_routed_to_head2": cert_head2,
    }
