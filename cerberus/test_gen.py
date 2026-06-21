"""
Unity test generator — produces complete test files using ThrowTheSwitch/Unity.

Takes the combined findings (scanner + AI) and generates regression tests that
specifically target each identified vulnerability. Also generates standard
boundary/null/error-path tests for every public function.
"""

import json
import os
import sys
from typing import List, Dict, Any, Optional
from pathlib import Path

UNITY_TEST_SYSTEM_PROMPT = """You are an expert C unit test engineer using the Unity test framework (ThrowTheSwitch/Unity). You are part of an automated CI pipeline.

Given C source code AND static analysis findings (from both a deterministic scanner and AI deep analysis), generate a COMPLETE, COMPILABLE Unity test file that:

1. Includes proper headers:
   #include "unity.h"
   // Plus any headers needed from the source

2. Provides setUp()/tearDown() that reset global state between tests

3. For EACH analysis finding, writes a targeted regression test:
   - Buffer overflow findings → test with boundary-length and over-length inputs
   - NULL dereference findings → test with NULL arguments
   - Off-by-one findings → test at exact boundary values
   - Memory leak findings → test allocation/free cycles
   - Integer overflow findings → test with INT_MAX/INT_MIN values
   - Format string findings → test with format specifier characters in input
   - Each test function comment references the finding ID: /* Targets F001, S003 */

4. For EACH public function, writes standard tests:
   - Happy path with valid inputs
   - Edge cases (empty string, zero, negative, max values)
   - Error paths (NULL pointers, invalid arguments)

5. Uses proper Unity assertions:
   - TEST_ASSERT_EQUAL_INT, TEST_ASSERT_EQUAL_STRING, TEST_ASSERT_NULL,
     TEST_ASSERT_NOT_NULL, TEST_ASSERT_TRUE, TEST_ASSERT_FALSE,
     TEST_ASSERT_EQUAL_MEMORY, TEST_ASSERT_EQUAL_PTR

6. Includes a test runner:
   int main(void) {
       UNITY_BEGIN();
       RUN_TEST(test_function_name);
       ...
       return UNITY_END();
   }

7. Where the source uses external functions (read, recv, etc.), provide mock/stub
   implementations at the top of the test file with controllable return values.

8. Add a header comment:
   /*
    * Auto-generated Unity regression tests
    * Source: <filename>
    * Findings targeted: <count>
    * Build: gcc -o test_runner test_<module>.c <module>.c unity.c -Iunity/src
    */

Return ONLY the complete .c file content. No markdown fences, no JSON, no preamble.
The output must compile with: gcc -Wall -Wextra -o test_runner test_file.c unity.c -Iunity/src
(source file may need stubs for system calls)."""


def generate_unity_tests(
    source: str,
    filepath: str,
    all_findings: List[Dict[str, Any]],
    output_path: Optional[str] = None,
) -> str:
    """
    Generate a Unity test file targeting the analysis findings.

    Args:
        source: The C source code
        filepath: Path to the original source file
        all_findings: Combined scanner + AI findings (as dicts)
        output_path: Where to write the test file (optional)

    Returns:
        The generated test file content
    """
    try:
        import anthropic
    except ImportError:
        print("ERROR: anthropic package not installed. Run: pip install anthropic", file=sys.stderr)
        sys.exit(1)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    findings_json = json.dumps(all_findings, indent=2)

    user_content = f"""Source file: {filepath}

Analysis findings to write regression tests for:
{findings_json}

Source code:
```c
{source}
```"""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=8192,
        system=UNITY_TEST_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )

    test_code = "".join(block.text for block in message.content if hasattr(block, "text"))
    test_code = test_code.strip().removeprefix("```c").removeprefix("```").removesuffix("```").strip()

    if output_path:
        Path(output_path).write_text(test_code)

    return test_code
