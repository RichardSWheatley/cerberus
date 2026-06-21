"""
Knowledge base updater — biweekly refresh cycle.

Fetches latest advisories from CWE, CERT C, NVD/CVE, MISRA, GCC/Clang,
and Zephyr security sources. Stores as JSON for the AI engine to reference
during analysis, giving it current threat context.

Run on a schedule (GitHub Actions cron) or manually via CLI.
"""

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

KB_FILE = Path(".cerberus-kb.json")
KB_META_FILE = Path(".cerberus-kb-meta.json")

SOURCES = [
    {"id": "cwe",    "name": "CWE Database",          "url": "https://cwe.mitre.org"},
    {"id": "cert_c", "name": "CERT C Coding Standard", "url": "https://wiki.sei.cmu.edu/confluence/display/c"},
    {"id": "cve",    "name": "NVD / CVE Feed",         "url": "https://nvd.nist.gov"},
    {"id": "misra",  "name": "MISRA C Advisories",     "url": "https://misra.org.uk"},
    {"id": "gcc",    "name": "GCC/Clang Diagnostics",  "url": "https://gcc.gnu.org"},
    {"id": "oss",    "name": "Zephyr Security",        "url": "https://github.com/zephyrproject-rtos/zephyr/security"},
]

KB_UPDATE_PROMPT = """You are a security research assistant with web search access. For each of the following vulnerability/standards sources, find and report the latest notable updates that a C embedded systems developer targeting Zephyr RTOS should know about.

Search for REAL, CURRENT information from each source:

1. CWE Database — any new CWEs added, Top 25 changes relevant to C
2. CERT C Coding Standard — rule updates, new recommendations
3. NVD/CVE — recent high-severity CVEs affecting: newlib, picolibc, libc, zlib, mbedtls, tinycrypt, any RTOS
4. MISRA C — amendments, technical corrigenda to MISRA C:2012
5. GCC/Clang — new warnings or sanitizer improvements in recent releases
6. Zephyr RTOS — security advisories from the Zephyr project

Return ONLY a JSON array (no markdown, no backticks):
[
  {
    "source_id": "<cwe|cert_c|cve|misra|gcc|oss>",
    "items": [
      {
        "title": "Short title",
        "detail": "What changed and why it matters for embedded C developers.",
        "severity": "<critical|high|medium|low|info>",
        "reference": "URL or identifier",
        "date": "YYYY-MM-DD or 'recent'"
      }
    ]
  }
]

Be factual. Empty items array for a source is better than fabrication."""


def is_update_due(kb_dir: Optional[Path] = None) -> bool:
    """Check if the biweekly update cycle is due."""
    meta_file = (kb_dir or Path(".")) / KB_META_FILE.name
    if not meta_file.exists():
        return True
    try:
        meta = json.loads(meta_file.read_text())
        next_update = datetime.fromisoformat(meta.get("next_update", "2000-01-01"))
        return datetime.now() >= next_update
    except (json.JSONDecodeError, ValueError):
        return True


def load_kb(kb_dir: Optional[Path] = None) -> Optional[str]:
    """Load the knowledge base as a context string for the AI engine."""
    kb_file = (kb_dir or Path(".")) / KB_FILE.name
    if not kb_file.exists():
        return None
    try:
        data = json.loads(kb_file.read_text())
        # Flatten into a concise text summary for the AI context window
        lines = ["Recent security advisories and standards updates:"]
        for source in data:
            for item in source.get("items", []):
                sev = item.get("severity", "info").upper()
                lines.append(f"- [{sev}] {item['title']}: {item['detail']}")
        return "\n".join(lines) if len(lines) > 1 else None
    except (json.JSONDecodeError, KeyError):
        return None


def update_kb(kb_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Run the biweekly knowledge base update.

    Uses Claude with web search to fetch real advisories from tracked sources.

    Returns:
        Dict with 'success', 'sources_updated', 'items_count'
    """
    try:
        import anthropic
    except ImportError:
        return {"success": False, "error": "anthropic package not installed"}

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"success": False, "error": "ANTHROPIC_API_KEY not set"}

    client = anthropic.Anthropic(api_key=api_key)

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        system=KB_UPDATE_PROMPT,
        messages=[{"role": "user", "content": "Check all sources and return the latest updates as of today."}],
        tools=[{"type": "web_search_20250305", "name": "web_search"}],
    )

    text = "".join(block.text for block in message.content if hasattr(block, "text"))
    clean = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        data = json.loads(clean)
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"Failed to parse KB response: {e}"}

    # Save KB data
    target_dir = kb_dir or Path(".")
    target_dir.mkdir(parents=True, exist_ok=True)

    (target_dir / KB_FILE.name).write_text(json.dumps(data, indent=2))

    # Save metadata
    now = datetime.now()
    meta = {
        "last_updated": now.isoformat(),
        "next_update": (now + timedelta(days=14)).isoformat(),
        "sources_checked": [s["id"] for s in SOURCES],
    }
    (target_dir / KB_META_FILE.name).write_text(json.dumps(meta, indent=2))

    total_items = sum(len(s.get("items", [])) for s in data)

    return {
        "success": True,
        "sources_updated": len(data),
        "items_count": total_items,
        "next_update": meta["next_update"],
    }
