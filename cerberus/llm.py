"""
CERBERUS LLM Provider Abstraction

Vendor-agnostic interface for the AI heads. One `complete()` call, swappable
backends. Provider and model are chosen by environment variable so nothing in
the rest of the codebase names a vendor.

Configuration (env vars):
  CERBERUS_LLM_PROVIDER   anthropic | openai | google | openai_compatible
                          (default: anthropic)
  CERBERUS_LLM_MODEL      model string (default: provider-specific sensible default)
  CERBERUS_LLM_API_KEY    API key (falls back to provider-native env vars)
  CERBERUS_LLM_BASE_URL   base URL for openai_compatible (e.g. local Ollama/vLLM)

Provider-native key fallbacks:
  anthropic          -> ANTHROPIC_API_KEY
  openai             -> OPENAI_API_KEY
  google             -> GOOGLE_API_KEY / GEMINI_API_KEY
  openai_compatible  -> CERBERUS_LLM_API_KEY (or "not-needed" for local)

The web_search capability is provider-dependent. Providers that don't support
it degrade gracefully (the knowledge-base updater runs without live search and
flags the result as less current).
"""

import os
import json
from typing import Optional, List, Dict, Any


DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-20250514",
    "openai": "gpt-4o",
    "google": "gemini-1.5-pro",
    "openai_compatible": "local-model",
}


class LLMError(Exception):
    pass


def _get_config():
    provider = os.environ.get("CERBERUS_LLM_PROVIDER", "anthropic").lower()
    model = os.environ.get("CERBERUS_LLM_MODEL") or DEFAULT_MODELS.get(provider)
    base_url = os.environ.get("CERBERUS_LLM_BASE_URL")

    # API key resolution: explicit override, then provider-native fallback
    key = os.environ.get("CERBERUS_LLM_API_KEY")
    if not key:
        if provider == "anthropic":
            key = os.environ.get("ANTHROPIC_API_KEY")
        elif provider == "openai":
            key = os.environ.get("OPENAI_API_KEY")
        elif provider == "google":
            key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        elif provider == "openai_compatible":
            key = "not-needed"  # local servers often need no key

    return provider, model, key, base_url


def provider_supports_web_search(provider: Optional[str] = None) -> bool:
    """Whether the active provider supports a native web-search tool."""
    if provider is None:
        provider, _, _, _ = _get_config()
    return provider == "anthropic"  # only Anthropic's tool is wired today


def complete(
    system: str,
    user: str,
    max_tokens: int = 4096,
    web_search: bool = False,
    json_mode: bool = False,
) -> str:
    """
    Run a single completion against the configured provider.

    Args:
        system:     System prompt
        user:       User message content
        max_tokens: Max output tokens
        web_search: Request native web search (only honored if supported)
        json_mode:  Hint the model to return raw JSON (provider-specific)

    Returns:
        The model's text response (concatenated text blocks).

    Raises:
        LLMError on missing dependency, missing key, or API failure.
    """
    provider, model, key, base_url = _get_config()

    if not key:
        raise LLMError(
            f"No API key for provider '{provider}'. Set CERBERUS_LLM_API_KEY "
            f"or the provider-native variable."
        )

    if provider == "anthropic":
        return _complete_anthropic(system, user, model, key, max_tokens, web_search)
    elif provider == "openai":
        return _complete_openai(system, user, model, key, max_tokens, json_mode, base_url)
    elif provider == "openai_compatible":
        return _complete_openai(system, user, model, key, max_tokens, json_mode,
                                base_url or "http://localhost:11434/v1")
    elif provider == "google":
        return _complete_google(system, user, model, key, max_tokens)
    else:
        raise LLMError(f"Unknown provider: {provider}")


# ── Anthropic ──────────────────────────────────────────────────

def _complete_anthropic(system, user, model, key, max_tokens, web_search):
    try:
        import anthropic
    except ImportError:
        raise LLMError("anthropic package not installed. Run: pip install anthropic")

    client = anthropic.Anthropic(api_key=key)
    kwargs = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    if web_search:
        kwargs["tools"] = [{"type": "web_search_20250305", "name": "web_search"}]

    msg = client.messages.create(**kwargs)
    return "".join(b.text for b in msg.content if hasattr(b, "text"))


# ── OpenAI / OpenAI-compatible (incl. local Ollama, vLLM, LM Studio) ──

def _complete_openai(system, user, model, key, max_tokens, json_mode, base_url):
    try:
        import openai
    except ImportError:
        raise LLMError("openai package not installed. Run: pip install openai")

    client_kwargs = {"api_key": key}
    if base_url:
        client_kwargs["base_url"] = base_url
    client = openai.OpenAI(**client_kwargs)

    kwargs = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    resp = client.chat.completions.create(**kwargs)
    return resp.choices[0].message.content or ""


# ── Google Gemini ──────────────────────────────────────────────

def _complete_google(system, user, model, key, max_tokens):
    try:
        import google.generativeai as genai
    except ImportError:
        raise LLMError("google-generativeai not installed. Run: pip install google-generativeai")

    genai.configure(api_key=key)
    gm = genai.GenerativeModel(model_name=model, system_instruction=system)
    resp = gm.generate_content(
        user,
        generation_config={"max_output_tokens": max_tokens},
    )
    return resp.text or ""


def active_provider_info() -> Dict[str, Any]:
    """Return the active provider/model for logging."""
    provider, model, key, base_url = _get_config()
    return {
        "provider": provider,
        "model": model,
        "has_key": bool(key),
        "base_url": base_url,
        "web_search": provider_supports_web_search(provider),
    }
