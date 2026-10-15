"""LLM providers: the live Anthropic loop and the scripted offline loop."""

from __future__ import annotations

import logging
from functools import lru_cache

from app.config import settings

from .base import AgentResult, Executor, LLMProvider, Narrator, ToolCall, ToolOutcome, ToolSpec
from .scripted_provider import ScriptedProvider, classify

log = logging.getLogger("chokepoint.providers")

__all__ = [
    "AgentResult",
    "Executor",
    "LLMProvider",
    "Narrator",
    "ScriptedProvider",
    "ToolCall",
    "ToolOutcome",
    "ToolSpec",
    "classify",
    "get_provider",
]


@lru_cache(maxsize=2)
def _scripted() -> LLMProvider:
    return ScriptedProvider()


@lru_cache(maxsize=2)
def _live() -> LLMProvider:
    from .anthropic_provider import AnthropicProvider

    return AnthropicProvider()


def get_provider(mode: str | None = None) -> LLMProvider:
    """Resolve the provider for a run. Falls back to scripted without a key."""
    wanted = (mode or settings.effective_mode).strip().lower()
    if wanted != "live":
        return _scripted()
    if not settings.anthropic_api_key.strip():
        log.warning("live mode requested without ANTHROPIC_API_KEY; using the scripted provider")
        return _scripted()
    try:
        return _live()
    except Exception as exc:  # noqa: BLE001 - missing SDK must not break a run
        log.warning("could not start the Anthropic provider (%s); using the scripted provider", exc)
        return _scripted()
