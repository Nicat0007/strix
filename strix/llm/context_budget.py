"""Model-aware token budgets, resolved from LiteLLM model metadata with a
large configurable fallback for models LiteLLM doesn't map.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from strix.config import load_settings


logger = logging.getLogger(__name__)

# LiteLLM keys models without the routing prefix users type (``openai/``,
# ``litellm/``, ``ollama/`` ...). Strip a leading provider segment on lookup.
_STRIPPABLE_PREFIXES = (
    "openai/",
    "chatgpt/",
    "litellm/",
    "any-llm/",
    "ollama/",
    "ollama_chat/",
)

_DEFAULT_OUTPUT_TOKENS = 8_192


def _lookup_key(model: str) -> str:
    for prefix in _STRIPPABLE_PREFIXES:
        if model.startswith(prefix):
            return model[len(prefix) :]
    return model


def _safe_get_model_info(model: str) -> dict[str, Any] | None:
    try:
        import litellm

        return dict(litellm.get_model_info(model))
    except Exception:  # noqa: BLE001 - unmapped models raise; caller falls back.
        return None


@lru_cache(maxsize=128)
def _model_info(model: str) -> dict[str, int]:
    lookup_key = _lookup_key(model)
    # Provider-qualified ChatGPT lookups may start a synchronous device-login
    # poll. LiteLLM keys the metadata by the underlying model slug.
    candidates = (lookup_key,) if model.startswith("chatgpt/") else (model, lookup_key)
    for candidate in candidates:
        info = _safe_get_model_info(candidate)
        if info is not None:
            return {
                "max_input_tokens": int(
                    info.get("max_input_tokens") or info.get("max_tokens") or 0
                ),
                "max_output_tokens": int(info.get("max_output_tokens") or 0),
            }
    logger.debug("No LiteLLM model info for %r; using configured fallbacks", model)
    return {"max_input_tokens": 0, "max_output_tokens": 0}


def context_window(model: str) -> int:
    """Input token capacity for ``model`` (configured fallback when unmapped)."""
    resolved = _model_info(model)["max_input_tokens"]
    return resolved or load_settings().context.fallback_context_tokens


def output_limit(model: str) -> int:
    """Max output tokens for ``model`` (a conservative default when unmapped)."""
    return _model_info(model)["max_output_tokens"] or _DEFAULT_OUTPUT_TOKENS


def count_tokens(model: str, text: str) -> int:
    """Token count for ``text`` under ``model``.

    When LiteLLM can't count (a model/tokenizer it doesn't know — DeepSeek is a
    real case), fall back to a ``chars/4`` estimate rather than raw UTF-8 byte
    length. Byte length over-counts by ~4x for typical text, which would make the
    budget check think the context is ~4x fuller than it is and fire compaction
    far too often — every fire is an extra uncached summary LLM call, so on a
    model that hits this fallback the old behaviour was a silent, recurring cost.
    Under-counting is the safe direction here: a genuine overflow is caught by the
    provider's context-length error and ``maybe_compact(force=True)`` (see
    ``strix/llm/compaction.py``), so an occasional miss self-corrects.
    """
    if not text:
        return 0
    try:
        import litellm

        return int(litellm.token_counter(model=_lookup_key(model), text=text))
    except Exception:  # noqa: BLE001 - tokenizer may be unavailable for some models.
        # ~4 characters per token is the standard rough estimate for English-ish
        # text; far closer than byte length, and overflow is recoverable.
        return max(1, len(text) // 4)
