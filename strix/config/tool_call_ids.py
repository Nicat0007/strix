"""Keep tool-call ids unique within a conversation.

Some providers return per-turn tool-call ids (``exec_command:0``,
``exec_command:1``, ...) whose counter restarts on every turn. Once the same
id appears twice in one conversation, the request payload has two assistant
tool calls sharing an id and strict providers reject the whole turn, which
permanently kills the agent because the malformed history is replayed on
every retry. Rewriting duplicates to fresh unique ids keeps the history
valid for any provider.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Any
from uuid import uuid4

from openai.types.responses import ResponseFunctionToolCall


# DeepSeek (and some other OpenAI-compatible routes) occasionally leak their
# native control tokens into assistant *content* — e.g. ``<｜end▁of▁thinking｜>``
# or tool-call markup like ``<｜｜DSML｜｜ invoke name="...">``. The call itself
# still executes (it also arrives in the structured tool_calls field), but the
# leaked markup lands in history, where it (1) wastes tokens on every later turn,
# and (2) invites the model to imitate the garbage and emit more malformed calls.
# These tags are identifiable by the full-width vertical bar U+FF5C (｜), which
# never legitimately appears inside an angle-bracket tag in security-testing text,
# so stripping any such tag is safe for every provider.
_LEAKED_CONTROL_TAG_RE = re.compile(r"<[^<>]*｜[^<>]*>")


def strip_leaked_control_tokens(text: str) -> str:
    """Remove leaked provider control-token markup (see ``_LEAKED_CONTROL_TAG_RE``)."""
    if "｜" not in text:
        return text
    return _LEAKED_CONTROL_TAG_RE.sub("", text)


def _clean_content(content: Any) -> tuple[Any, bool]:
    if isinstance(content, str):
        cleaned = strip_leaked_control_tokens(content)
        return cleaned, cleaned != content
    if isinstance(content, list):
        changed = False
        out: list[Any] = []
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                new_text = strip_leaked_control_tokens(block["text"])
                if new_text != block["text"]:
                    block = {**block, "text": new_text}
                    changed = True
            out.append(block)
        return out, changed
    return content, False


def strip_leaked_markup_from_items(items: list[Any]) -> list[Any]:
    """Return ``items`` with leaked control-token markup removed from message
    content. Returns the same list object when nothing changed, so callers can
    cheaply skip a rebuild."""
    changed = False
    out: list[Any] = []
    for item in items:
        if isinstance(item, dict) and "content" in item:
            cleaned, item_changed = _clean_content(item["content"])
            if item_changed:
                item = {**item, "content": cleaned}
                changed = True
        out.append(item)
    return out if changed else items


def new_call_id() -> str:
    return f"call_{uuid4().hex}"


def collect_call_ids(items: list[Any]) -> set[str]:
    used: set[str] = set()
    for item in items:
        if isinstance(item, dict):
            call_id = item.get("call_id")
            if isinstance(call_id, str):
                used.add(call_id)
        elif isinstance(item, ResponseFunctionToolCall):
            used.add(item.call_id)
    return used


def dedupe_history_call_ids(items: list[Any]) -> tuple[list[Any], bool]:
    """Rewrite duplicate call ids in a conversation history.

    Outputs are paired with their call by order, so parallel calls that share
    an id keep answering the right call after the rewrite.
    """
    used: set[str] = set()
    pending: dict[str, deque[str]] = defaultdict(deque)
    rebuilt: list[Any] = []
    changed = False

    for item in items:
        if not isinstance(item, dict):
            rebuilt.append(item)
            continue
        call_id = item.get("call_id")
        if not isinstance(call_id, str):
            rebuilt.append(item)
            continue

        kind = item.get("type")
        if kind == "function_call":
            effective = call_id
            if call_id in used:
                effective = new_call_id()
                item = {**item, "call_id": effective}  # noqa: PLW2901
                changed = True
            used.add(effective)
            pending[call_id].append(effective)
        elif kind == "function_call_output":
            queue = pending.get(call_id)
            if queue:
                effective = queue.popleft()
                if effective != call_id:
                    item = {**item, "call_id": effective}  # noqa: PLW2901
                    changed = True
        rebuilt.append(item)

    return rebuilt, changed


def dedupe_input(model_input: str | list[Any]) -> str | list[Any]:
    if isinstance(model_input, str):
        return strip_leaked_control_tokens(model_input)
    rebuilt, changed = dedupe_history_call_ids(model_input)
    # Strip leaked provider control-token markup from history content on the way
    # in, so the model never re-reads (or imitates) its own leaked markup.
    return strip_leaked_markup_from_items(rebuilt if changed else model_input)


class TurnCallIdRewriter:
    """Rewrite a single turn's tool-call ids that collide with the history.

    A turn's items surface several times (streamed item events, then the
    completed response), so the same original id must always map to the same
    replacement within the turn.
    """

    def __init__(self, model_input: str | list[Any]) -> None:
        self._used = set() if isinstance(model_input, str) else collect_call_ids(model_input)
        self._remap: dict[str, str] = {}
        self._settled: set[str] = set()

    def rewrite_item(self, item: Any) -> Any:
        if not isinstance(item, ResponseFunctionToolCall):
            return item
        original = item.call_id
        if original in self._settled:
            return item
        replacement = self._remap.get(original)
        if replacement is None:
            if original not in self._used:
                self._used.add(original)
                self._settled.add(original)
                return item
            replacement = new_call_id()
            self._remap[original] = replacement
            self._used.add(replacement)
            self._settled.add(replacement)
        return item.model_copy(update={"call_id": replacement})

    def rewrite_items(self, items: list[Any]) -> list[Any]:
        return [self.rewrite_item(item) for item in items]
