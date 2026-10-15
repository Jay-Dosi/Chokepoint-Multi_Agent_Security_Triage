"""Live agent loop on the Anthropic Messages API with MCP-discovered tools."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from anthropic import AsyncAnthropic

from app.config import settings

from .base import AgentResult, Executor, LLMProvider, Narrator, ToolCall, ToolSpec, for_llm

log = logging.getLogger("chokepoint.provider.anthropic")

JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)
MAX_TURNS = 12
TOOL_RESULT_BUDGET = 12000


class AnthropicProvider(LLMProvider):
    """Chooses tools, interprets results and writes prose. It computes nothing."""

    name = "anthropic"

    def __init__(self) -> None:
        self.client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        self.model = settings.anthropic_model
        self.max_tokens = settings.llm_max_tokens
        self.temperature = settings.llm_temperature
        self.timeout_s = settings.agent_timeout_s

    def _tools_payload(self, tools: list[ToolSpec]) -> list[dict[str, Any]]:
        payload: list[dict[str, Any]] = [
            {"name": spec.name, "description": spec.description, "input_schema": spec.agent_schema()}
            for spec in tools
        ]
        if payload:
            payload[-1]["cache_control"] = {"type": "ephemeral"}
        return payload

    def _system_payload(self, system: str) -> list[dict[str, Any]]:
        return [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]

    async def _create(
        self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None
    ) -> Any:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "system": self._system_payload(system),
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = tools
        return await self.client.messages.create(**kwargs)

    async def run_agent(
        self,
        *,
        agent: str,
        system: str,
        user: str,
        tools: list[ToolSpec],
        executor: Executor,
        max_tool_calls: int,
        narrate: Narrator,
        context: dict[str, Any],
    ) -> AgentResult:
        tool_payload = self._tools_payload(tools)
        messages: list[dict[str, Any]] = [{"role": "user", "content": user}]
        calls = 0
        turns = 0
        texts: list[str] = []
        deadline = time.monotonic() + self.timeout_s
        stopped = "finished"

        while turns < MAX_TURNS:
            turns += 1
            try:
                response = await self._create(system=system, messages=messages, tools=tool_payload)
            except Exception as exc:  # noqa: BLE001 - surface API failures as a run error
                log.warning("%s: Anthropic call failed: %s", agent, exc)
                await narrate(f"The model call failed: {exc}. Concluding with what is on the blackboard.")
                return AgentResult(text="\n".join(texts), tool_calls=calls, stopped_because="llm_error")

            assistant_content: list[dict[str, Any]] = []
            tool_uses: list[Any] = []
            for block in response.content:
                if block.type == "text":
                    text = str(block.text).strip()
                    if text:
                        texts.append(text)
                        await narrate(text)
                    assistant_content.append({"type": "text", "text": block.text})
                elif block.type == "tool_use":
                    tool_uses.append(block)
                    assistant_content.append(
                        {"type": "tool_use", "id": block.id, "name": block.name, "input": block.input}
                    )
            if assistant_content:
                messages.append({"role": "assistant", "content": assistant_content})

            if not tool_uses:
                break

            results: list[dict[str, Any]] = []
            for block in tool_uses:
                if calls >= max_tool_calls:
                    stopped = "tool_budget"
                    results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps(
                                {"error": "tool budget exhausted; write your conclusion now"}
                            ),
                            "is_error": True,
                        }
                    )
                    continue
                calls += 1
                args = dict(block.input) if isinstance(block.input, dict) else {}
                outcome = await executor(ToolCall(id=str(block.id), name=str(block.name), args=args))
                body = for_llm(outcome.result) if outcome.ok else {"error": outcome.error}
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(body, default=str)[:TOOL_RESULT_BUDGET],
                        "is_error": not outcome.ok,
                    }
                )
            messages.append({"role": "user", "content": results})

            if calls >= max_tool_calls or time.monotonic() > deadline:
                stopped = "tool_budget" if calls >= max_tool_calls else "timeout"
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Your tool budget is spent. Write your conclusion now from the results "
                            "you already have, without calling any tool."
                        ),
                    }
                )
                try:
                    final = await self._create(system=system, messages=messages, tools=None)
                except Exception as exc:  # noqa: BLE001
                    log.warning("%s: final Anthropic call failed: %s", agent, exc)
                    break
                for block in final.content:
                    if block.type == "text" and str(block.text).strip():
                        texts.append(str(block.text).strip())
                        await narrate(str(block.text).strip())
                break

        return AgentResult(text="\n\n".join(texts), tool_calls=calls, stopped_because=stopped)

    async def distill_lesson(self, prompt: str, payload: dict[str, Any]) -> dict[str, Any]:
        """One short call that must return a single JSON object."""
        message = (
            "Feedback document:\n```json\n"
            + json.dumps(payload, indent=2, default=str)
            + "\n```\nReply with the JSON object only."
        )
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=600,
            temperature=0.0,
            system=self._system_payload(prompt),
            messages=[{"role": "user", "content": message}],
        )
        text = "".join(str(b.text) for b in response.content if b.type == "text")
        match = JSON_BLOCK.search(text)
        if not match:
            raise ValueError("lesson distiller returned no JSON object")
        return json.loads(match.group(0))
