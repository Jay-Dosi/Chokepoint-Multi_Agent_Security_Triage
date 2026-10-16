"""Live agent loop on the Gemini API with MCP-discovered tools.

Two things differ from a plain chat loop and are handled here:

1. Gemini declares tools with an OpenAPI 3.0 schema subset, not raw JSON
   Schema. The MCP tools are described by Pydantic models, so their schemas
   carry `$ref`/`$defs`, `anyOf` unions and `additionalProperties`, none of
   which Gemini accepts. :func:`to_gemini_schema` rewrites them.
2. Automatic function calling is switched off. The orchestrator drives the
   loop so every call is role-checked, recorded as a Step and streamed.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from google import genai
from google.genai import types

from app.config import settings

from .base import AgentResult, Executor, LLMProvider, Narrator, ToolCall, ToolSpec, for_llm

log = logging.getLogger("chokepoint.provider.gemini")

JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)
MAX_TURNS = 12
TOOL_RESULT_BUDGET = 12000

# JSON Schema keywords Gemini's FunctionDeclaration does not accept.
DROPPED_KEYS = frozenset(
    {
        "$schema",
        "$id",
        "$defs",
        "definitions",
        "additionalProperties",
        "title",
        "default",
        "examples",
        "const",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "pattern",
        "minItems",
        "maxItems",
        "allOf",
        "discriminator",
    }
)

TYPE_MAP = {
    "string": "STRING",
    "number": "NUMBER",
    "integer": "INTEGER",
    "boolean": "BOOLEAN",
    "array": "ARRAY",
    "object": "OBJECT",
}


def _deref(node: Any, defs: dict[str, Any], depth: int = 0) -> Any:
    """Inline `$ref` targets. Pydantic emits one `$defs` entry per nested model."""
    if depth > 12 or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/"):
        target = defs.get(ref.split("/")[-1])
        if isinstance(target, dict):
            merged = {k: v for k, v in node.items() if k != "$ref"}
            return _deref({**target, **merged}, defs, depth + 1)
    return node


def _convert(node: Any, defs: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """One JSON Schema node to one Gemini Schema node."""
    if depth > 12 or not isinstance(node, dict):
        return {"type": "STRING"}
    node = _deref(node, defs, depth)

    # `str | None` becomes anyOf[X, null]; Gemini expresses that as nullable.
    options = node.get("anyOf") or node.get("oneOf")
    if isinstance(options, list):
        concrete = [o for o in options if isinstance(o, dict) and o.get("type") != "null"]
        nullable = len(concrete) < len(options)
        if concrete:
            converted = _convert(concrete[0], defs, depth + 1)
            if nullable:
                converted["nullable"] = True
            if node.get("description"):
                converted["description"] = str(node["description"])
            return converted
        return {"type": "STRING", "nullable": True}

    out: dict[str, Any] = {}
    raw_type = node.get("type")
    if isinstance(raw_type, list):
        concrete_types = [t for t in raw_type if t != "null"]
        raw_type = concrete_types[0] if concrete_types else "string"
        out["nullable"] = True
    out["type"] = TYPE_MAP.get(str(raw_type or "string"), "STRING")

    if node.get("description"):
        out["description"] = str(node["description"])
    if isinstance(node.get("enum"), list):
        out["enum"] = [str(v) for v in node["enum"]]
        out["type"] = "STRING"

    if out["type"] == "OBJECT":
        properties = node.get("properties")
        if isinstance(properties, dict) and properties:
            out["properties"] = {
                key: _convert(value, defs, depth + 1) for key, value in properties.items()
            }
            required = [r for r in (node.get("required") or []) if r in properties]
            if required:
                out["required"] = required
        else:
            # Gemini rejects an OBJECT with no properties; describe it loosely.
            out = {"type": "STRING", "description": str(node.get("description") or "JSON object")}
    elif out["type"] == "ARRAY":
        out["items"] = _convert(node.get("items") or {"type": "string"}, defs, depth + 1)

    for key in DROPPED_KEYS:
        out.pop(key, None)
    return out


def to_gemini_schema(schema: dict[str, Any]) -> dict[str, Any] | None:
    """An MCP tool's JSON Schema as a Gemini parameter schema, or None if empty."""
    defs = schema.get("$defs") if isinstance(schema.get("$defs"), dict) else {}
    properties = schema.get("properties")
    if not isinstance(properties, dict) or not properties:
        return None
    converted = {key: _convert(value, defs) for key, value in properties.items()}
    required = [r for r in (schema.get("required") or []) if r in converted]
    out: dict[str, Any] = {"type": "OBJECT", "properties": converted}
    if required:
        out["required"] = required
    return out


class GeminiProvider(LLMProvider):
    """Chooses tools, interprets results and writes prose. It computes nothing."""

    name = "gemini"

    def __init__(self) -> None:
        self.client = genai.Client(api_key=settings.gemini_api_key)
        self.model = settings.gemini_model
        self.max_tokens = settings.llm_max_tokens
        self.temperature = settings.llm_temperature
        self.timeout_s = settings.agent_timeout_s

    def _declarations(self, tools: list[ToolSpec]) -> list[types.Tool]:
        declarations = []
        for spec in tools:
            parameters = to_gemini_schema(spec.agent_schema())
            declaration: dict[str, Any] = {
                "name": spec.name,
                "description": spec.description[:1024],
            }
            if parameters:
                declaration["parameters"] = parameters
            declarations.append(declaration)
        return [types.Tool(function_declarations=declarations)]

    def _config(self, system: str, tools: list[types.Tool] | None) -> types.GenerateContentConfig:
        kwargs: dict[str, Any] = {
            "system_instruction": system,
            "temperature": self.temperature,
            "max_output_tokens": self.max_tokens,
        }
        if tools:
            kwargs["tools"] = tools
            # The orchestrator runs the loop; the SDK must not call anything.
            kwargs["automatic_function_calling"] = types.AutomaticFunctionCallingConfig(
                disable=True
            )
        return types.GenerateContentConfig(**kwargs)

    async def _generate(
        self, *, system: str, contents: list[types.Content], tools: list[types.Tool] | None
    ) -> Any:
        return await self.client.aio.models.generate_content(
            model=self.model,
            contents=contents,
            config=self._config(system, tools),
        )

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
        declarations = self._declarations(tools)
        contents: list[types.Content] = [
            types.Content(role="user", parts=[types.Part.from_text(text=user)])
        ]
        calls = 0
        turns = 0
        texts: list[str] = []
        deadline = time.monotonic() + self.timeout_s
        stopped = "finished"

        while turns < MAX_TURNS:
            turns += 1
            try:
                response = await self._generate(
                    system=system, contents=contents, tools=declarations
                )
            except Exception as exc:  # noqa: BLE001 - surface API failures as a run error
                log.warning("%s: Gemini call failed: %s", agent, exc)
                await narrate(f"The model call failed: {exc}. Concluding with what is on the blackboard.")
                return AgentResult(text="\n".join(texts), tool_calls=calls, stopped_because="llm_error")

            candidate = (response.candidates or [None])[0]
            if candidate is None or candidate.content is None:
                reason = getattr(response, "prompt_feedback", None)
                log.warning("%s: Gemini returned no content (%s)", agent, reason)
                stopped = "empty_response"
                break

            parts = candidate.content.parts or []
            tool_uses = []
            for part in parts:
                if getattr(part, "text", None):
                    text = str(part.text).strip()
                    if text:
                        texts.append(text)
                        await narrate(text)
                if getattr(part, "function_call", None):
                    tool_uses.append(part.function_call)
            contents.append(candidate.content)

            if not tool_uses:
                break

            responses: list[types.Part] = []
            for call in tool_uses:
                name = str(call.name or "")
                if calls >= max_tool_calls:
                    stopped = "tool_budget"
                    responses.append(
                        types.Part.from_function_response(
                            name=name,
                            response={"error": "tool budget exhausted; write your conclusion now"},
                        )
                    )
                    continue
                calls += 1
                args = dict(call.args) if isinstance(call.args, dict) else {}
                outcome = await executor(ToolCall(id=f"{agent}-{calls}", name=name, args=args))
                body = for_llm(outcome.result) if outcome.ok else {"error": outcome.error}
                # Gemini requires an object here, so oversized results are
                # carried as one trimmed JSON string rather than raw fields.
                encoded = json.dumps(body, default=str)
                if len(encoded) > TOOL_RESULT_BUDGET:
                    payload: dict[str, Any] = {
                        "truncated": True,
                        "result_json": encoded[:TOOL_RESULT_BUDGET],
                    }
                else:
                    payload = body if isinstance(body, dict) else {"result": body}
                responses.append(types.Part.from_function_response(name=name, response=payload))
            contents.append(types.Content(role="user", parts=responses))

            if calls >= max_tool_calls or time.monotonic() > deadline:
                stopped = "tool_budget" if calls >= max_tool_calls else "timeout"
                contents.append(
                    types.Content(
                        role="user",
                        parts=[
                            types.Part.from_text(
                                text=(
                                    "Your tool budget is spent. Write your conclusion now from the "
                                    "results you already have, without calling any tool."
                                )
                            )
                        ],
                    )
                )
                try:
                    final = await self._generate(system=system, contents=contents, tools=None)
                except Exception as exc:  # noqa: BLE001
                    log.warning("%s: final Gemini call failed: %s", agent, exc)
                    break
                final_candidate = (final.candidates or [None])[0]
                if final_candidate is not None and final_candidate.content is not None:
                    for part in final_candidate.content.parts or []:
                        if getattr(part, "text", None) and str(part.text).strip():
                            texts.append(str(part.text).strip())
                            await narrate(str(part.text).strip())
                break

        return AgentResult(text="\n\n".join(texts), tool_calls=calls, stopped_because=stopped)

    async def distill_lesson(self, prompt: str, payload: dict[str, Any]) -> dict[str, Any]:
        """One short call constrained to JSON output."""
        message = (
            "Feedback document:\n```json\n"
            + json.dumps(payload, indent=2, default=str)
            + "\n```\nReply with the JSON object only."
        )
        response = await self.client.aio.models.generate_content(
            model=self.model,
            contents=[types.Content(role="user", parts=[types.Part.from_text(text=message)])],
            config=types.GenerateContentConfig(
                system_instruction=prompt,
                temperature=0.0,
                max_output_tokens=600,
                response_mime_type="application/json",
            ),
        )
        candidate = (response.candidates or [None])[0]
        text = ""
        if candidate is not None and candidate.content is not None:
            text = "".join(
                str(part.text) for part in (candidate.content.parts or []) if getattr(part, "text", None)
            )
        match = JSON_BLOCK.search(text)
        if not match:
            raise ValueError("lesson distiller returned no JSON object")
        return json.loads(match.group(0))
