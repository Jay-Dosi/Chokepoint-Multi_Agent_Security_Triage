"""Analyst feedback becomes a Lesson that changes the next investigation.

The lesson text and scope are distilled by the active provider (an LLM call in
live mode, a rule in scripted mode) and then written through the MCP
`record_lesson` tool with the `backend` role, which no agent holds.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.db import ro_query, rw_query
from app.models import FeedbackModel, FeedbackRequest, FeedbackResponse, MemoryHit
from app.orchestrator.mcp_client import client
from app.orchestrator.providers import ToolCall, get_provider
from app.orchestrator.runner import load_prompt

log = logging.getLogger("chokepoint.lessons")

VERDICT_CONTEXT_CYPHER = """
MATCH (i:Investigation)-[:PRODUCED]->(v:Verdict {id: $vid})
OPTIONAL MATCH (v)-[:ON]->(f:Finding)
OPTIONAL MATCH (s:Service)-[:HAS_FINDING]->(f)
OPTIONAL MATCH (f)-[:VIA]->(pk:Package)
OPTIONAL MATCH (t:Team)-[:OWNS]->(s)
RETURN i.id AS investigation_id, v.kind AS kind, v.confidence AS confidence,
       collect(DISTINCT f.id) AS finding_ids, collect(DISTINCT s.id) AS service_ids,
       collect(DISTINCT pk.name) AS packages, collect(DISTINCT t.id) AS team_ids
"""
SERVICE_PROPS_CYPHER = """
MATCH (s:Service {id: $sid})
RETURN s.id AS id, s.name AS name, s.env AS env, s.cluster AS cluster, s.tier AS tier,
       s.status AS status
"""
NEXT_FEEDBACK_CYPHER = "MATCH (fb:Feedback) RETURN count(fb) AS c"
CREATE_FEEDBACK_CYPHER = """
MATCH (v:Verdict {id: $vid})
CREATE (fb:Feedback {id: $fid, action: $action, new_kind: $new_kind, note: $note,
                     by: $by, at: $now})
CREATE (fb)-[:ON]->(v)
RETURN fb.id AS id
"""
APPLY_OVERRIDE_CYPHER = """
MATCH (v:Verdict {id: $vid})
SET v.kind = $kind, v.overridden = true
RETURN v.id AS id, v.kind AS kind
"""
SCOPE_CYPHER: dict[str, str] = {
    "cluster": "MATCH (s:Service) WHERE s.cluster = $value RETURN s.id AS id",
    "service": "MATCH (s:Service) WHERE s.id = $value OR s.name = $value RETURN s.id AS id",
    "package": "MATCH (p:Package) WHERE p.name = $value OR p.id = $value RETURN p.id AS id",
    "team": (
        "MATCH (t:Team) WHERE t.id = $value OR t.name = $value "
        "OPTIONAL MATCH (t)-[:OWNS]->(s:Service) "
        "RETURN collect(DISTINCT t.id) + collect(DISTINCT s.id) AS ids"
    ),
    "control": "MATCH (c:Control) WHERE c.id = $value OR c.name = $value RETURN c.id AS id",
}
LESSON_READ_CYPHER = """
MATCH (l:Lesson {id: $lid})
RETURN l.id AS lesson_id, l.text AS text, l.effect AS effect, l.scope_kind AS scope_kind,
       l.scope_value AS scope_value, l.strength AS strength, coalesce(l.uses, 0) AS uses
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scope_ids(scope_kind: str, scope_value: str) -> list[str]:
    cypher = SCOPE_CYPHER.get(scope_kind)
    if not cypher or not scope_value:
        return []
    try:
        outcome = ro_query(cypher, {"value": scope_value})
    except Exception as exc:  # noqa: BLE001
        log.warning("scope resolution failed for %s=%s: %s", scope_kind, scope_value, exc)
        return []
    ids: list[str] = []
    for row in outcome.dicts():
        if "ids" in row and isinstance(row["ids"], list):
            ids += [str(v) for v in row["ids"] if v]
        elif row.get("id"):
            ids.append(str(row["id"]))
    return list(dict.fromkeys(ids))[:80]


def verdict_context(verdict_id: str) -> dict[str, Any] | None:
    row = ro_query(VERDICT_CONTEXT_CYPHER, {"vid": verdict_id}).first()
    if row is None or not row.get("investigation_id"):
        return None
    service_ids = [str(s) for s in (row.get("service_ids") or []) if s]
    service: dict[str, Any] = {}
    if service_ids:
        service = ro_query(SERVICE_PROPS_CYPHER, {"sid": service_ids[0]}).first() or {}
    packages = [str(p) for p in (row.get("packages") or []) if p]
    return {
        "verdict_id": verdict_id,
        "investigation_id": str(row["investigation_id"]),
        "kind": str(row.get("kind") or ""),
        "confidence": float(row.get("confidence") or 0.0),
        "finding_ids": [str(f) for f in (row.get("finding_ids") or []) if f],
        "service_ids": service_ids,
        "service": service,
        "package": packages[0] if packages else "",
        "team_ids": [str(t) for t in (row.get("team_ids") or []) if t],
    }


async def record_feedback(verdict_id: str, request: FeedbackRequest) -> FeedbackResponse:
    """Store Feedback, and on an override distil and store the Lesson."""
    context = verdict_context(verdict_id)
    if context is None:
        raise KeyError(f"no verdict {verdict_id}")
    if request.action == "override" and not request.note.strip():
        raise ValueError("an override requires a note")
    if request.action == "override" and request.new_kind is None:
        raise ValueError("an override requires new_kind")

    index = int(ro_query(NEXT_FEEDBACK_CYPHER).scalar(0) or 0) + 1
    feedback_id = f"FB-{index:04d}"
    rw_query(
        CREATE_FEEDBACK_CYPHER,
        {
            "vid": verdict_id,
            "fid": feedback_id,
            "action": request.action,
            "new_kind": request.new_kind or "",
            "note": request.note.strip(),
            "by": request.by or "analyst",
            "now": _now(),
        },
    )

    if request.action == "agree":
        return FeedbackResponse(
            feedback_id=feedback_id,
            verdict_id=verdict_id,
            action=request.action,
            message="Agreement recorded. No lesson is created when the verdict stands.",
        )

    rw_query(APPLY_OVERRIDE_CYPHER, {"vid": verdict_id, "kind": request.new_kind})

    payload = {
        **context,
        "new_kind": request.new_kind,
        "note": request.note.strip(),
        "by": request.by,
    }
    provider = get_provider()
    try:
        distilled = await provider.distill_lesson(load_prompt("lesson_distill"), payload)
    except Exception as exc:  # noqa: BLE001 - never lose the override over a model failure
        log.warning("lesson distillation failed (%s); using the rule-based distiller", exc)
        from app.orchestrator.providers.scripted_provider import ScriptedProvider

        distilled = await ScriptedProvider().distill_lesson("", payload)

    scope_kind = str(distilled.get("scope_kind") or "service")
    scope_value = str(distilled.get("scope_value") or (context["service"].get("id") or ""))
    if scope_kind not in SCOPE_CYPHER:
        scope_kind = "service"
    apply_to = _scope_ids(scope_kind, scope_value)
    if not apply_to:
        scope_kind, scope_value = "service", str(context["service"].get("id") or "")
        apply_to = _scope_ids(scope_kind, scope_value)

    await client.connect()
    outcome = await client.call_tool(
        "backend",
        ToolCall(
            id=f"lesson-{feedback_id}",
            name="record_lesson",
            args={
                "text": str(distilled.get("text") or "").strip(),
                "scope_kind": scope_kind,
                "scope_value": scope_value,
                "effect": str(distilled.get("effect") or "downgrade"),
                "strength": float(distilled.get("strength") or 0.7),
                "apply_to_ids": apply_to,
                "feedback_id": feedback_id,
            },
        ),
    )
    if not outcome.ok:
        return FeedbackResponse(
            feedback_id=feedback_id,
            verdict_id=verdict_id,
            action=request.action,
            message=f"Override recorded, but the lesson could not be stored: {outcome.error}",
        )

    data = outcome.result.get("data") or {}
    lesson_id = str(data.get("lesson_id") or "")
    lesson_row = ro_query(LESSON_READ_CYPHER, {"lid": lesson_id}).first() or {}
    hit = MemoryHit(
        lesson_id=lesson_id,
        text=str(lesson_row.get("text") or distilled.get("text") or ""),
        effect=str(lesson_row.get("effect") or ""),
        scope_kind=str(lesson_row.get("scope_kind") or scope_kind),
        scope_value=str(lesson_row.get("scope_value") or scope_value),
        strength=float(lesson_row.get("strength") or 0.0),
        uses=int(lesson_row.get("uses") or 0),
        why_retrieved="graph",
    )
    return FeedbackResponse(
        feedback_id=feedback_id,
        verdict_id=verdict_id,
        action=request.action,
        lesson=hit,
        lesson_applies_to=apply_to,
        message=(
            f"Override recorded. Lesson {lesson_id} now applies to {len(apply_to)} node(s) "
            f"scoped by {scope_kind}={scope_value}."
        ),
    )


def feedback_for_verdict(verdict_id: str) -> FeedbackModel | None:
    row = ro_query(
        """
        MATCH (fb:Feedback)-[:ON]->(:Verdict {id: $vid})
        OPTIONAL MATCH (fb)-[:TAUGHT]->(l:Lesson)
        RETURN fb.id AS id, fb.action AS action, fb.new_kind AS new_kind, fb.note AS note,
               fb.by AS by, fb.at AS at, coalesce(l.id, '') AS lesson_id
        ORDER BY fb.at DESC
        LIMIT 1
        """,
        {"vid": verdict_id},
    ).first()
    if row is None:
        return None
    new_kind = str(row.get("new_kind") or "")
    return FeedbackModel(
        id=str(row["id"]),
        action="override" if str(row.get("action")) == "override" else "agree",
        new_kind=new_kind if new_kind in ("FIX_NOW", "SCHEDULE", "ACCEPT", "SUPPRESS") else None,
        note=str(row.get("note") or ""),
        by=str(row.get("by") or ""),
        at=str(row.get("at") or ""),
        lesson_id=str(row.get("lesson_id") or ""),
    )
