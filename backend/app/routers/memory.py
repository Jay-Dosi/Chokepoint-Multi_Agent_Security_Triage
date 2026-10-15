"""GET /api/memory/lessons - lessons with their scope, source and usage."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter

from app.db import ro_query
from app.memory.embeddings import embedder
from app.models import EmbeddingStatus, FeedbackModel, GraphNode, LessonDetail, LessonsResponse

router = APIRouter(prefix="/memory", tags=["memory"])

LESSONS_CYPHER = """
MATCH (l:Lesson)
OPTIONAL MATCH (l)-[:APPLIES_TO]->(n)
OPTIONAL MATCH (fb:Feedback)-[:TAUGHT]->(l)
OPTIONAL MATCH (i:Investigation)-[:USED_LESSON]->(l)
RETURN l.id AS id, l.text AS text, l.scope_kind AS scope_kind, l.scope_value AS scope_value,
       l.effect AS effect, l.strength AS strength, coalesce(l.uses, 0) AS uses,
       coalesce(l.created_at, '') AS created_at,
       collect(DISTINCT n.id) AS applies_to_ids,
       collect(DISTINCT labels(n)[0]) AS applies_to_labels,
       collect(DISTINCT fb.id) AS feedback_ids,
       collect(DISTINCT i.id) AS investigation_ids
ORDER BY l.id
"""

FEEDBACK_CYPHER = """
MATCH (fb:Feedback)
WHERE fb.id IN $ids
OPTIONAL MATCH (fb)-[:TAUGHT]->(l:Lesson)
RETURN fb.id AS id, fb.action AS action, fb.new_kind AS new_kind, fb.note AS note,
       fb.by AS by, fb.at AS at, coalesce(l.id, '') AS lesson_id
"""

NODE_CYPHER = """
MATCH (n)
WHERE n.id IN $ids
RETURN n.id AS id, labels(n)[0] AS label, coalesce(n.name, n.id) AS name
"""


def _collect() -> LessonsResponse:
    rows = ro_query(LESSONS_CYPHER).dicts()
    feedback_ids = [
        str(f) for row in rows for f in (row.get("feedback_ids") or []) if f
    ]
    feedback_map: dict[str, FeedbackModel] = {}
    if feedback_ids:
        for row in ro_query(FEEDBACK_CYPHER, {"ids": feedback_ids}).dicts():
            new_kind = str(row.get("new_kind") or "")
            feedback_map[str(row["id"])] = FeedbackModel(
                id=str(row["id"]),
                action="override" if str(row.get("action")) == "override" else "agree",
                new_kind=new_kind if new_kind in ("FIX_NOW", "SCHEDULE", "ACCEPT", "SUPPRESS") else None,
                note=str(row.get("note") or ""),
                by=str(row.get("by") or ""),
                at=str(row.get("at") or ""),
                lesson_id=str(row.get("lesson_id") or ""),
            )

    node_ids = [str(n) for row in rows for n in (row.get("applies_to_ids") or []) if n]
    node_map: dict[str, GraphNode] = {}
    if node_ids:
        for row in ro_query(NODE_CYPHER, {"ids": list(dict.fromkeys(node_ids))[:400]}).dicts():
            node_map[str(row["id"])] = GraphNode(
                id=str(row["id"]),
                label=str(row.get("label") or "Unknown"),
                props={"name": str(row.get("name") or row["id"])},
            )

    lessons: list[LessonDetail] = []
    for row in rows:
        applies = [node_map[str(n)] for n in (row.get("applies_to_ids") or []) if str(n) in node_map]
        source = next(
            (feedback_map[str(f)] for f in (row.get("feedback_ids") or []) if str(f) in feedback_map),
            None,
        )
        lessons.append(
            LessonDetail(
                id=str(row["id"]),
                text=str(row.get("text") or ""),
                scope_kind=str(row.get("scope_kind") or ""),
                scope_value=str(row.get("scope_value") or ""),
                effect=str(row.get("effect") or ""),
                strength=float(row.get("strength") or 0.0),
                uses=int(row.get("uses") or 0),
                created_at=str(row.get("created_at") or ""),
                applies_to=applies,
                source_feedback=source,
                investigations=[str(i) for i in (row.get("investigation_ids") or []) if i],
            )
        )

    status = embedder().status()
    note = (
        "Lessons are retrieved two ways: by graph proximity, when a lesson APPLIES_TO a node within "
        "two hops of the subject, and by embedding similarity on the question text."
    )
    if status.get("warning"):
        note += f" Vector memory is off: {status['warning']} Retrieval falls back to keyword plus graph proximity."
    return LessonsResponse(lessons=lessons, embeddings=EmbeddingStatus(**status), note=note)


@router.get("/lessons", response_model=LessonsResponse)
async def lessons() -> LessonsResponse:
    return await asyncio.to_thread(_collect)
