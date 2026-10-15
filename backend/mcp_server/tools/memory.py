"""Memory tools (PRD 8.3): hybrid lesson recall and the day-over-day diff."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Annotated, Any

from pydantic import Field

from app.db import ro_query
from app.memory.embeddings import embedder

from ..attack import enumerate_paths, total_weight
from ..graph_ops import envelope, error_envelope, load_projection

log = logging.getLogger("chokepoint.tools.memory")

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.-]+")

DIRECT_LESSON_CYPHER = """
MATCH (l:Lesson)-[:APPLIES_TO]->(t)
WHERE t.id IN $subjects
RETURN DISTINCT l.id AS id, l.text AS text, l.effect AS effect, l.scope_kind AS scope_kind,
       l.scope_value AS scope_value, l.strength AS strength, coalesce(l.uses, 0) AS uses,
       t.id AS via, 0 AS distance
LIMIT 40
"""

NEAR_LESSON_CYPHER = """
UNWIND $subjects AS sid
MATCH (s) WHERE s.id = sid
MATCH (s)-[*1..2]-(t)<-[:APPLIES_TO]-(l:Lesson)
RETURN DISTINCT l.id AS id, l.text AS text, l.effect AS effect, l.scope_kind AS scope_kind,
       l.scope_value AS scope_value, l.strength AS strength, coalesce(l.uses, 0) AS uses,
       t.id AS via, 2 AS distance
LIMIT 40
"""

VECTOR_LESSON_CYPHER = """
CALL db.idx.vector.queryNodes('Lesson', 'embedding', $k, vecf32($q)) YIELD node, score
RETURN node.id AS id, node.text AS text, node.effect AS effect, node.scope_kind AS scope_kind,
       node.scope_value AS scope_value, node.strength AS strength,
       coalesce(node.uses, 0) AS uses, score AS score
"""

ALL_LESSON_CYPHER = """
MATCH (l:Lesson)
RETURN l.id AS id, l.text AS text, l.effect AS effect, l.scope_kind AS scope_kind,
       l.scope_value AS scope_value, l.strength AS strength, coalesce(l.uses, 0) AS uses
LIMIT 200
"""

PAST_VERDICT_CYPHER = """
MATCH (v:Verdict)-[:ON]->(f:Finding)<-[:HAS_FINDING]-(s:Service)
WHERE f.id IN $subjects OR s.id IN $subjects
OPTIONAL MATCH (fb:Feedback)-[:ON]->(v)
RETURN v.id AS verdict_id, v.kind AS kind, v.confidence AS confidence,
       v.created_at AS created_at, coalesce(v.grounded, false) AS grounded,
       f.id AS finding_id, s.id AS service_id, fb.action AS feedback_action,
       fb.new_kind AS feedback_new_kind, fb.note AS feedback_note, fb.by AS feedback_by
ORDER BY v.created_at DESC
LIMIT 20
"""

LAST_SNAPSHOT_CYPHER = """
MATCH (i:Investigation)
WHERE i.status = 'done' AND coalesce(i.snapshot_json, '') <> '' AND i.id <> $exclude
RETURN i.id AS id, i.goal AS goal, i.started_at AS started_at, i.ended_at AS ended_at,
       coalesce(i.scan_id, '') AS scan_id, i.snapshot_json AS snapshot_json
ORDER BY i.started_at DESC
LIMIT 1
"""


def _merge(records: dict[str, dict[str, Any]], row: dict[str, Any], why: str) -> None:
    key = str(row["id"])
    existing = records.get(key)
    if existing is None:
        records[key] = {
            "lesson_id": key,
            "text": row.get("text"),
            "effect": row.get("effect"),
            "scope_kind": row.get("scope_kind"),
            "scope_value": row.get("scope_value"),
            "strength": float(row.get("strength") or 0.0),
            "uses": int(row.get("uses") or 0),
            "why_retrieved": why,
            "via": row.get("via"),
            "similarity": round(float(row["score"]), 4) if row.get("score") is not None else None,
        }
        return
    if existing["why_retrieved"] != why:
        existing["why_retrieved"] = "both"
    if row.get("score") is not None and existing.get("similarity") is None:
        existing["similarity"] = round(float(row["score"]), 4)
    if row.get("via") and not existing.get("via"):
        existing["via"] = row.get("via")


def _keyword_rank(query_text: str, limit: int) -> tuple[list[dict[str, Any]], str]:
    """Fallback retrieval when vector search is off: token overlap on Lesson.text."""
    outcome = ro_query(ALL_LESSON_CYPHER)
    wanted = set(TOKEN_RE.findall(query_text.lower()))
    scored: list[tuple[float, dict[str, Any]]] = []
    for row in outcome.dicts():
        tokens = set(TOKEN_RE.findall(str(row.get("text") or "").lower()))
        tokens |= set(TOKEN_RE.findall(str(row.get("scope_value") or "").lower()))
        if not tokens:
            continue
        overlap = len(tokens & wanted)
        if overlap:
            scored.append((overlap / len(wanted or {"x"}), row))
    scored.sort(key=lambda pair: (-pair[0], str(pair[1]["id"])))
    rows = []
    for score, row in scored[:limit]:
        enriched = dict(row)
        enriched["score"] = round(score, 4)
        rows.append(enriched)
    return rows, outcome.cypher


def recall(
    subject_ids: Annotated[
        list[str], Field(description="Node ids the question is about: services, findings or packages.")
    ],
    query_text: Annotated[str, Field(description="The question in words, used for similarity search.")],
) -> dict[str, Any]:
    """Retrieve lessons and past verdicts relevant to these subjects, by graph and by similarity."""
    started = time.perf_counter()
    subjects = [s for s in dict.fromkeys(subject_ids) if s][:12]
    cypher: list[str] = []
    records: dict[str, dict[str, Any]] = {}
    vector_used = False
    try:
        if subjects:
            direct = ro_query(DIRECT_LESSON_CYPHER, {"subjects": subjects})
            cypher.append(direct.cypher)
            for row in direct.dicts():
                _merge(records, row, "graph")
            near = ro_query(NEAR_LESSON_CYPHER, {"subjects": subjects})
            cypher.append(near.cypher)
            for row in near.dicts():
                _merge(records, row, "graph")

        vector = embedder().embed(query_text) if query_text.strip() else None
        if vector:
            try:
                outcome = ro_query(VECTOR_LESSON_CYPHER, {"k": 5, "q": vector})
                cypher.append(outcome.cypher)
                for row in outcome.dicts():
                    _merge(records, row, "vector")
                vector_used = True
            except Exception as exc:  # noqa: BLE001 - vector index may be missing
                log.info("vector recall unavailable: %s", exc)
        if not vector_used and query_text.strip():
            rows, cy = _keyword_rank(query_text, 5)
            cypher.append(cy)
            for row in rows:
                _merge(records, row, "vector")

        verdicts: list[dict[str, Any]] = []
        if subjects:
            past = ro_query(PAST_VERDICT_CYPHER, {"subjects": subjects})
            cypher.append(past.cypher)
            verdicts = past.dicts()
    except Exception as exc:  # noqa: BLE001
        return error_envelope("recall failed", detail=str(exc), cypher=cypher)

    lessons = sorted(
        records.values(),
        key=lambda r: (-float(r.get("strength") or 0.0), -int(r.get("uses") or 0), str(r["lesson_id"])),
    )
    overridden = [v for v in verdicts if str(v.get("feedback_action") or "") == "override"]
    retrieval = "graph + vector" if vector_used else "graph + keyword"
    summary = (
        f"{len(lessons)} lesson(s) and {len(verdicts)} past verdict(s) for "
        f"{len(subjects)} subject(s) via {retrieval}"
        + (f"; {len(overridden)} were overridden by an analyst." if overridden else ".")
    )
    if not lessons and not verdicts:
        summary = f"No lessons or past verdicts touch {', '.join(subjects) or 'these subjects'} yet."
    return envelope(
        summary=summary,
        data={
            "lessons": lessons,
            "past_verdicts": verdicts,
            "subjects": subjects,
            "retrieval": retrieval,
            "vector_search": vector_used,
            "embeddings": embedder().status(),
        },
        cypher=cypher,
        # Lesson ids are touched so a Scribe claim may cite a lesson it applied.
        touched_ids=[str(lesson["lesson_id"]) for lesson in lessons]
        + subjects
        + [str(v["finding_id"]) for v in verdicts],
        rows=len(lessons) + len(verdicts),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def _path_signature(entry: str, target: str) -> str:
    return f"{entry}=>{target}"


def diff_since_last(
    scan_id: Annotated[str | None, Field(description="Scan id to diff; defaults to all open findings.")] = None,
    investigation_id: Annotated[
        str | None, Field(description="Exclude this investigation when choosing the baseline.")
    ] = None,
) -> dict[str, Any]:
    """Compare the current open findings and attack paths with the last completed investigation."""
    started = time.perf_counter()
    cypher: list[str] = []
    try:
        baseline = ro_query(LAST_SNAPSHOT_CYPHER, {"exclude": investigation_id or ""})
        cypher.append(baseline.cypher)
        previous = baseline.first()
        proj = load_projection()
        current_paths = enumerate_paths(proj, top_k=0)
        current_findings = sorted(
            fid
            for fid, facts in proj.findings.items()
            if facts.status == "open" and (not scan_id or facts.scan_id == scan_id)
        )
    except Exception as exc:  # noqa: BLE001
        return error_envelope("diff_since_last failed", detail=str(exc), cypher=cypher)

    current_signatures = {
        _path_signature(p.entry, p.target): {
            "path_id": p.id,
            "entry": p.entry,
            "target": p.target,
            "hops": p.hops,
            "score_pct": round(p.breakdown.score * 100, 1),
        }
        for p in current_paths
    }

    if previous is None:
        data = {
            "baseline": None,
            "new_findings": current_findings,
            "resolved_findings": [],
            "unchanged_findings": [],
            "new_paths": list(current_signatures.values()),
            "resolved_paths": [],
            "changed_paths": [],
            "current_total_weight": round(total_weight(current_paths), 4),
        }
        return envelope(
            summary=(
                "No completed investigation to diff against; treating all "
                f"{len(current_findings)} open findings and {len(current_paths)} paths as new."
            ),
            data=data,
            cypher=cypher,
            touched_ids=current_findings[:40],
            rows=len(current_findings),
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )

    try:
        snapshot = json.loads(str(previous.get("snapshot_json") or "{}"))
    except json.JSONDecodeError:
        snapshot = {}
    prior_findings = {str(f) for f in snapshot.get("findings", [])}
    prior_paths = {
        _path_signature(str(p.get("entry")), str(p.get("target"))): p for p in snapshot.get("paths", [])
    }

    new_findings = [f for f in current_findings if f not in prior_findings]
    resolved_findings = sorted(prior_findings - set(current_findings))
    unchanged = [f for f in current_findings if f in prior_findings]

    new_paths = [v for k, v in current_signatures.items() if k not in prior_paths]
    resolved_paths = [v for k, v in prior_paths.items() if k not in current_signatures]
    changed_paths = []
    for key, current in current_signatures.items():
        prior = prior_paths.get(key)
        if prior is None:
            continue
        before = float(prior.get("score_pct") or 0.0)
        if abs(before - float(current["score_pct"])) >= 0.1:
            changed_paths.append({**current, "previous_score_pct": before})

    data = {
        "baseline": {
            "investigation_id": previous.get("id"),
            "goal": previous.get("goal"),
            "ended_at": previous.get("ended_at"),
            "scan_id": previous.get("scan_id"),
            "findings": len(prior_findings),
            "paths": len(prior_paths),
        },
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "unchanged_findings": unchanged[:60],
        "new_paths": new_paths,
        "resolved_paths": resolved_paths,
        "changed_paths": changed_paths,
        "current_total_weight": round(total_weight(current_paths), 4),
        "previous_total_weight": float(snapshot.get("total_weight") or 0.0),
    }
    summary = (
        f"Against {previous.get('id')}: {len(new_paths)} new path(s), {len(resolved_paths)} resolved, "
        f"{len(changed_paths)} changed; {len(new_findings)} new finding(s), "
        f"{len(resolved_findings)} resolved, {len(unchanged)} unchanged."
    )
    return envelope(
        summary=summary,
        data=data,
        cypher=cypher,
        touched_ids=new_findings[:30] + [p["entry"] for p in new_paths] + [p["target"] for p in new_paths],
        rows=len(new_findings) + len(new_paths),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


DESCRIPTIONS = {
    "recall": (
        "Memory retrieval. Returns lessons learned from analyst overrides that apply to these "
        "subjects - found both by graph proximity (lesson APPLIES_TO a node within two hops of a "
        "subject) and by embedding similarity on your question - plus any past verdicts on the same "
        "findings or services and the feedback they received. Each lesson says why_retrieved: graph, "
        "vector or both. Call it before judging anything that has been judged before."
    ),
    "diff_since_last": (
        "Compare the current open findings and attack paths with the snapshot stored by the last "
        "completed investigation: new, resolved, changed. Use it for 'what changed since yesterday' "
        "questions so you report only the delta and can reference earlier decisions."
    ),
}


def register(mcp: Any) -> None:
    mcp.tool(name="recall", description=DESCRIPTIONS["recall"])(recall)
    mcp.tool(name="diff_since_last", description=DESCRIPTIONS["diff_since_last"])(diff_since_last)
