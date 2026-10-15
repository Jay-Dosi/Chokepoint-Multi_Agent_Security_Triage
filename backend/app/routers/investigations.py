"""Investigation lifecycle: list, start, read and stream."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.db import ro_query
from app.events import event_stream
from app.memory.lessons import feedback_for_verdict
from app.models import (
    ActionModel,
    AttackPathModel,
    ChallengeModel,
    ChokepointFix,
    ClaimModel,
    CreateInvestigationRequest,
    CreateInvestigationResponse,
    DiffSummary,
    HypothesisModel,
    InvestigationDetail,
    InvestigationSummary,
    MemoryBrief,
    MemoryHit,
    SimulationResult,
    SimulationSide,
    StepRecord,
    VerdictModel,
)
from app.orchestrator.runner import create_investigation, run_investigation

router = APIRouter(tags=["investigations"])
log = logging.getLogger("chokepoint.investigations")

LIST_CYPHER = """
MATCH (i:Investigation)
OPTIONAL MATCH (i)-[:HAS_STEP]->(s:Step)
OPTIONAL MATCH (i)-[:PRODUCED]->(v:Verdict)
RETURN i.id AS id, i.goal AS goal, i.mode AS mode, i.status AS status,
       i.started_at AS started_at, coalesce(i.ended_at, '') AS ended_at,
       coalesce(i.scan_id, '') AS scan_id, coalesce(i.model, '') AS model,
       coalesce(i.preset, '') AS preset, coalesce(i.duration_ms, 0.0) AS duration_ms,
       coalesce(i.error, '') AS error,
       count(DISTINCT s) AS steps, collect(v.kind) AS verdict_kinds
ORDER BY i.started_at DESC
LIMIT 50
"""
DETAIL_CYPHER = """
MATCH (i:Investigation {id: $iid})
OPTIONAL MATCH (i)-[:HAS_STEP]->(s:Step)
RETURN i.id AS id, i.goal AS goal, i.mode AS mode, i.status AS status,
       i.started_at AS started_at, coalesce(i.ended_at, '') AS ended_at,
       coalesce(i.scan_id, '') AS scan_id, coalesce(i.model, '') AS model,
       coalesce(i.preset, '') AS preset, coalesce(i.duration_ms, 0.0) AS duration_ms,
       coalesce(i.error, '') AS error,
       coalesce(i.memory_json, '{}') AS memory_json,
       coalesce(i.chokepoints_json, '[]') AS chokepoints_json,
       coalesce(i.simulation_json, '{}') AS simulation_json,
       count(DISTINCT s) AS steps
"""
STEPS_CYPHER = """
MATCH (:Investigation {id: $iid})-[:HAS_STEP]->(s:Step)
RETURN s.id AS id, s.n AS n, s.agent AS agent, s.tool AS tool,
       coalesce(s.args_json, '{}') AS args_json, coalesce(s.cypher_json, '[]') AS cypher_json,
       coalesce(s.rows, 0) AS rows, coalesce(s.latency_ms, 0.0) AS latency_ms,
       coalesce(s.summary, '') AS summary, coalesce(s.touched_ids_json, '[]') AS touched_ids_json,
       coalesce(s.engine, 'falkordb') AS engine, coalesce(s.ok, true) AS ok,
       coalesce(s.result_json, '{}') AS result_json
ORDER BY s.n
"""
PATHS_CYPHER = """
MATCH (:Investigation {id: $iid})-[:FOUND_PATH]->(p:AttackPath)
RETURN p.id AS id, p.score AS score, p.hops AS hops, p.entry AS entry, p.target AS target,
       coalesce(p.nodes_json, '[]') AS nodes_json, coalesce(p.edges_json, '[]') AS edges_json,
       coalesce(p.weight_json, '{}') AS weight_json,
       coalesce(p.findings_json, '[]') AS findings_json,
       coalesce(p.exploits_json, '[]') AS exploits_json,
       coalesce(p.entry_ingress, '') AS entry_ingress,
       coalesce(p.entry_authn, '') AS entry_authn,
       coalesce(p.target_name, '') AS target_name,
       coalesce(p.target_classification, '') AS target_classification,
       coalesce(p.target_records, 0) AS target_records,
       coalesce(p.controls_json, '[]') AS controls_json
ORDER BY p.score DESC
"""
HYPOTHESES_CYPHER = """
MATCH (:Investigation {id: $iid})-[:HAS_HYPOTHESIS]->(h:Hypothesis)
OPTIONAL MATCH (h)-[:ABOUT]->(n)
OPTIONAL MATCH (h)-[:BASED_ON]->(s:Step)
RETURN h.id AS id, h.agent AS agent, h.claim AS claim, h.status AS status,
       coalesce(h.confidence, 0.0) AS confidence,
       collect(DISTINCT n.id) AS about_ids, collect(DISTINCT s.id) AS based_on_step_ids
ORDER BY h.id
"""
CHALLENGES_CYPHER = """
MATCH (:Investigation {id: $iid})-[:HAS_CHALLENGE]->(c:Challenge)
OPTIONAL MATCH (c)-[:TARGETS]->(h:Hypothesis)
OPTIONAL MATCH (c)-[:BASED_ON]->(s:Step)
RETURN c.id AS id, c.kind AS kind, c.claim AS claim, c.outcome AS outcome,
       coalesce(h.id, '') AS hypothesis_id, coalesce(h.claim, '') AS hypothesis_claim,
       collect(DISTINCT s.id) AS based_on_step_ids
ORDER BY c.id
"""
VERDICTS_CYPHER = """
MATCH (:Investigation {id: $iid})-[:PRODUCED]->(v:Verdict)
OPTIONAL MATCH (v)-[:ON]->(f:Finding)
OPTIONAL MATCH (v)-[:EVIDENCE]->(p:AttackPath)
OPTIONAL MATCH (v)-[:ON]->(:Finding)<-[:HAS_FINDING]-(svc:Service)
RETURN v.id AS id, v.kind AS kind, coalesce(v.confidence, 0.0) AS confidence,
       coalesce(v.grounded, false) AS grounded, coalesce(v.safety_valve, false) AS safety_valve,
       coalesce(v.created_at, '') AS created_at, coalesce(v.rationale_json, '{}') AS rationale_json,
       collect(DISTINCT f.id) AS finding_ids, collect(DISTINCT p.id) AS evidence_path_ids,
       collect(DISTINCT svc.id) AS services
ORDER BY v.id
"""
ACTIONS_CYPHER = """
MATCH (:Investigation {id: $iid})-[:PRODUCED]->(v:Verdict)-[:RESULTED_IN]->(a:Action)
OPTIONAL MATCH (a)-[:ROUTED_TO]->(t:Team)
OPTIONAL MATCH (a)-[:NOTIFY]->(p:Person)
OPTIONAL MATCH (v)-[:ON]->(f:Finding)
RETURN a.id AS id, a.kind AS kind, a.status AS status, a.title AS title,
       coalesce(a.body_md, '') AS body_md, coalesce(a.created_at, '') AS created_at,
       coalesce(a.outbox_path, '') AS outbox_path, coalesce(a.delivery_json, '[]') AS delivery_json,
       v.id AS verdict_id, v.kind AS verdict_kind,
       coalesce(t.name, '') AS team, coalesce(t.slack_channel, '') AS slack_channel,
       collect(DISTINCT p.name) AS on_call, collect(DISTINCT f.id) AS finding_ids
ORDER BY a.id
"""
LESSONS_USED_CYPHER = """
MATCH (:Investigation {id: $iid})-[u:USED_LESSON]->(l:Lesson)
RETURN l.id AS lesson_id, l.text AS text, l.effect AS effect, l.scope_kind AS scope_kind,
       l.scope_value AS scope_value, coalesce(l.strength, 0.0) AS strength,
       coalesce(l.uses, 0) AS uses, coalesce(u.influence, '') AS influence
ORDER BY l.id
"""
MESSAGES_CYPHER = """
MATCH (:Investigation {id: $iid})-[:HAS_EVENT]->(e:Event)
WHERE e.type = 'agent_message'
RETURN e.n AS n, e.payload_json AS payload_json
ORDER BY e.n
LIMIT 200
"""
PHASE_CYPHER = """
MATCH (:Investigation {id: $iid})-[:HAS_EVENT]->(e:Event)
WHERE e.type = 'phase'
RETURN e.n AS n, e.payload_json AS payload_json
ORDER BY e.n DESC
LIMIT 1
"""
STATUS_CYPHER = "MATCH (i:Investigation {id: $iid}) RETURN i.status AS status"


def _json(raw: Any, default: Any) -> Any:
    try:
        return json.loads(str(raw))
    except (json.JSONDecodeError, TypeError):
        return default


def _summary_from(row: dict[str, Any]) -> InvestigationSummary:
    kinds: dict[str, int] = {}
    for kind in row.get("verdict_kinds") or []:
        if kind:
            kinds[str(kind)] = kinds.get(str(kind), 0) + 1
    return InvestigationSummary(
        id=str(row["id"]),
        goal=str(row.get("goal") or ""),
        mode=str(row.get("mode") or "live"),
        status=str(row.get("status") or "running"),  # type: ignore[arg-type]
        started_at=str(row.get("started_at") or ""),
        ended_at=str(row.get("ended_at") or ""),
        scan_id=str(row.get("scan_id") or ""),
        model=str(row.get("model") or ""),
        preset=str(row.get("preset") or ""),
        steps=int(row.get("steps") or 0),
        verdict_kinds=kinds,
        duration_ms=float(row.get("duration_ms") or 0.0),
        error=str(row.get("error") or ""),
    )


def _path_model(row: dict[str, Any]) -> AttackPathModel:
    nodes = _json(row.get("nodes_json"), [])
    edges = _json(row.get("edges_json"), [])
    weights = _json(row.get("weight_json"), {})
    score = float(row.get("score") or 0.0)
    return AttackPathModel(
        id=str(row["id"]),
        score=score,
        score_pct=round(score * 100, 1),
        hops=int(row.get("hops") or 0),
        entry=str(row.get("entry") or ""),
        target=str(row.get("target") or ""),
        entry_ingress=str(row.get("entry_ingress") or ""),
        entry_authn=str(row.get("entry_authn") or ""),
        target_name=str(row.get("target_name") or ""),
        target_classification=str(row.get("target_classification") or ""),
        target_records=int(row.get("target_records") or 0),
        components=weights if isinstance(weights, dict) else {},
        nodes=[n for n in nodes if isinstance(n, dict)],
        edges=[e for e in edges if isinstance(e, dict)],
        live_exploits=[e for e in _json(row.get("exploits_json"), []) if isinstance(e, dict)],
        mitigating_controls=[str(c) for c in _json(row.get("controls_json"), [])],
    )


def _verdict_model(row: dict[str, Any]) -> VerdictModel:
    rationale = _json(row.get("rationale_json"), {})
    claim_rows = (rationale.get("claims") if isinstance(rationale, dict) else []) or []
    grounding = (rationale.get("grounding") if isinstance(rationale, dict) else {}) or {}
    valve = (rationale.get("safety_valve") if isinstance(rationale, dict) else {}) or {}
    by_id = {
        str(c.get("claim_id")): c
        for c in (grounding.get("claims") or [])
        if isinstance(c, dict)
    }
    claims = []
    for claim in claim_rows:
        if not isinstance(claim, dict):
            continue
        report = by_id.get(str(claim.get("id")), {})
        claims.append(
            ClaimModel(
                id=str(claim.get("id") or ""),
                text=str(claim.get("text") or ""),
                cites=[str(c) for c in claim.get("cites") or []],
                node_ids=[str(n) for n in claim.get("node_ids") or []],
                grounded=bool(report.get("grounded", True)),
                failures=[str(f) for f in report.get("failures") or []],
            )
        )
    requested = str((rationale or {}).get("requested_kind") or "")
    return VerdictModel(
        id=str(row["id"]),
        kind=str(row.get("kind") or "SCHEDULE"),  # type: ignore[arg-type]
        requested_kind=requested if requested in ("FIX_NOW", "SCHEDULE", "ACCEPT", "SUPPRESS") else None,
        confidence=float(row.get("confidence") or 0.0),
        grounded=bool(row.get("grounded")),
        safety_valve=bool(row.get("safety_valve")),
        safety_valve_reason=str(valve.get("reason") or ""),
        created_at=str(row.get("created_at") or ""),
        headline=claims[0].text if claims else "",
        finding_ids=[str(f) for f in row.get("finding_ids") or [] if f],
        services=[str(s) for s in row.get("services") or [] if s],
        claims=claims,
        evidence_path_ids=[str(p) for p in row.get("evidence_path_ids") or [] if p],
        feedback=feedback_for_verdict(str(row["id"])),
    )


def _detail(investigation_id: str) -> InvestigationDetail:
    head = ro_query(DETAIL_CYPHER, {"iid": investigation_id}).first()
    if head is None:
        raise KeyError(investigation_id)
    kinds = ro_query(
        "MATCH (:Investigation {id: $iid})-[:PRODUCED]->(v:Verdict) RETURN collect(v.kind) AS kinds",
        {"iid": investigation_id},
    ).scalar([]) or []
    summary = _summary_from({**head, "verdict_kinds": kinds})

    steps = [
        StepRecord(
            id=str(row["id"]),
            n=int(row.get("n") or 0),
            agent=str(row.get("agent") or "scout"),  # type: ignore[arg-type]
            tool=str(row.get("tool") or ""),
            args=_json(row.get("args_json"), {}),
            cypher=[str(c) for c in _json(row.get("cypher_json"), [])],
            rows=int(row.get("rows") or 0),
            latency_ms=float(row.get("latency_ms") or 0.0),
            summary=str(row.get("summary") or ""),
            touched_ids=[str(t) for t in _json(row.get("touched_ids_json"), [])],
            engine=str(row.get("engine") or "falkordb"),
            ok=bool(row.get("ok")),
            result=_json(row.get("result_json"), {}),
        )
        for row in ro_query(STEPS_CYPHER, {"iid": investigation_id}).dicts()
    ]
    paths = [_path_model(row) for row in ro_query(PATHS_CYPHER, {"iid": investigation_id}).dicts()]
    hypotheses = [
        HypothesisModel(
            id=str(row["id"]),
            agent=str(row.get("agent") or "scout"),
            claim=str(row.get("claim") or ""),
            status=str(row.get("status") or "open"),  # type: ignore[arg-type]
            confidence=float(row.get("confidence") or 0.0),
            about_ids=[str(a) for a in row.get("about_ids") or [] if a],
            based_on_step_ids=[str(s) for s in row.get("based_on_step_ids") or [] if s],
        )
        for row in ro_query(HYPOTHESES_CYPHER, {"iid": investigation_id}).dicts()
    ]
    challenges = [
        ChallengeModel(
            id=str(row["id"]),
            kind=str(row.get("kind") or ""),
            claim=str(row.get("claim") or ""),
            outcome=str(row.get("outcome") or "rejected"),  # type: ignore[arg-type]
            hypothesis_id=str(row.get("hypothesis_id") or ""),
            hypothesis_claim=str(row.get("hypothesis_claim") or ""),
            based_on_step_ids=[str(s) for s in row.get("based_on_step_ids") or [] if s],
        )
        for row in ro_query(CHALLENGES_CYPHER, {"iid": investigation_id}).dicts()
    ]
    verdicts = [_verdict_model(row) for row in ro_query(VERDICTS_CYPHER, {"iid": investigation_id}).dicts()]
    actions = [
        ActionModel(
            id=str(row["id"]),
            kind=str(row.get("kind") or "ticket"),  # type: ignore[arg-type]
            status=str(row.get("status") or "proposed"),  # type: ignore[arg-type]
            title=str(row.get("title") or ""),
            body_md=str(row.get("body_md") or ""),
            created_at=str(row.get("created_at") or ""),
            verdict_id=str(row.get("verdict_id") or ""),
            verdict_kind=str(row.get("verdict_kind") or ""),
            team=str(row.get("team") or ""),
            slack_channel=str(row.get("slack_channel") or ""),
            on_call=[str(p) for p in row.get("on_call") or [] if p],
            finding_ids=[str(f) for f in row.get("finding_ids") or [] if f],
            outbox_path=str(row.get("outbox_path") or ""),
            delivery=[str(d) for d in _json(row.get("delivery_json"), [])],
        )
        for row in ro_query(ACTIONS_CYPHER, {"iid": investigation_id}).dicts()
    ]
    lessons_used = [
        MemoryHit(
            lesson_id=str(row["lesson_id"]),
            text=str(row.get("text") or ""),
            effect=str(row.get("effect") or ""),
            scope_kind=str(row.get("scope_kind") or ""),
            scope_value=str(row.get("scope_value") or ""),
            strength=float(row.get("strength") or 0.0),
            uses=int(row.get("uses") or 0),
            why_retrieved="graph",
        )
        for row in ro_query(LESSONS_USED_CYPHER, {"iid": investigation_id}).dicts()
    ]

    memory_raw = _json(head.get("memory_json"), {})
    diff_raw = (memory_raw.get("diff") if isinstance(memory_raw, dict) else {}) or {}
    brief = MemoryBrief(
        subjects=[str(s) for s in (memory_raw.get("subjects") or [])],
        retrieval=str(memory_raw.get("retrieval") or "graph + keyword"),
        vector_search=bool(memory_raw.get("vector_search")),
        lessons=[
            MemoryHit(**{k: v for k, v in lesson.items() if k in MemoryHit.model_fields})
            for lesson in (memory_raw.get("lessons") or [])
            if isinstance(lesson, dict)
        ],
        past_verdicts=[v for v in (memory_raw.get("past_verdicts") or []) if isinstance(v, dict)],
        diff=DiffSummary(**{k: v for k, v in diff_raw.items() if k in DiffSummary.model_fields}),
        note=str(memory_raw.get("note") or ""),
    )

    chokepoints = [
        ChokepointFix(**{k: v for k, v in fix.items() if k in ChokepointFix.model_fields})
        for fix in _json(head.get("chokepoints_json"), [])
        if isinstance(fix, dict)
    ]
    simulation_raw = _json(head.get("simulation_json"), {})
    simulation: SimulationResult | None = None
    if isinstance(simulation_raw, dict) and simulation_raw.get("before"):
        delta = simulation_raw.get("delta") or {}
        simulation = SimulationResult(
            before=SimulationSide(
                **{
                    k: v
                    for k, v in (simulation_raw.get("before") or {}).items()
                    if k in SimulationSide.model_fields
                }
            ),
            after=SimulationSide(
                **{
                    k: v
                    for k, v in (simulation_raw.get("after") or {}).items()
                    if k in SimulationSide.model_fields
                }
            ),
            paths_removed=int(delta.get("paths_removed") or 0),
            weight_removed=float(delta.get("weight_removed") or 0.0),
            risk_removed_pct=float(delta.get("risk_removed_pct") or 0.0),
            crown_jewels_cut=[str(c) for c in delta.get("crown_jewels_cut") or []],
            fixes_applied=[f for f in simulation_raw.get("fixes_applied") or [] if isinstance(f, dict)],
        )

    messages: list[dict[str, str]] = []
    for row in ro_query(MESSAGES_CYPHER, {"iid": investigation_id}).dicts():
        payload = _json(row.get("payload_json"), {})
        if isinstance(payload, dict) and payload.get("text"):
            messages.append({"agent": str(payload.get("agent") or ""), "text": str(payload["text"])})

    phase_row = ro_query(PHASE_CYPHER, {"iid": investigation_id}).first()
    phase = None
    if phase_row:
        payload = _json(phase_row.get("payload_json"), {})
        if isinstance(payload, dict):
            phase = str(payload.get("phase") or "") or None

    baseline_weight = 0.0
    for fix in chokepoints:
        if fix.cumulative_risk_removed_pct > 0 and fix.risk_removed > 0:
            baseline_weight = round(fix.risk_removed / (fix.cumulative_risk_removed_pct / 100.0), 4)
            break

    return InvestigationDetail(
        summary=summary,
        phase=phase,  # type: ignore[arg-type]
        steps=steps,
        paths=paths,
        hypotheses=hypotheses,
        challenges=challenges,
        verdicts=verdicts,
        actions=actions,
        memory_brief=brief,
        lessons_used=lessons_used,
        chokepoints=chokepoints,
        chokepoint_baseline_weight=baseline_weight,
        simulation=simulation,
        agent_messages=messages,
    )


@router.get("/investigations", response_model=list[InvestigationSummary])
async def list_investigations() -> list[InvestigationSummary]:
    rows = await asyncio.to_thread(lambda: ro_query(LIST_CYPHER).dicts())
    return [_summary_from(row) for row in rows]


@router.post("/investigations", response_model=CreateInvestigationResponse, status_code=201)
async def start_investigation(request: CreateInvestigationRequest) -> CreateInvestigationResponse:
    created = await asyncio.to_thread(create_investigation, request.goal, request.preset)
    task = asyncio.create_task(run_investigation(created["id"], request.goal, request.preset))
    _BACKGROUND.add(task)
    task.add_done_callback(_BACKGROUND.discard)
    return CreateInvestigationResponse(
        id=created["id"],
        status="running",
        mode=created["mode"],
    )


@router.get("/investigations/{investigation_id}", response_model=InvestigationDetail)
async def get_investigation(investigation_id: str) -> InvestigationDetail:
    try:
        return await asyncio.to_thread(_detail, investigation_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"no investigation {investigation_id}") from exc


@router.get("/investigations/{investigation_id}/stream")
async def stream(investigation_id: str) -> StreamingResponse:
    status = await asyncio.to_thread(
        lambda: str(ro_query(STATUS_CYPHER, {"iid": investigation_id}).scalar("") or "")
    )
    if not status:
        raise HTTPException(status_code=404, detail=f"no investigation {investigation_id}")
    return StreamingResponse(
        event_stream(investigation_id, is_finished=status in ("done", "failed")),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


_BACKGROUND: set[asyncio.Task[None]] = set()
