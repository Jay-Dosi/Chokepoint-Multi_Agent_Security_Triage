"""Verdict, action and lesson writes (PRD 8.5)."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.db import ro_query, rw_query
from app.memory.embeddings import embedder

from ..attack import Modifications, enumerate_paths, live_exploits
from ..graph_ops import envelope, error_envelope, load_projection
from ..grounding import check_claims
from . import require_role

log = logging.getLogger("chokepoint.tools.actions")

VERDICT_KINDS = ("FIX_NOW", "SCHEDULE", "ACCEPT", "SUPPRESS")
DOWNGRADED = ("ACCEPT", "SUPPRESS")


class Claim(BaseModel):
    """One sentence of a verdict rationale, with its citations."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Short claim id, for example 'C1'.")
    text: str = Field(description="One short, concrete sentence in plain language.")
    cites: list[str] = Field(default_factory=list, description="Step ids from this investigation.")
    node_ids: list[str] = Field(
        default_factory=list, description="Graph node ids this claim names; each must be touched by a cited step."
    )


NEXT_VERDICT_CYPHER = """
MATCH (:Investigation {id: $iid})-[:PRODUCED]->(v:Verdict)
RETURN count(v) AS c
"""
CREATE_VERDICT_CYPHER = """
MATCH (i:Investigation {id: $iid})
CREATE (v:Verdict {id: $vid, kind: $kind, confidence: $confidence, rationale_json: $rationale,
                   grounded: $grounded, safety_valve: $valve, created_at: $now})
CREATE (i)-[:PRODUCED]->(v)
RETURN v.id AS id
"""
LINK_VERDICT_FINDINGS_CYPHER = """
MATCH (v:Verdict {id: $vid})
UNWIND $ids AS fid
MATCH (f:Finding {id: fid})
MERGE (v)-[:ON]->(f)
RETURN count(f) AS linked
"""
LINK_CITE_CYPHER = """
MATCH (v:Verdict {id: $vid})
MATCH (s:Step {id: $sid})
MERGE (v)-[c:CITES {claim_id: $claim_id}]->(s)
RETURN count(c) AS linked
"""
LINK_EVIDENCE_CYPHER = """
MATCH (v:Verdict {id: $vid})
UNWIND $ids AS pid
MATCH (p:AttackPath {id: pid})
MERGE (v)-[:EVIDENCE]->(p)
RETURN count(p) AS linked
"""
INVESTIGATION_PATHS_CYPHER = """
MATCH (:Investigation {id: $iid})-[:FOUND_PATH]->(p:AttackPath)
RETURN p.id AS id, coalesce(p.findings_json, '[]') AS findings_json, p.entry AS entry,
       p.target AS target, p.score AS score
"""
LESSONS_FOR_SERVICE_CYPHER = """
MATCH (l:Lesson)-[:APPLIES_TO]->(s:Service {id: $sid})
RETURN l.id AS id, l.scope_kind AS scope_kind, l.scope_value AS scope_value, l.effect AS effect
"""
FINDING_SERVICE_CYPHER = """
MATCH (s:Service)-[:HAS_FINDING]->(f:Finding)
WHERE f.id IN $ids
RETURN f.id AS finding_id, s.id AS service_id
"""
VERDICT_LOOKUP_CYPHER = """
MATCH (i:Investigation)-[:PRODUCED]->(v:Verdict {id: $vid})
OPTIONAL MATCH (v)-[:ON]->(f:Finding)
RETURN i.id AS investigation_id, v.kind AS kind, collect(DISTINCT f.id) AS finding_ids
"""
NEXT_ACTION_CYPHER = """
MATCH (:Investigation {id: $iid})-[:PRODUCED]->(:Verdict)-[:RESULTED_IN]->(a:Action)
RETURN count(a) AS c
"""
CREATE_ACTION_CYPHER = """
MATCH (v:Verdict {id: $vid})
CREATE (a:Action {id: $aid, kind: $kind, status: 'proposed', title: $title, body_md: $body,
                  created_at: $now})
CREATE (v)-[:RESULTED_IN]->(a)
RETURN a.id AS id
"""
ROUTE_ACTION_CYPHER = """
MATCH (a:Action {id: $aid})
MATCH (t:Team {id: $tid})
MERGE (a)-[:ROUTED_TO]->(t)
RETURN t.name AS name, t.slack_channel AS slack_channel
"""
NOTIFY_ACTION_CYPHER = """
MATCH (a:Action {id: $aid})
UNWIND $ids AS pid
MATCH (p:Person {id: pid})
MERGE (a)-[:NOTIFY]->(p)
RETURN count(p) AS linked
"""
OWNER_CYPHER = """
MATCH (t:Team)-[:OWNS]->(s:Service {id: $sid})
OPTIONAL MATCH (p:Person)-[:ON_CALL_FOR]->(s)
RETURN t.id AS team_id, t.name AS team_name, t.slack_channel AS slack_channel,
       collect(DISTINCT p.id) AS person_ids, collect(DISTINCT p.name) AS person_names
"""
CREATE_LESSON_CYPHER = """
CREATE (l:Lesson {id: $lid, text: $text, scope_kind: $scope_kind, scope_value: $scope_value,
                  effect: $effect, strength: $strength, uses: 0, created_at: $now})
RETURN l.id AS id
"""
SET_EMBEDDING_CYPHER = "MATCH (l:Lesson {id: $lid}) SET l.embedding = vecf32($vec) RETURN l.id AS id"
LINK_LESSON_CYPHER = """
MATCH (l:Lesson {id: $lid})
UNWIND $ids AS nid
MATCH (n) WHERE n.id = nid
MERGE (l)-[:APPLIES_TO]->(n)
RETURN count(n) AS linked
"""
LINK_TAUGHT_CYPHER = """
MATCH (fb:Feedback {id: $fid})
MATCH (l:Lesson {id: $lid})
MERGE (fb)-[:TAUGHT]->(l)
RETURN count(l) AS linked
"""
NEXT_LESSON_CYPHER = "MATCH (l:Lesson) RETURN count(l) AS c"


def _finding_services(finding_ids: list[str]) -> dict[str, str]:
    if not finding_ids:
        return {}
    outcome = ro_query(FINDING_SERVICE_CYPHER, {"ids": finding_ids})
    return {str(r["finding_id"]): str(r["service_id"]) for r in outcome.dicts()}


def _safety_valve(
    finding_ids: list[str], kind: str, claims: list[Claim]
) -> tuple[str, dict[str, Any]]:
    """Lessons may not downgrade a live exploit that reaches a crown jewel (PRD 10)."""
    if kind not in DOWNGRADED:
        return kind, {"applied": False, "reason": "verdict is not a downgrade"}
    proj = load_projection()
    paths = enumerate_paths(proj, top_k=0)
    on_path_services = {s for p in paths for s in p.services}
    lateral = live_exploits(proj, Modifications(), as_entry=False)
    cited_nodes = {n for claim in claims for n in claim.node_ids}

    blocked: list[dict[str, Any]] = []
    for finding_id in finding_ids:
        facts = proj.findings.get(finding_id)
        if facts is None:
            continue
        service_id = facts.service_id
        if service_id not in on_path_services:
            continue
        if not any(c.finding_id == finding_id for c in lateral.get(service_id, [])):
            continue
        lessons = ro_query(LESSONS_FOR_SERVICE_CYPHER, {"sid": service_id}).dicts()
        covering = [str(row["id"]) for row in lessons if str(row["id"]) in cited_nodes]
        if covering:
            continue
        targets = sorted({p.target for p in paths if service_id in p.services})
        blocked.append(
            {
                "finding_id": finding_id,
                "service_id": service_id,
                "crown_jewels_reached": targets,
                "lessons_scoping_this_service": [str(row["id"]) for row in lessons],
            }
        )
    if not blocked:
        return kind, {"applied": False, "reason": "no live exploit with a crown-jewel path in this group"}
    return "FIX_NOW", {
        "applied": True,
        "reason": (
            "a live exploit in this group reaches a crown jewel and no cited lesson scopes the "
            "affected service, so the verdict was raised to FIX_NOW"
        ),
        "blocked": blocked,
    }


def record_verdict(
    role: Annotated[str, Field(description="Calling agent role; must be 'scribe'.")],
    investigation_id: Annotated[str, Field(description="Current investigation id.")],
    finding_ids: Annotated[list[str], Field(description="Findings this verdict covers.")],
    kind: Annotated[
        Literal["FIX_NOW", "SCHEDULE", "ACCEPT", "SUPPRESS"], Field(description="The decision.")
    ],
    confidence: Annotated[float, Field(ge=0.0, le=1.0, description="Confidence, 0 to 1.")],
    claims: Annotated[list[Claim], Field(description="Every rationale sentence with its citations.")],
) -> dict[str, Any]:
    """Adjudicate a finding group. Runs the grounding check and the lesson safety valve."""
    started = time.perf_counter()
    try:
        require_role(role, "record_verdict")
    except PermissionError as exc:
        return error_envelope("record_verdict refused", detail=str(exc))
    if not finding_ids:
        return error_envelope("record_verdict refused", detail="finding_ids must not be empty")
    if not claims:
        return error_envelope("record_verdict refused", detail="a verdict needs at least one claim")

    cypher: list[str] = []
    try:
        claim_dicts = [c.model_dump() for c in claims]
        report = check_claims(investigation_id, claim_dicts)
        cypher.extend(report.cypher)
        final_kind, valve = _safety_valve(list(finding_ids), kind, list(claims))

        count = ro_query(NEXT_VERDICT_CYPHER, {"iid": investigation_id})
        cypher.append(count.cypher)
        vid = f"{investigation_id}-V{int(count.scalar(0) or 0) + 1}"
        rationale = json.dumps(
            {
                "claims": claim_dicts,
                "grounding": report.as_dict(),
                "safety_valve": valve,
                "requested_kind": kind,
            }
        )
        created = rw_query(
            CREATE_VERDICT_CYPHER,
            {
                "iid": investigation_id,
                "vid": vid,
                "kind": final_kind,
                "confidence": float(confidence),
                "rationale": rationale,
                "grounded": bool(report.grounded),
                "valve": bool(valve.get("applied")),
                "now": datetime.now(timezone.utc).isoformat(),
            },
        )
        cypher.append(created.cypher)
        if created.row_count == 0:
            return error_envelope(
                "record_verdict refused", detail=f"no investigation {investigation_id}", cypher=cypher
            )
        linked = rw_query(LINK_VERDICT_FINDINGS_CYPHER, {"vid": vid, "ids": list(finding_ids)})
        cypher.append(linked.cypher)
        for claim in claims:
            for step_id in dict.fromkeys(claim.cites):
                out = rw_query(LINK_CITE_CYPHER, {"vid": vid, "sid": step_id, "claim_id": claim.id})
                if out.row_count:
                    cypher.append(out.cypher)

        paths = ro_query(INVESTIGATION_PATHS_CYPHER, {"iid": investigation_id})
        cypher.append(paths.cypher)
        evidence: list[str] = []
        wanted = set(finding_ids)
        for row in paths.dicts():
            try:
                path_findings = {str(f) for f in json.loads(str(row.get("findings_json") or "[]"))}
            except json.JSONDecodeError:
                path_findings = set()
            if path_findings & wanted:
                evidence.append(str(row["id"]))
        if evidence:
            out = rw_query(LINK_EVIDENCE_CYPHER, {"vid": vid, "ids": evidence})
            cypher.append(out.cypher)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("record_verdict failed", detail=str(exc), cypher=cypher)

    services = _finding_services(list(finding_ids))
    data = {
        "verdict_id": vid,
        "kind": final_kind,
        "requested_kind": kind,
        "confidence": round(float(confidence), 2),
        "grounded": bool(report.grounded),
        "grounding": report.as_dict(),
        "safety_valve": valve,
        "findings_linked": int(linked.scalar(0) or 0),
        "evidence_path_ids": evidence,
        "services": sorted(set(services.values())),
        "headline": claims[0].text,
    }
    summary = f"Verdict {vid}: {final_kind} on {len(finding_ids)} finding(s), "
    summary += "all claims grounded." if report.grounded else (
        f"{len(report.failures)} claim(s) failed the grounding check: "
        + "; ".join(f["failures"][0] for f in report.failures if f["failures"])[:300]
    )
    if valve.get("applied"):
        summary += " Safety valve raised the verdict to FIX_NOW: lesson considered, not applied."
    return envelope(
        summary=summary,
        data=data,
        cypher=cypher,
        touched_ids=[vid, *finding_ids, *sorted(set(services.values())), *evidence],
        rows=1,
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def propose_action(
    role: Annotated[str, Field(description="Calling agent role; must be 'scribe'.")],
    verdict_id: Annotated[str, Field(description="Verdict this action follows from.")],
    kind: Annotated[
        Literal["ticket", "suppress", "virtual_patch_request"], Field(description="What to propose.")
    ],
    title: Annotated[str, Field(description="One-line title an engineer would accept.")],
    body_md: Annotated[str, Field(description="Markdown body: what, why, fix, blast radius, verification.")],
) -> dict[str, Any]:
    """Propose a human-approved action, routed to the owning team and on-call people via the graph."""
    started = time.perf_counter()
    try:
        require_role(role, "propose_action")
    except PermissionError as exc:
        return error_envelope("propose_action refused", detail=str(exc))

    cypher: list[str] = []
    try:
        lookup = ro_query(VERDICT_LOOKUP_CYPHER, {"vid": verdict_id})
        cypher.append(lookup.cypher)
        row = lookup.first()
        if row is None:
            return error_envelope(
                "propose_action refused", detail=f"no verdict {verdict_id}", cypher=cypher
            )
        investigation_id = str(row["investigation_id"])
        finding_ids = [str(f) for f in (row.get("finding_ids") or [])]
        services = _finding_services(finding_ids)
        primary_service = sorted(set(services.values()))[0] if services else ""
        owner: dict[str, Any] | None = None
        if primary_service:
            owner_outcome = ro_query(OWNER_CYPHER, {"sid": primary_service})
            cypher.append(owner_outcome.cypher)
            owner = owner_outcome.first()

        count = ro_query(NEXT_ACTION_CYPHER, {"iid": investigation_id})
        cypher.append(count.cypher)
        aid = f"{investigation_id}-A{int(count.scalar(0) or 0) + 1}"
        created = rw_query(
            CREATE_ACTION_CYPHER,
            {
                "vid": verdict_id,
                "aid": aid,
                "kind": kind,
                "title": title.strip(),
                "body": body_md,
                "now": datetime.now(timezone.utc).isoformat(),
            },
        )
        cypher.append(created.cypher)
        routed: dict[str, Any] | None = None
        notified = 0
        if owner and owner.get("team_id"):
            route = rw_query(ROUTE_ACTION_CYPHER, {"aid": aid, "tid": str(owner["team_id"])})
            cypher.append(route.cypher)
            routed = route.first()
            person_ids = [str(p) for p in (owner.get("person_ids") or []) if p]
            if person_ids:
                notify = rw_query(NOTIFY_ACTION_CYPHER, {"aid": aid, "ids": person_ids})
                cypher.append(notify.cypher)
                notified = int(notify.scalar(0) or 0)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("propose_action failed", detail=str(exc), cypher=cypher)

    data = {
        "action_id": aid,
        "status": "proposed",
        "kind": kind,
        "title": title.strip(),
        "verdict_id": verdict_id,
        "verdict_kind": row.get("kind"),
        "service_id": primary_service,
        "team": routed["name"] if routed else None,
        "slack_channel": routed["slack_channel"] if routed else None,
        "notified_people": notified,
        "on_call": [str(n) for n in (owner.get("person_names") or [])] if owner else [],
        "finding_ids": finding_ids,
    }
    summary = (
        f"Action {aid} ({kind}) proposed for {verdict_id}, routed to "
        f"{data['team'] or 'no team'} ({data['slack_channel'] or 'no channel'}); "
        f"{notified} person(s) notified. Awaiting human approval."
    )
    return envelope(
        summary=summary,
        data=data,
        cypher=cypher,
        touched_ids=[aid, verdict_id, primary_service, *finding_ids],
        rows=1,
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def record_lesson(
    role: Annotated[str, Field(description="Must be 'backend'; agents may not call this tool.")],
    text: Annotated[str, Field(description="One sentence stating what was learned.")],
    scope_kind: Annotated[
        Literal["cluster", "service", "package", "team", "control"],
        Field(description="What the lesson is scoped to."),
    ],
    scope_value: Annotated[str, Field(description="The scope value, for example 'sandbox-eu'.")],
    effect: Annotated[
        Literal["downgrade", "upgrade", "suppress", "require_check"],
        Field(description="How the lesson should influence future verdicts."),
    ],
    strength: Annotated[float, Field(ge=0.0, le=1.0, description="How strongly it applies.")] = 0.7,
    apply_to_ids: Annotated[
        list[str] | None, Field(description="Node ids the lesson APPLIES_TO.")
    ] = None,
    feedback_id: Annotated[str | None, Field(description="Feedback node that taught it.")] = None,
) -> dict[str, Any]:
    """Store a lesson with its embedding and scope links. Backend only; never offered to agents."""
    started = time.perf_counter()
    try:
        require_role(role, "record_lesson")
    except PermissionError as exc:
        return error_envelope("record_lesson refused", detail=str(exc))

    cypher: list[str] = []
    try:
        count = ro_query(NEXT_LESSON_CYPHER)
        cypher.append(count.cypher)
        lid = f"L-{int(count.scalar(0) or 0) + 1:04d}"
        created = rw_query(
            CREATE_LESSON_CYPHER,
            {
                "lid": lid,
                "text": text.strip(),
                "scope_kind": scope_kind,
                "scope_value": scope_value,
                "effect": effect,
                "strength": float(strength),
                "now": datetime.now(timezone.utc).isoformat(),
            },
        )
        cypher.append(created.cypher)
        vector = embedder().embed(text)
        embedded = False
        if vector:
            try:
                out = rw_query(SET_EMBEDDING_CYPHER, {"lid": lid, "vec": vector})
                cypher.append(out.cypher)
                embedded = True
            except Exception as exc:  # noqa: BLE001 - vector support is optional
                log.info("could not store lesson embedding: %s", exc)
        ids = [i for i in dict.fromkeys(apply_to_ids or []) if i]
        linked = 0
        if ids:
            out = rw_query(LINK_LESSON_CYPHER, {"lid": lid, "ids": ids})
            cypher.append(out.cypher)
            linked = int(out.scalar(0) or 0)
        if feedback_id:
            out = rw_query(LINK_TAUGHT_CYPHER, {"fid": feedback_id, "lid": lid})
            cypher.append(out.cypher)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("record_lesson failed", detail=str(exc), cypher=cypher)

    data = {
        "lesson_id": lid,
        "text": text.strip(),
        "scope_kind": scope_kind,
        "scope_value": scope_value,
        "effect": effect,
        "strength": round(float(strength), 2),
        "applies_to_linked": linked,
        "embedded": embedded,
        "embeddings": embedder().status(),
    }
    return envelope(
        summary=(
            f"Lesson {lid} stored ({scope_kind}={scope_value}, effect {effect}), linked to "
            f"{linked} node(s); embedding {'written' if embedded else 'skipped'}."
        ),
        data=data,
        cypher=cypher,
        touched_ids=[lid, *(apply_to_ids or [])],
        rows=1,
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


DESCRIPTIONS = {
    "record_verdict": (
        "Scribe only. Store the decision for one finding group: FIX_NOW, SCHEDULE, ACCEPT or "
        "SUPPRESS. Every rationale sentence is a claim with step citations and the node ids it "
        "names. The tool runs the grounding check (citations must exist, named nodes must have been "
        "touched by a cited step, every number must appear in a cited step's result) and returns the "
        "failures so you can fix them. A downgrade to ACCEPT or SUPPRESS is raised back to FIX_NOW "
        "if a live exploit in the group reaches a crown jewel and no cited lesson scopes that "
        "service. Finding statuses are not changed until a human approves an action."
    ),
    "propose_action": (
        "Scribe only. Propose a ticket, suppression or virtual-patch request for a verdict. The "
        "owning team, its Slack channel and the on-call people are resolved through the graph, not "
        "guessed. The action is created as 'proposed' and waits for human approval. Write the body "
        "in Markdown: what, why (the attack path in words), the fix, the blast radius, the simulated "
        "risk reduction, and how to verify."
    ),
    "record_lesson": (
        "Backend only - no agent role may call this. Creates a Lesson node with its embedding and "
        "APPLIES_TO links. The backend calls it when an analyst overrides a verdict."
    ),
}


def register(mcp: Any) -> None:
    mcp.tool(name="record_verdict", description=DESCRIPTIONS["record_verdict"])(record_verdict)
    mcp.tool(name="propose_action", description=DESCRIPTIONS["propose_action"])(propose_action)
    mcp.tool(name="record_lesson", description=DESCRIPTIONS["record_lesson"])(record_lesson)
