"""Blackboard tools (PRD 8.4).

Agents never read each other's text. They post to the graph and read the graph
back, which is what makes the graph the shared context.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import Field

from app.db import ro_query, rw_query

from ..graph_ops import envelope, error_envelope
from . import require_role

CHALLENGE_KINDS = (
    "control_present",
    "edge_dead",
    "service_inactive",
    "auth_required",
    "unreachable_code",
    "prior_lesson",
)

NEXT_HYPOTHESIS_CYPHER = """
MATCH (:Investigation {id: $iid})-[:HAS_HYPOTHESIS]->(h:Hypothesis)
RETURN count(h) AS c
"""
NEXT_CHALLENGE_CYPHER = """
MATCH (:Investigation {id: $iid})-[:HAS_CHALLENGE]->(c:Challenge)
RETURN count(c) AS c
"""
CREATE_HYPOTHESIS_CYPHER = """
MATCH (i:Investigation {id: $iid})
CREATE (h:Hypothesis {id: $hid, agent: $agent, claim: $claim, status: 'open',
                      confidence: $confidence, created_at: $now})
CREATE (i)-[:HAS_HYPOTHESIS]->(h)
RETURN h.id AS id
"""
LINK_ABOUT_CYPHER = """
MATCH (h:Hypothesis {id: $hid})
UNWIND $ids AS nid
MATCH (n) WHERE n.id = nid
MERGE (h)-[:ABOUT]->(n)
RETURN count(n) AS linked
"""
LINK_BASED_ON_CYPHER = """
MATCH (x {id: $xid})
UNWIND $ids AS sid
MATCH (s:Step {id: sid})
MERGE (x)-[:BASED_ON]->(s)
RETURN count(s) AS linked
"""
CREATE_CHALLENGE_CYPHER = """
MATCH (i:Investigation {id: $iid})
MATCH (h:Hypothesis {id: $hid})
CREATE (c:Challenge {id: $cid, agent: 'skeptic', kind: $kind, claim: $claim,
                     outcome: $outcome, created_at: $now})
CREATE (i)-[:HAS_CHALLENGE]->(c)
CREATE (c)-[:TARGETS]->(h)
SET h.status = $new_status
RETURN c.id AS id, h.status AS hypothesis_status
"""
STEP_EXISTS_CYPHER = """
MATCH (:Investigation {id: $iid})-[:HAS_STEP]->(s:Step)
WHERE s.id IN $ids
RETURN collect(s.id) AS found
"""
HYPOTHESIS_LIST_CYPHER = """
MATCH (:Investigation {id: $iid})-[:HAS_HYPOTHESIS]->(h:Hypothesis)
OPTIONAL MATCH (h)-[:ABOUT]->(n)
OPTIONAL MATCH (h)-[:BASED_ON]->(s:Step)
RETURN h.id AS id, h.agent AS agent, h.claim AS claim, h.status AS status,
       h.confidence AS confidence, collect(DISTINCT n.id) AS about_ids,
       collect(DISTINCT s.id) AS based_on_step_ids
ORDER BY h.id
"""
CHALLENGE_LIST_CYPHER = """
MATCH (:Investigation {id: $iid})-[:HAS_CHALLENGE]->(c:Challenge)
OPTIONAL MATCH (c)-[:TARGETS]->(h:Hypothesis)
OPTIONAL MATCH (c)-[:BASED_ON]->(s:Step)
RETURN c.id AS id, c.kind AS kind, c.claim AS claim, c.outcome AS outcome,
       h.id AS hypothesis_id, h.claim AS hypothesis_claim,
       collect(DISTINCT s.id) AS based_on_step_ids
ORDER BY c.id
"""
PATH_LIST_CYPHER = """
MATCH (:Investigation {id: $iid})-[:FOUND_PATH]->(p:AttackPath)
RETURN p.id AS id, p.score AS score, p.hops AS hops, p.entry AS entry, p.target AS target,
       coalesce(p.nodes_json, '[]') AS nodes_json, coalesce(p.weight_json, '{}') AS weight_json
ORDER BY p.score DESC
LIMIT 12
"""
STEP_LIST_CYPHER = """
MATCH (:Investigation {id: $iid})-[:HAS_STEP]->(s:Step)
RETURN s.id AS id, s.n AS n, s.agent AS agent, s.tool AS tool, s.summary AS summary,
       coalesce(s.rows, 0) AS rows, coalesce(s.engine, '') AS engine,
       coalesce(s.touched_ids_json, '[]') AS touched_ids_json,
       coalesce(s.ok, true) AS ok
ORDER BY s.n
LIMIT 80
"""
VERDICT_LIST_CYPHER = """
MATCH (:Investigation {id: $iid})-[:PRODUCED]->(v:Verdict)
OPTIONAL MATCH (v)-[:ON]->(f:Finding)
RETURN v.id AS id, v.kind AS kind, v.confidence AS confidence,
       coalesce(v.grounded, false) AS grounded, collect(DISTINCT f.id) AS finding_ids
ORDER BY v.id
"""


def _known_steps(investigation_id: str, step_ids: list[str]) -> list[str]:
    if not step_ids:
        return []
    outcome = ro_query(STEP_EXISTS_CYPHER, {"iid": investigation_id, "ids": step_ids})
    found = outcome.scalar([]) or []
    return [str(s) for s in found]


def post_hypothesis(
    role: Annotated[str, Field(description="Calling agent role; must be 'scout'.")],
    investigation_id: Annotated[str, Field(description="Current investigation id.")],
    claim: Annotated[str, Field(description="One falsifiable sentence.")],
    about_ids: Annotated[list[str], Field(description="Node ids the claim is about.")],
    based_on_step_ids: Annotated[
        list[str], Field(description="Step ids whose results support the claim.")
    ],
    confidence: Annotated[float, Field(ge=0.0, le=1.0, description="Your confidence, 0 to 1.")],
) -> dict[str, Any]:
    """Write a falsifiable claim to the blackboard so the Skeptic can attack it."""
    started = time.perf_counter()
    try:
        require_role(role, "post_hypothesis")
    except PermissionError as exc:
        return error_envelope("post_hypothesis refused", detail=str(exc))
    if not claim.strip():
        return error_envelope("post_hypothesis refused", detail="claim must not be empty")

    cypher: list[str] = []
    try:
        count = ro_query(NEXT_HYPOTHESIS_CYPHER, {"iid": investigation_id})
        cypher.append(count.cypher)
        index = int(count.scalar(0) or 0) + 1
        hid = f"{investigation_id}-H{index}"
        created = rw_query(
            CREATE_HYPOTHESIS_CYPHER,
            {
                "iid": investigation_id,
                "hid": hid,
                "agent": "scout",
                "claim": claim.strip(),
                "confidence": float(confidence),
                "now": datetime.now(timezone.utc).isoformat(),
            },
        )
        cypher.append(created.cypher)
        if created.row_count == 0:
            return error_envelope(
                "post_hypothesis refused", detail=f"no investigation {investigation_id}", cypher=cypher
            )
        about = [a for a in dict.fromkeys(about_ids) if a][:20]
        linked_about = 0
        if about:
            out = rw_query(LINK_ABOUT_CYPHER, {"hid": hid, "ids": about})
            cypher.append(out.cypher)
            linked_about = int(out.scalar(0) or 0)
        known = _known_steps(investigation_id, [s for s in dict.fromkeys(based_on_step_ids) if s])
        if known:
            out = rw_query(LINK_BASED_ON_CYPHER, {"xid": hid, "ids": known})
            cypher.append(out.cypher)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("post_hypothesis failed", detail=str(exc), cypher=cypher)

    unknown = [s for s in based_on_step_ids if s not in known]
    data = {
        "hypothesis_id": hid,
        "status": "open",
        "about_ids_linked": linked_about,
        "based_on_step_ids": known,
        "ignored_step_ids": unknown,
        "claim": claim.strip(),
        "confidence": round(float(confidence), 2),
    }
    summary = f"Hypothesis {hid} posted (confidence {round(float(confidence), 2)}), citing {len(known)} step(s)."
    if unknown:
        summary += f" {len(unknown)} cited step id(s) did not exist and were dropped."
    return envelope(
        summary=summary,
        data=data,
        cypher=cypher,
        touched_ids=[hid, *about],
        rows=1,
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def post_challenge(
    role: Annotated[str, Field(description="Calling agent role; must be 'skeptic'.")],
    investigation_id: Annotated[str, Field(description="Current investigation id.")],
    hypothesis_id: Annotated[str, Field(description="Hypothesis this challenge targets.")],
    kind: Annotated[
        Literal[
            "control_present",
            "edge_dead",
            "service_inactive",
            "auth_required",
            "unreachable_code",
            "prior_lesson",
        ],
        Field(description="Which falsification check you ran."),
    ],
    claim: Annotated[str, Field(description="One sentence stating the flaw you tested for.")],
    based_on_step_ids: Annotated[list[str], Field(description="Step ids that support the outcome.")],
    outcome: Annotated[
        Literal["upheld", "rejected"],
        Field(description="'upheld' only when a tool result supports the challenge."),
    ],
) -> dict[str, Any]:
    """Record a falsification attempt against a hypothesis, upheld or rejected."""
    started = time.perf_counter()
    try:
        require_role(role, "post_challenge")
    except PermissionError as exc:
        return error_envelope("post_challenge refused", detail=str(exc))

    cypher: list[str] = []
    try:
        known = _known_steps(investigation_id, [s for s in dict.fromkeys(based_on_step_ids) if s])
        if outcome == "upheld" and not known:
            return error_envelope(
                "post_challenge refused",
                detail="an upheld challenge must cite at least one step from this investigation",
            )
        count = ro_query(NEXT_CHALLENGE_CYPHER, {"iid": investigation_id})
        cypher.append(count.cypher)
        index = int(count.scalar(0) or 0) + 1
        cid = f"{investigation_id}-X{index}"
        created = rw_query(
            CREATE_CHALLENGE_CYPHER,
            {
                "iid": investigation_id,
                "hid": hypothesis_id,
                "cid": cid,
                "kind": kind,
                "claim": claim.strip(),
                "outcome": outcome,
                "new_status": "falsified" if outcome == "upheld" else "supported",
                "now": datetime.now(timezone.utc).isoformat(),
            },
        )
        cypher.append(created.cypher)
        if created.row_count == 0:
            return error_envelope(
                "post_challenge refused",
                detail=f"no hypothesis {hypothesis_id} in investigation {investigation_id}",
                cypher=cypher,
            )
        if known:
            out = rw_query(LINK_BASED_ON_CYPHER, {"xid": cid, "ids": known})
            cypher.append(out.cypher)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("post_challenge failed", detail=str(exc), cypher=cypher)

    row = created.first() or {}
    data = {
        "challenge_id": cid,
        "hypothesis_id": hypothesis_id,
        "hypothesis_status": row.get("hypothesis_status"),
        "kind": kind,
        "outcome": outcome,
        "based_on_step_ids": known,
    }
    summary = (
        f"Challenge {cid} ({kind}) {outcome} against {hypothesis_id}; "
        f"hypothesis is now '{row.get('hypothesis_status')}'."
    )
    return envelope(
        summary=summary,
        data=data,
        cypher=cypher,
        touched_ids=[cid, hypothesis_id],
        rows=1,
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def list_blackboard(
    investigation_id: Annotated[str, Field(description="Investigation whose blackboard to read.")],
) -> dict[str, Any]:
    """Read the shared state: steps so far, attack paths, hypotheses, challenges and verdicts."""
    started = time.perf_counter()
    cypher: list[str] = []
    try:
        hypotheses = ro_query(HYPOTHESIS_LIST_CYPHER, {"iid": investigation_id})
        cypher.append(hypotheses.cypher)
        challenges = ro_query(CHALLENGE_LIST_CYPHER, {"iid": investigation_id})
        cypher.append(challenges.cypher)
        paths = ro_query(PATH_LIST_CYPHER, {"iid": investigation_id})
        cypher.append(paths.cypher)
        steps = ro_query(STEP_LIST_CYPHER, {"iid": investigation_id})
        cypher.append(steps.cypher)
        verdicts = ro_query(VERDICT_LIST_CYPHER, {"iid": investigation_id})
        cypher.append(verdicts.cypher)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("list_blackboard failed", detail=str(exc), cypher=cypher)

    path_rows = []
    for row in paths.dicts():
        try:
            nodes = json.loads(str(row.get("nodes_json") or "[]"))
        except json.JSONDecodeError:
            nodes = []
        try:
            weights = json.loads(str(row.get("weight_json") or "{}"))
        except json.JSONDecodeError:
            weights = {}
        path_rows.append(
            {
                "id": row.get("id"),
                "score": float(row.get("score") or 0.0),
                "score_pct": round(float(row.get("score") or 0.0) * 100, 1),
                "hops": int(row.get("hops") or 0),
                "entry": row.get("entry"),
                "target": row.get("target"),
                "node_ids": [str(n.get("id", n)) if isinstance(n, dict) else str(n) for n in nodes],
                "components": weights,
            }
        )

    step_rows = []
    for row in steps.dicts():
        try:
            touched = json.loads(str(row.get("touched_ids_json") or "[]"))
        except json.JSONDecodeError:
            touched = []
        step_rows.append(
            {
                "id": row.get("id"),
                "n": int(row.get("n") or 0),
                "agent": row.get("agent"),
                "tool": row.get("tool"),
                "summary": str(row.get("summary") or "")[:140],
                "rows": int(row.get("rows") or 0),
                "engine": row.get("engine"),
                "ok": bool(row.get("ok")),
                "touched_ids": [str(t) for t in touched][:8],
            }
        )

    hypothesis_rows = hypotheses.dicts()
    challenge_rows = challenges.dicts()
    upheld = [c for c in challenge_rows if str(c.get("outcome")) == "upheld"]
    open_hypotheses = [h for h in hypothesis_rows if str(h.get("status")) == "open"]
    data = {
        "investigation_id": investigation_id,
        "steps": step_rows,
        "attack_paths": path_rows,
        "hypotheses": hypothesis_rows,
        "challenges": challenge_rows,
        "verdicts": verdicts.dicts(),
        "counts": {
            "steps": len(step_rows),
            "paths": len(path_rows),
            "hypotheses": len(hypothesis_rows),
            "open_hypotheses": len(open_hypotheses),
            "challenges": len(challenge_rows),
            "upheld_challenges": len(upheld),
            "verdicts": len(verdicts.dicts()),
        },
    }
    summary = (
        f"Blackboard for {investigation_id}: {len(step_rows)} step(s), {len(path_rows)} path(s), "
        f"{len(hypothesis_rows)} hypothesis/es ({len(open_hypotheses)} open), "
        f"{len(challenge_rows)} challenge(s) of which {len(upheld)} upheld."
    )
    return envelope(
        summary=summary,
        data=data,
        cypher=cypher,
        touched_ids=[p["target"] for p in path_rows] + [p["entry"] for p in path_rows],
        rows=len(step_rows) + len(hypothesis_rows) + len(challenge_rows),
        latency_ms=(time.perf_counter() - started) * 1000.0,
        # `data` is clipped to the LLM budget, which can drop the very
        # hypothesis a verdict has to adjudicate. The orchestrator reads the
        # complete board from here; the provider strips it before the model.
        extra={
            "full": {
                "steps": step_rows,
                "attack_paths": path_rows,
                "hypotheses": hypothesis_rows,
                "challenges": challenge_rows,
            }
        },
    )


DESCRIPTIONS = {
    "post_hypothesis": (
        "Scout only. Post one falsifiable, one-sentence claim to the shared blackboard, with the node "
        "ids it is about and the step ids whose results support it. Do not post a claim you have not "
        "verified with a tool. Step ids that do not belong to this investigation are dropped."
    ),
    "post_challenge": (
        "Skeptic only. Record a falsification attempt against a hypothesis. 'kind' names the check: "
        "control_present, edge_dead, service_inactive, auth_required, unreachable_code or "
        "prior_lesson. Use outcome 'upheld' only when a cited tool result supports the challenge; an "
        "upheld challenge marks the hypothesis falsified. Otherwise use 'rejected'."
    ),
    "list_blackboard": (
        "Read everything the other agents have written for this investigation: the step ledger with "
        "summaries and touched ids, the persisted attack paths with score components, all hypotheses "
        "with status, all challenges with outcome, and any verdicts. This is the only way you see "
        "another agent's work - there is no chat between agents."
    ),
}


def register(mcp: Any) -> None:
    mcp.tool(name="post_hypothesis", description=DESCRIPTIONS["post_hypothesis"])(post_hypothesis)
    mcp.tool(name="post_challenge", description=DESCRIPTIONS["post_challenge"])(post_challenge)
    mcp.tool(name="list_blackboard", description=DESCRIPTIONS["list_blackboard"])(list_blackboard)
