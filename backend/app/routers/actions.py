"""Action approval. Approving writes the outbox files and the graph status."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from app.actions import github, outbox, slack
from app.db import ro_query, rw_query
from app.models import ActionDecisionResponse, ActionModel

router = APIRouter(prefix="/actions", tags=["actions"])
log = logging.getLogger("chokepoint.actions")

READ_ACTION_CYPHER = """
MATCH (v:Verdict)-[:RESULTED_IN]->(a:Action {id: $aid})
OPTIONAL MATCH (a)-[:ROUTED_TO]->(t:Team)
OPTIONAL MATCH (a)-[:NOTIFY]->(p:Person)
OPTIONAL MATCH (v)-[:ON]->(f:Finding)
RETURN a.id AS id, a.kind AS kind, a.status AS status, a.title AS title,
       coalesce(a.body_md, '') AS body_md, coalesce(a.created_at, '') AS created_at,
       coalesce(a.outbox_path, '') AS outbox_path,
       coalesce(a.delivery_json, '[]') AS delivery_json,
       v.id AS verdict_id, v.kind AS verdict_kind,
       coalesce(t.name, '') AS team, coalesce(t.slack_channel, '') AS slack_channel,
       collect(DISTINCT p.name) AS on_call, collect(DISTINCT f.id) AS finding_ids
"""
SET_STATUS_CYPHER = """
MATCH (a:Action {id: $aid})
SET a.status = $status, a.decided_at = $now, a.outbox_path = $outbox,
    a.delivery_json = $delivery
RETURN a.id AS id
"""
SET_FINDING_STATUS_CYPHER = """
MATCH (f:Finding)
WHERE f.id IN $ids
SET f.status = $status, f.last_seen = $now
RETURN count(f) AS c
"""

# A ticket leaves findings open until an engineer actually ships the fix; only
# an approved suppression changes the finding state.
STATUS_FOR_KIND = {"suppress": "suppressed", "virtual_patch_request": "accepted"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read(action_id: str) -> dict:
    row = ro_query(READ_ACTION_CYPHER, {"aid": action_id}).first()
    if row is None:
        raise KeyError(action_id)
    try:
        delivery = json.loads(str(row.get("delivery_json") or "[]"))
    except json.JSONDecodeError:
        delivery = []
    return {
        "id": str(row["id"]),
        "kind": str(row.get("kind") or "ticket"),
        "status": str(row.get("status") or "proposed"),
        "title": str(row.get("title") or ""),
        "body_md": str(row.get("body_md") or ""),
        "created_at": str(row.get("created_at") or ""),
        "verdict_id": str(row.get("verdict_id") or ""),
        "verdict_kind": str(row.get("verdict_kind") or ""),
        "team": str(row.get("team") or ""),
        "slack_channel": str(row.get("slack_channel") or ""),
        "on_call": [str(p) for p in row.get("on_call") or [] if p],
        "finding_ids": [str(f) for f in row.get("finding_ids") or [] if f],
        "outbox_path": str(row.get("outbox_path") or ""),
        "delivery": [str(d) for d in delivery],
    }


@router.post("/{action_id}/approve", response_model=ActionDecisionResponse)
async def approve(action_id: str) -> ActionDecisionResponse:
    try:
        action = await asyncio.to_thread(_read, action_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"no action {action_id}") from exc
    if action["status"] in ("executed", "rejected"):
        raise HTTPException(status_code=409, detail=f"action {action_id} is already {action['status']}")

    written = await asyncio.to_thread(outbox.write_action, action)
    delivery = [f"outbox: {written.get('markdown') or written.get('error') or 'not written'}"]
    delivery.append(await slack.post_action(action))
    delivery.append(await github.create_issue(action))

    finding_status = STATUS_FOR_KIND.get(action["kind"])
    if finding_status and action["finding_ids"]:
        await asyncio.to_thread(
            rw_query,
            SET_FINDING_STATUS_CYPHER,
            {"ids": action["finding_ids"], "status": finding_status, "now": _now()},
        )
        delivery.append(f"graph: {len(action['finding_ids'])} finding(s) set to '{finding_status}'")
    else:
        delivery.append("graph: finding statuses unchanged until the fix ships")

    await asyncio.to_thread(
        rw_query,
        SET_STATUS_CYPHER,
        {
            "aid": action_id,
            "status": "executed",
            "now": _now(),
            "outbox": written.get("markdown") or "",
            "delivery": json.dumps(delivery),
        },
    )
    updated = await asyncio.to_thread(_read, action_id)
    return ActionDecisionResponse(
        action=ActionModel(**updated),
        message=f"Approved and executed. {delivery[0]}",
    )


@router.post("/{action_id}/reject", response_model=ActionDecisionResponse)
async def reject(action_id: str) -> ActionDecisionResponse:
    try:
        action = await asyncio.to_thread(_read, action_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"no action {action_id}") from exc
    if action["status"] == "executed":
        raise HTTPException(status_code=409, detail=f"action {action_id} is already executed")
    await asyncio.to_thread(
        rw_query,
        SET_STATUS_CYPHER,
        {
            "aid": action_id,
            "status": "rejected",
            "now": _now(),
            "outbox": "",
            "delivery": json.dumps(["rejected by analyst"]),
        },
    )
    updated = await asyncio.to_thread(_read, action_id)
    return ActionDecisionResponse(action=ActionModel(**updated), message="Rejected. Nothing was sent.")
