"""Read-only Cypher for the Explorer, plus the schema and saved examples."""

from __future__ import annotations

import asyncio
import re

from fastapi import APIRouter, HTTPException

from app.config import settings
from app.db import ro_query
from app.models import CypherRequest, CypherResponse, SchemaResponse
from mcp_server.graph_ops import CANDIDATE_PATH_CYPHER

router = APIRouter(tags=["cypher"])

FORBIDDEN = re.compile(
    r"\b(create|merge|delete|detach|set|remove|drop|load\s+csv|foreach)\b"
    r"|call\s+db\.idx\.[a-z.]*create"
    r"|\bgraph\.(copy|delete)\b",
    re.IGNORECASE,
)

LABEL_CYPHER = "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC"
REL_CYPHER = "MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS count ORDER BY count DESC"

EXAMPLES: list[dict[str, str]] = [
    {
        "name": "Attack paths to a crown jewel",
        "description": "The candidate query the analysis tools run before Python scores each path.",
        "query": CANDIDATE_PATH_CYPHER.replace("__TAIL__", "5").replace("$limit", "50").strip(),
    },
    {
        "name": "Live-exploit candidates",
        "description": "Open findings with a network vector and reachable code, highest CVSS first.",
        "query": (
            "MATCH (s:Service)-[:HAS_FINDING]->(f:Finding)-[:OF]->(v:Vulnerability)\n"
            "WHERE f.status = 'open' AND f.reachable_code = true AND v.attack_vector = 'network'\n"
            "RETURN f.id, s.id, v.cve, v.cvss, v.epss, v.kev\n"
            "ORDER BY v.cvss DESC LIMIT 25"
        ),
    },
    {
        "name": "Unprotected call edges",
        "description": "Service-to-service calls that carry no authorisation at all.",
        "query": (
            "MATCH (a:Service)-[r:CALLS]->(b:Service)\n"
            "WHERE coalesce(r.authz, 'none') = 'none'\n"
            "RETURN a.id, b.id, r.protocol, r.rps ORDER BY r.rps DESC"
        ),
    },
    {
        "name": "Who can reach the payments vault",
        "description": "Direct writers and IAM-role holders for the PCI vault.",
        "query": (
            "MATCH (d:DataStore {id: 'payments-vault'})\n"
            "OPTIONAL MATCH (s:Service)-[a:READS_FROM|WRITES_TO]->(d)\n"
            "OPTIONAL MATCH (t:Service)-[:ASSUMES]->(ro:IAMRole)-[:CAN_ACCESS]->(d)\n"
            "RETURN d.classification, collect(DISTINCT s.id) AS direct,\n"
            "       collect(DISTINCT t.id) AS via_role, collect(DISTINCT ro.name) AS roles"
        ),
    },
    {
        "name": "The shared chokepoint package",
        "description": "Every service that depends on the internal HTTP client and its findings.",
        "query": (
            "MATCH (s:Service)-[:DEPENDS_ON]->(p:Package {name: 'internal-http-client'})\n"
            "OPTIONAL MATCH (s)-[:HAS_FINDING]->(f:Finding)-[:VIA]->(p)\n"
            "RETURN s.id, s.internet_facing, collect(f.id) AS findings ORDER BY s.id"
        ),
    },
    {
        "name": "Active controls and what they cover",
        "description": "Which control protects which node, and against what.",
        "query": (
            "MATCH (c:Control)-[p:PROTECTS]->(t)\n"
            "RETURN c.name, c.type, c.active, p.against, t.id, labels(t)[0] AS target_label\n"
            "ORDER BY c.active DESC, c.name"
        ),
    },
    {
        "name": "Lessons and what they apply to",
        "description": "The memory layer linked back into the estate.",
        "query": (
            "MATCH (l:Lesson)-[:APPLIES_TO]->(n)\n"
            "RETURN l.id, l.scope_kind, l.scope_value, l.effect, l.uses,\n"
            "       collect(n.id)[0..8] AS applies_to ORDER BY l.id"
        ),
    },
]


def _schema() -> SchemaResponse:
    labels = ro_query(LABEL_CYPHER).dicts()
    rels = ro_query(REL_CYPHER).dicts()
    return SchemaResponse(
        labels=[
            {"label": str(row.get("label") or "?"), "count": int(row.get("count") or 0)}
            for row in labels
            if row.get("label")
        ],
        relationship_types=[
            {"type": str(row.get("type") or "?"), "count": int(row.get("count") or 0)}
            for row in rels
            if row.get("type")
        ],
        examples=EXAMPLES,
    )


def _run(query: str) -> CypherResponse:
    outcome = ro_query(query, None, timeout_ms=settings.cypher_timeout_ms)
    rows = outcome.rows
    truncated = len(rows) > settings.cypher_row_cap
    return CypherResponse(
        header=outcome.header,
        rows=rows[: settings.cypher_row_cap],
        row_count=len(rows),
        latency_ms=outcome.latency_ms,
        truncated=truncated,
        query=query,
    )


@router.get("/cypher/schema", response_model=SchemaResponse)
async def schema() -> SchemaResponse:
    return await asyncio.to_thread(_schema)


@router.post("/cypher/readonly", response_model=CypherResponse)
async def readonly(request: CypherRequest) -> CypherResponse:
    query = request.query.strip().rstrip(";")
    match = FORBIDDEN.search(query)
    if match:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{match.group(0).strip()}' is not allowed here. This endpoint is read-only: "
                "no CREATE, MERGE, DELETE, SET, REMOVE, DROP, LOAD CSV, index creation or GRAPH.COPY."
            ),
        )
    try:
        return await asyncio.to_thread(_run, query)
    except Exception as exc:  # noqa: BLE001 - report the database error verbatim
        raise HTTPException(status_code=400, detail=f"{exc.__class__.__name__}: {exc}") from exc
