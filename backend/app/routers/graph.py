"""Graph read endpoints for the map, the headline numbers and the naive view."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import APIRouter, Query

from app.models import (
    CrownJewel,
    FindingRow,
    GraphEdge,
    GraphNode,
    GraphOverviewResponse,
    Headline,
    NaiveViewResponse,
    PublicIngress,
    SubgraphResponse,
)
from app.config import settings
from app.db import ro_query
from mcp_server.attack import enumerate_paths
from mcp_server.graph_ops import load_projection
from mcp_server.tools import read as read_tools

router = APIRouter(prefix="/graph", tags=["graph"])

NODE_CAP = 150
EDGE_CAP = 900

NODES_CYPHER = """
MATCH (n)
WHERE n.id IN $ids
RETURN n.id AS id, labels(n)[0] AS label, properties(n) AS props
"""
# Use IN clause instead of UNWIND + MATCH for better performance
EDGES_BETWEEN_CYPHER = """
MATCH (a)-[r]->(b)
WHERE a.id IN $ids AND b.id IN $ids
RETURN a.id AS source, b.id AS target, type(r) AS type, properties(r) AS props
LIMIT $cap
"""
OUT_EDGES_CYPHER = """
MATCH (a)-[r]->(b)
WHERE a.id IN $ids AND b.id IS NOT NULL
RETURN a.id AS source, b.id AS target, type(r) AS type, properties(r) AS props
LIMIT $cap
"""
IN_EDGES_CYPHER = """
MATCH (a)-[r]->(b)
WHERE b.id IN $ids AND a.id IS NOT NULL
RETURN a.id AS source, b.id AS target, type(r) AS type, properties(r) AS props
LIMIT $cap
"""


def _clean_props(props: Any) -> dict[str, Any]:
    if not isinstance(props, dict):
        return {}
    return {
        key: value
        for key, value in props.items()
        if not key.startswith("__") and key not in ("embedding", "result_json", "payload_json")
    }


def _edges_between(ids: list[str], timeout_ms: int | None = None) -> list[GraphEdge]:
    if not ids:
        return []
    seen: dict[str, GraphEdge] = {}
    wanted = set(ids)
    for row in ro_query(EDGES_BETWEEN_CYPHER, {"ids": ids, "cap": EDGE_CAP}, timeout_ms=timeout_ms).dicts():
        source, target = str(row["source"]), str(row["target"])
        # The IN clause already filters both source and target, but double-check
        if source not in wanted or target not in wanted:
            continue
        rel = str(row["type"])
        key = f"{source}|{rel}|{target}"
        if key in seen:
            continue
        seen[key] = GraphEdge(
            id=key, source=source, target=target, type=rel, props=_clean_props(row.get("props"))
        )
    return list(seen.values())


def _expand(ids: list[str], hops: int, timeout_ms: int | None = None) -> list[str]:
    frontier = list(dict.fromkeys(ids))
    collected = list(frontier)
    for _ in range(max(0, hops)):
        if not frontier or len(collected) >= NODE_CAP * 2:
            break
        neighbours: list[str] = []
        for cypher in (OUT_EDGES_CYPHER, IN_EDGES_CYPHER):
            for row in ro_query(cypher, {"ids": frontier, "cap": EDGE_CAP}, timeout_ms=timeout_ms).dicts():
                for candidate in (str(row["source"]), str(row["target"])):
                    if candidate not in collected:
                        collected.append(candidate)
                        neighbours.append(candidate)
        frontier = neighbours
    return collected


def _subgraph(ids: list[str], hops: int, timeout_ms: int | None = None) -> SubgraphResponse:
    started = time.perf_counter()
    collected = _expand(ids, hops, timeout_ms=timeout_ms)
    truncated = len(collected) > NODE_CAP
    hidden = max(0, len(collected) - NODE_CAP)
    kept = collected[:NODE_CAP]
    nodes = [
        GraphNode(
            id=str(row["id"]),
            label=str(row.get("label") or "Unknown"),
            props=_clean_props(row.get("props")),
        )
        for row in ro_query(NODES_CYPHER, {"ids": kept}, timeout_ms=timeout_ms).dicts()
    ]
    present = [n.id for n in nodes]
    return SubgraphResponse(
        nodes=nodes,
        edges=_edges_between(present, timeout_ms=timeout_ms),
        truncated=truncated,
        hidden_nodes=hidden,
        latency_ms=round((time.perf_counter() - started) * 1000.0, 2),
    )


def _overview() -> GraphOverviewResponse:
    result = read_tools.graph_overview()
    data = result.get("data") or {}
    headline = data.get("headline") or {}
    return GraphOverviewResponse(
        nodes_by_label={str(k): int(v) for k, v in (data.get("nodes_by_label") or {}).items()},
        relationships_by_type={
            str(k): int(v) for k, v in (data.get("relationships_by_type") or {}).items()
        },
        scan_ids=[str(s) for s in data.get("scan_ids") or []],
        public_ingress_count=int(data.get("public_ingress_count") or 0),
        public_ingress=[
            PublicIngress(
                id=str(row.get("id")),
                host=str(row.get("host") or ""),
                authn=str(row.get("authn") or ""),
                waf=bool(row.get("waf")),
                service_id=str(row.get("service_id") or ""),
            )
            for row in data.get("public_ingress") or []
            if isinstance(row, dict)
        ],
        crown_jewels=[
            CrownJewel(
                id=str(row.get("id")),
                name=str(row.get("name") or ""),
                kind=str(row.get("kind") or ""),
                classification=str(row.get("classification") or ""),
                records=int(row.get("records") or 0),
            )
            for row in data.get("crown_jewels") or []
            if isinstance(row, dict)
        ],
        headline=Headline(
            open_findings=int(headline.get("open_findings") or 0),
            internet_reachable_findings=int(headline.get("internet_reachable_findings") or 0),
            findings_reaching_crown_jewel=int(headline.get("findings_reaching_crown_jewel") or 0),
            attack_paths=int(headline.get("attack_paths") or 0),
            crown_jewels_reachable=[str(c) for c in headline.get("crown_jewels_reachable") or []],
            top_path_score_pct=float(headline.get("top_path_score_pct") or 0.0),
        ),
        latency_ms=float(result.get("latency_ms") or 0.0),
    )


def _focus(kind: str) -> SubgraphResponse:
    projection = load_projection()
    ids: list[str] = ["internet"]
    if kind == "attack_surface":
        paths = enumerate_paths(projection, top_k=10)
        for path in paths:
            ids += [str(node["id"]) for node in path.nodes]
        ids += [gid for gid, g in projection.ingress.items() if g.get("public")]
        ids += [sid for sid, store in projection.stores.items() if store.get("crown_jewel")]
    elif kind == "controls":
        ids += [c.id for c in projection.controls] + [c.target_id for c in projection.controls]
    else:
        ids += [gid for gid, g in projection.ingress.items() if g.get("public")]
        ids += [sid for sid, store in projection.stores.items() if store.get("crown_jewel")]
    unique = [i for i in dict.fromkeys(ids) if i][:120]
    return _subgraph(unique, hops=0, timeout_ms=settings.cypher_timeout_ms)


def _naive(limit: int) -> NaiveViewResponse:
    result = read_tools.list_open_findings(limit=limit)
    data = result.get("data") or {}
    rows = [
        FindingRow(
            finding_id=str(row.get("finding_id")),
            service_id=str(row.get("service_id") or ""),
            cve=str(row.get("cve") or ""),
            cvss=float(row.get("cvss") or 0.0),
            epss=float(row.get("epss") or 0.0),
            kev=bool(row.get("kev")),
            attack_vector=str(row.get("attack_vector") or "network"),
            reachable_code=bool(row.get("reachable_code")),
            package=str(row.get("package") or ""),
            version=str(row.get("version") or ""),
            scan_id=str(row.get("scan_id") or ""),
            summary=str(row.get("summary") or ""),
            tier=int(row.get("tier") or 3),
        )
        for row in data.get("findings") or []
        if isinstance(row, dict)
    ]
    return NaiveViewResponse(findings=rows, latency_ms=float(result.get("latency_ms") or 0.0))


@router.get("/overview", response_model=GraphOverviewResponse)
async def overview() -> GraphOverviewResponse:
    return await asyncio.to_thread(_overview)


@router.get("/subgraph", response_model=SubgraphResponse)
async def subgraph(
    ids: str = Query(default="", description="Comma-separated node ids."),
    hops: int = Query(default=1, ge=0, le=3),
) -> SubgraphResponse:
    wanted = [part.strip() for part in ids.split(",") if part.strip()]
    if not wanted:
        return SubgraphResponse()
    return await asyncio.to_thread(_subgraph, wanted[:60], hops, settings.cypher_timeout_ms)


@router.get("/focus", response_model=SubgraphResponse)
async def focus(kind: str = Query(default="attack_surface")) -> SubgraphResponse:
    return await asyncio.to_thread(_focus, kind)


@router.get("/findings", response_model=NaiveViewResponse)
async def naive_view(limit: int = Query(default=10, ge=1, le=50)) -> NaiveViewResponse:
    return await asyncio.to_thread(_naive, limit)
