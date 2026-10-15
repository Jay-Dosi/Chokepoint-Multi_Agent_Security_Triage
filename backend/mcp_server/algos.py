"""Graph algorithms with a FalkorDB-native path and a networkx fallback.

Procedure names differ between FalkorDB builds, so every algorithm is probed
once at start-up (PRD 7.6) and each wrapper reports the `engine` it actually
used. The networkx projections are built from the same bounded queries the
analysis tools already run.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import networkx as nx

from app.db import ro_query

log = logging.getLogger("chokepoint.algos")

ESTATE_REL_TYPES = [
    "REACHES",
    "ROUTES_TO",
    "CALLS",
    "READS_FROM",
    "WRITES_TO",
    "ASSUMES",
    "CAN_ACCESS",
    "DEPENDS_ON",
    "AFFECTED_BY",
    "HAS_FINDING",
    "OF",
    "VIA",
    "PROTECTS",
    "OWNS",
]

EDGE_CYPHER = """
MATCH (a)-[r]->(b)
WHERE a.id IS NOT NULL AND b.id IS NOT NULL AND type(r) IN $types
RETURN a.id AS src, type(r) AS rel, b.id AS dst
LIMIT $limit
"""

PROCEDURE_CYPHER = "CALL dbms.procedures() YIELD name RETURN name"

NATIVE_PROCEDURES = {
    "bfs": "algo.BFS",
    "pagerank": "algo.pageRank",
    "betweenness": "algo.betweenness",
    "wcc": "algo.WCC",
    "shortest_path": "algo.SPpaths",
}


@dataclass(slots=True)
class AlgoResult:
    engine: str
    cypher: list[str]
    data: dict[str, Any]
    rows: int


_capabilities: dict[str, bool] | None = None
_procedure_names: list[str] = []


def detect_capabilities(force: bool = False) -> dict[str, bool]:
    """Probe which `algo.*` procedures this FalkorDB build exposes."""
    global _capabilities, _procedure_names
    if _capabilities is not None and not force:
        return _capabilities
    names: list[str] = []
    try:
        outcome = ro_query(PROCEDURE_CYPHER)
        names = [str(v) for v in outcome.column("name")]
    except Exception as exc:  # noqa: BLE001 - procedure listing is optional
        log.warning("procedure listing unavailable (%s); algorithms will use networkx", exc)
    _procedure_names = sorted(names)
    lowered = {n.lower() for n in names}
    _capabilities = {key: proc.lower() in lowered for key, proc in NATIVE_PROCEDURES.items()}
    log.info(
        "algorithm capabilities: %s",
        ", ".join(f"{k}={'native' if v else 'networkx'}" for k, v in sorted(_capabilities.items())),
    )
    return _capabilities


def capability_report() -> dict[str, Any]:
    caps = detect_capabilities()
    return {
        "procedures_detected": len(_procedure_names),
        "algorithms": {k: ("falkordb" if v else "networkx") for k, v in sorted(caps.items())},
        "native_procedures": [p for p in _procedure_names if p.lower().startswith("algo.")][:40],
    }


def load_edges(rel_types: list[str] | None = None, graph: str | None = None) -> tuple[list[tuple[str, str, str]], str]:
    types = [t for t in (rel_types or ESTATE_REL_TYPES) if t in ESTATE_REL_TYPES] or ESTATE_REL_TYPES
    outcome = ro_query(EDGE_CYPHER, {"types": types, "limit": 200000}, graph=graph)
    edges = [(str(r["src"]), str(r["rel"]), str(r["dst"])) for r in outcome.dicts()]
    return edges, outcome.cypher


def build_digraph(edges: list[tuple[str, str, str]]) -> nx.DiGraph:
    g: nx.DiGraph = nx.DiGraph()
    for src, rel, dst in edges:
        g.add_edge(src, dst, rel=rel)
    return g


def calls_digraph(graph: str | None = None) -> tuple[nx.DiGraph, str]:
    edges, cypher = load_edges(["CALLS"], graph)
    return build_digraph(edges), cypher


def pagerank(nodes: list[str] | None, graph: str | None = None) -> AlgoResult:
    """PageRank over the CALLS graph, optionally restricted to a node subset."""
    caps = detect_capabilities()
    cypher: list[str] = []
    if caps.get("pagerank"):
        try:
            outcome = ro_query(
                "CALL algo.pageRank('Service', 'CALLS') YIELD node, score "
                "RETURN node.id AS id, score ORDER BY score DESC LIMIT 50",
                graph=graph,
            )
            scores = {str(r["id"]): float(r["score"]) for r in outcome.dicts() if r.get("id")}
            if scores:
                if nodes:
                    scores = {k: v for k, v in scores.items() if k in set(nodes)}
                return AlgoResult("falkordb", [outcome.cypher], {"scores": scores}, len(scores))
        except Exception as exc:  # noqa: BLE001 - fall back to networkx
            log.info("algo.pageRank unavailable at call time: %s", exc)
    g, cy = calls_digraph(graph)
    cypher.append(cy)
    if nodes:
        g = g.subgraph([n for n in nodes if n in g]).copy()
    if g.number_of_nodes() == 0:
        return AlgoResult("networkx", cypher, {"scores": {}}, 0)
    scores = nx.pagerank(g, alpha=0.85)
    return AlgoResult("networkx", cypher, {"scores": scores}, len(scores))


def betweenness(nodes: list[str] | None, graph: str | None = None) -> AlgoResult:
    """Betweenness centrality over the CALLS graph, optionally on a subset."""
    caps = detect_capabilities()
    cypher: list[str] = []
    if caps.get("betweenness"):
        try:
            outcome = ro_query(
                "CALL algo.betweenness({nodeLabels: ['Service'], relationshipTypes: ['CALLS']}) "
                "YIELD node, score RETURN node.id AS id, score ORDER BY score DESC LIMIT 50",
                graph=graph,
            )
            scores = {str(r["id"]): float(r["score"]) for r in outcome.dicts() if r.get("id")}
            if scores:
                if nodes:
                    scores = {k: v for k, v in scores.items() if k in set(nodes)}
                return AlgoResult("falkordb", [outcome.cypher], {"scores": scores}, len(scores))
        except Exception as exc:  # noqa: BLE001 - fall back to networkx
            log.info("algo.betweenness unavailable at call time: %s", exc)
    g, cy = calls_digraph(graph)
    cypher.append(cy)
    if nodes:
        g = g.subgraph([n for n in nodes if n in g]).copy()
    if g.number_of_nodes() == 0:
        return AlgoResult("networkx", cypher, {"scores": {}}, 0)
    scores = nx.betweenness_centrality(g, normalized=True)
    return AlgoResult("networkx", cypher, {"scores": scores}, len(scores))


def weakly_connected(graph: str | None = None) -> AlgoResult:
    """Weakly connected components of the CALLS graph (PRD tool 12)."""
    caps = detect_capabilities()
    if caps.get("wcc"):
        try:
            outcome = ro_query(
                "CALL algo.WCC({nodeLabels: ['Service'], relationshipTypes: ['CALLS']}) "
                "YIELD node, componentId RETURN node.id AS id, componentId AS component",
                graph=graph,
            )
            grouped: dict[str, list[str]] = {}
            for row in outcome.dicts():
                grouped.setdefault(str(row["component"]), []).append(str(row["id"]))
            if grouped:
                components = sorted(grouped.values(), key=lambda c: (-len(c), c[0]))
                return AlgoResult("falkordb", [outcome.cypher], {"components": components}, len(components))
        except Exception as exc:  # noqa: BLE001 - fall back to networkx
            log.info("algo.WCC unavailable at call time: %s", exc)
    g, cypher = calls_digraph(graph)
    if g.number_of_nodes() == 0:
        return AlgoResult("networkx", [cypher], {"components": []}, 0)
    components = [sorted(c) for c in nx.weakly_connected_components(g)]
    components.sort(key=lambda c: (-len(c), c[0]))
    return AlgoResult("networkx", [cypher], {"components": components}, len(components))


def bfs_levels(start: str, max_hops: int, graph: str | None = None) -> AlgoResult:
    """Depth per reachable service from `start` over CALLS edges."""
    caps = detect_capabilities()
    if caps.get("bfs"):
        try:
            outcome = ro_query(
                "MATCH (s:Service {id: $start}) "
                "CALL algo.BFS(s, $hops, 'CALLS') YIELD nodes "
                "UNWIND nodes AS n RETURN n.id AS id",
                {"start": start, "hops": int(max_hops)},
                graph=graph,
            )
            ids = [str(v) for v in outcome.column("id") if v]
            if ids:
                return AlgoResult("falkordb", [outcome.cypher], {"reached": ids}, len(ids))
        except Exception as exc:  # noqa: BLE001 - fall back to networkx
            log.info("algo.BFS unavailable at call time: %s", exc)
    g, cypher = calls_digraph(graph)
    if start not in g:
        return AlgoResult("networkx", [cypher], {"depths": {}}, 0)
    depths = nx.single_source_shortest_path_length(g, start, cutoff=int(max_hops))
    return AlgoResult("networkx", [cypher], {"depths": depths}, len(depths))


def shortest_path(
    from_id: str, to_id: str, rel_types: list[str] | None = None, graph: str | None = None
) -> AlgoResult:
    """Shortest undirected-aware path between two estate nodes."""
    edges, cypher = load_edges(rel_types, graph)
    g = build_digraph(edges)
    if from_id not in g or to_id not in g:
        return AlgoResult("networkx", [cypher], {"found": False, "reason": "node not present in the projected edge set"}, 0)
    try:
        nodes = nx.shortest_path(g, from_id, to_id)
        directed = True
    except nx.NetworkXNoPath:
        undirected = g.to_undirected(as_view=True)
        try:
            nodes = nx.shortest_path(undirected, from_id, to_id)
            directed = False
        except nx.NetworkXNoPath:
            return AlgoResult(
                "networkx",
                [cypher],
                {"found": False, "reason": f"no path between {from_id} and {to_id} over {rel_types or 'estate'} edges"},
                0,
            )
    rels: list[str] = []
    for src, dst in zip(nodes, nodes[1:], strict=False):
        data = g.get_edge_data(src, dst) or g.get_edge_data(dst, src) or {}
        rels.append(str(data.get("rel", "")))
    return AlgoResult(
        "networkx",
        [cypher],
        {
            "found": True,
            "directed": directed,
            "nodes": nodes,
            "rel_types": rels,
            "hops": len(nodes) - 1,
        },
        len(nodes),
    )

