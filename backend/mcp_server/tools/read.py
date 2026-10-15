"""Read and discovery tools (PRD 8.1)."""

from __future__ import annotations

import logging
import re
import time
from typing import Annotated, Any

from pydantic import Field

from app.db import ro_query

from ..attack import Modifications, enumerate_paths, live_exploits
from ..graph_ops import envelope, error_envelope, load_projection

log = logging.getLogger("chokepoint.tools.read")

SAFE_SEARCH = re.compile(r"[^A-Za-z0-9 ._@/:-]+")

LABEL_COUNT_CYPHER = "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS c ORDER BY c DESC"
REL_COUNT_CYPHER = "MATCH ()-[r]->() RETURN type(r) AS rel, count(r) AS c ORDER BY c DESC"
SCAN_CYPHER = "MATCH (f:Finding) RETURN DISTINCT f.scan_id AS scan_id ORDER BY scan_id DESC LIMIT 12"
LAST_INVESTIGATION_CYPHER = """
MATCH (i:Investigation)
RETURN i.id AS id, i.goal AS goal, i.status AS status, i.started_at AS started_at,
       i.scan_id AS scan_id
ORDER BY i.started_at DESC
LIMIT 1
"""
PUBLIC_INGRESS_CYPHER = """
MATCH (:Internet)-[:REACHES]->(g:Ingress)
WHERE g.public = true
OPTIONAL MATCH (g)-[:ROUTES_TO]->(s:Service)
RETURN g.id AS id, g.host AS host, g.authn AS authn, g.waf AS waf, s.id AS service_id
"""
CROWN_CYPHER = """
MATCH (d:DataStore)
WHERE d.crown_jewel = true
RETURN d.id AS id, d.name AS name, d.kind AS kind, d.classification AS classification,
       d.records AS records
ORDER BY d.records DESC
"""
OPEN_FINDING_COUNT_CYPHER = "MATCH (f:Finding) WHERE f.status = 'open' RETURN count(f) AS c"


def graph_overview() -> dict[str, Any]:
    """Counts, scan ids, public ingress and crown jewels, plus the live headline numbers."""
    started = time.perf_counter()
    cypher: list[str] = []
    try:
        labels = ro_query(LABEL_COUNT_CYPHER)
        cypher.append(labels.cypher)
        rels = ro_query(REL_COUNT_CYPHER)
        cypher.append(rels.cypher)
        scans = ro_query(SCAN_CYPHER)
        cypher.append(scans.cypher)
        last = ro_query(LAST_INVESTIGATION_CYPHER)
        cypher.append(last.cypher)
        ingress = ro_query(PUBLIC_INGRESS_CYPHER)
        cypher.append(ingress.cypher)
        crown = ro_query(CROWN_CYPHER)
        cypher.append(crown.cypher)
        open_count = ro_query(OPEN_FINDING_COUNT_CYPHER)
        cypher.append(open_count.cypher)
    except Exception as exc:  # noqa: BLE001 - surface database errors to the agent
        return error_envelope("graph_overview failed", detail=str(exc), cypher=cypher)

    proj = load_projection()
    entry_live = live_exploits(proj, Modifications(), as_entry=True)
    lateral_live = live_exploits(proj, Modifications(), as_entry=False)
    paths = enumerate_paths(proj, top_k=0)
    path_services = {s for p in paths for s in p.services}
    internet_reachable = sum(len(v) for k, v in entry_live.items() if proj.public_entry_ingress(k))
    reaching_crown = sum(len(lateral_live.get(s, [])) for s in path_services)

    crown_rows = crown.dicts()
    ingress_rows = ingress.dicts()
    data = {
        "nodes_by_label": {str(r["label"]): int(r["c"]) for r in labels.dicts() if r.get("label")},
        "relationships_by_type": {str(r["rel"]): int(r["c"]) for r in rels.dicts() if r.get("rel")},
        "scan_ids": [str(r["scan_id"]) for r in scans.dicts() if r.get("scan_id")],
        "last_investigation": last.first(),
        "public_ingress_count": len({str(r["id"]) for r in ingress_rows}),
        "public_ingress": [
            {
                "id": str(r["id"]),
                "host": r.get("host"),
                "authn": r.get("authn"),
                "waf": bool(r.get("waf")),
                "service_id": r.get("service_id"),
            }
            for r in ingress_rows
        ],
        "crown_jewels": [
            {
                "id": str(r["id"]),
                "name": r.get("name"),
                "kind": r.get("kind"),
                "classification": r.get("classification"),
                "records": int(r.get("records") or 0),
            }
            for r in crown_rows
        ],
        "headline": {
            "open_findings": int(open_count.scalar(0) or 0),
            "internet_reachable_findings": internet_reachable,
            "findings_reaching_crown_jewel": reaching_crown,
            "attack_paths": len(paths),
            "crown_jewels_reachable": sorted({p.target for p in paths}),
            "top_path_score_pct": round(paths[0].breakdown.score * 100, 1) if paths else 0.0,
        },
    }
    touched = [str(r["id"]) for r in crown_rows] + [str(r["id"]) for r in ingress_rows]
    return envelope(
        summary=(
            f"{data['headline']['open_findings']} open findings; "
            f"{internet_reachable} internet-reachable; {reaching_crown} on a crown-jewel path; "
            f"{len(paths)} attack paths across {data['public_ingress_count']} public ingress points."
        ),
        data=data,
        cypher=cypher,
        touched_ids=touched,
        rows=len(crown_rows) + len(ingress_rows),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def _fulltext(label: str, query: str, limit: int) -> tuple[list[dict[str, Any]], str]:
    cleaned = SAFE_SEARCH.sub(" ", query).strip()
    if not cleaned:
        return [], ""
    cypher = (
        f"CALL db.idx.fulltext.queryNodes('{label}', $q) YIELD node, score "
        "RETURN node.id AS id, labels(node)[0] AS label, "
        "coalesce(node.name, node.cve, node.id) AS name, score ORDER BY score DESC LIMIT $limit"
    )
    try:
        outcome = ro_query(cypher, {"q": cleaned, "limit": limit})
        return outcome.dicts(), outcome.cypher
    except Exception as exc:  # noqa: BLE001 - fulltext index may be absent
        log.info("fulltext search on %s unavailable: %s", label, exc)
        return [], ""


def _contains(label: str, props: list[str], query: str, limit: int) -> tuple[list[dict[str, Any]], str]:
    clause = " OR ".join(f"toLower(coalesce(n.{p}, '')) CONTAINS $q" for p in props)
    cypher = (
        f"MATCH (n:{label}) WHERE {clause} "
        "RETURN n.id AS id, labels(n)[0] AS label, coalesce(n.name, n.cve, n.id) AS name, 1.0 AS score "
        "ORDER BY name LIMIT $limit"
    )
    outcome = ro_query(cypher, {"q": query.strip().lower(), "limit": limit})
    return outcome.dicts(), outcome.cypher


def find_entities(
    query: Annotated[str, Field(description="Free text: a service name, repo, CVE id or package name.")],
    label: Annotated[
        str | None,
        Field(description="Restrict to one label: Service, Vulnerability, Package or DataStore."),
    ] = None,
    limit: Annotated[int, Field(ge=1, le=40, description="Maximum rows to return.")] = 10,
) -> dict[str, Any]:
    """Resolve free text to graph node ids before using any other tool."""
    started = time.perf_counter()
    wanted = [label] if label else ["Service", "Vulnerability", "Package", "DataStore"]
    cypher: list[str] = []
    hits: list[dict[str, Any]] = []
    try:
        for lbl in wanted:
            rows, cy = ([], "")
            if lbl in ("Service", "Vulnerability"):
                rows, cy = _fulltext(lbl, query, limit)
            if not rows:
                props = {
                    "Service": ["name", "repo", "id"],
                    "Vulnerability": ["cve", "summary"],
                    "Package": ["name", "id"],
                    "DataStore": ["name", "kind", "id"],
                }.get(lbl, ["name", "id"])
                rows, cy = _contains(lbl, props, query, limit)
            if cy:
                cypher.append(cy)
            hits.extend(rows)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("find_entities failed", detail=str(exc), cypher=cypher)

    hits.sort(key=lambda r: (-float(r.get("score") or 0.0), str(r.get("name") or "")))
    hits = hits[:limit]
    return envelope(
        summary=f"{len(hits)} match(es) for '{query}'."
        if hits
        else f"No entity matches '{query}'. Try a service name, a CVE id or a package name.",
        data={"matches": hits},
        cypher=cypher,
        touched_ids=[str(h["id"]) for h in hits],
        rows=len(hits),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


SERVICE_CYPHER = """
MATCH (s:Service {id: $sid})
OPTIONAL MATCH (t:Team)-[:OWNS]->(s)
RETURN s.id AS id, s.name AS name, s.repo AS repo, s.language AS language, s.tier AS tier,
       s.status AS status, s.env AS env, s.cluster AS cluster,
       s.internet_facing AS internet_facing, t.id AS team_id, t.name AS team_name,
       t.slack_channel AS slack_channel
"""
ONCALL_CYPHER = """
MATCH (p:Person)-[:ON_CALL_FOR]->(:Service {id: $sid})
RETURN p.id AS id, p.name AS name, p.email AS email, p.role AS role ORDER BY p.name
"""
SERVICE_INGRESS_CYPHER = """
MATCH (:Internet)-[:REACHES]->(g:Ingress)-[r:ROUTES_TO]->(:Service {id: $sid})
RETURN g.id AS id, g.host AS host, g.public AS public, g.waf AS waf, g.authn AS authn,
       coalesce(r.path_prefix, '/') AS path_prefix
"""
SERVICE_CONTROL_CYPHER = """
MATCH (c:Control)-[p:PROTECTS]->(t)
WHERE t.id = $sid OR t.id IN $ingress_ids
RETURN c.id AS id, c.name AS name, c.type AS type, c.active AS active,
       coalesce(p.against, '*') AS against, t.id AS target
"""
SERVICE_STORE_CYPHER = """
MATCH (:Service {id: $sid})-[r:READS_FROM|WRITES_TO]->(d:DataStore)
RETURN d.id AS id, d.name AS name, d.kind AS kind, d.classification AS classification,
       d.records AS records, d.crown_jewel AS crown_jewel, type(r) AS access
"""
SERVICE_ROLE_CYPHER = """
MATCH (:Service {id: $sid})-[:ASSUMES]->(ro:IAMRole)
OPTIONAL MATCH (ro)-[:CAN_ACCESS]->(d:DataStore)
RETURN ro.id AS id, ro.name AS name, ro.privilege AS privilege, d.id AS store_id,
       d.classification AS store_classification, d.crown_jewel AS store_crown_jewel
"""
SERVICE_CALLS_CYPHER = """
MATCH (a:Service)-[r:CALLS]->(b:Service)
WHERE a.id = $sid OR b.id = $sid
RETURN a.id AS src, b.id AS dst, coalesce(r.authz, 'none') AS authz,
       coalesce(r.protocol, 'http') AS protocol, coalesce(r.rps, 0) AS rps
"""
SERVICE_FINDING_CYPHER = """
MATCH (:Service {id: $sid})-[:HAS_FINDING]->(f:Finding)-[:OF]->(v:Vulnerability)
WHERE f.status = 'open'
OPTIONAL MATCH (f)-[:VIA]->(pk:Package)
RETURN f.id AS finding_id, f.status AS status, f.reachable_code AS reachable_code,
       v.cve AS cve, v.cvss AS cvss, v.epss AS epss, v.kev AS kev,
       coalesce(pk.name, '') AS package, coalesce(pk.version, '') AS version
ORDER BY v.cvss DESC
LIMIT 25
"""


def get_service_context(
    service_id: Annotated[str, Field(description="Service id, for example 'gateway'.")],
) -> dict[str, Any]:
    """Everything about one service: owners, on-call, ingress, controls, data, calls, open findings."""
    started = time.perf_counter()
    cypher: list[str] = []
    try:
        service = ro_query(SERVICE_CYPHER, {"sid": service_id})
        cypher.append(service.cypher)
        row = service.first()
        if row is None:
            return error_envelope(
                f"No service with id '{service_id}'.",
                detail="use find_entities to resolve the name first",
                cypher=cypher,
            )
        ingress = ro_query(SERVICE_INGRESS_CYPHER, {"sid": service_id})
        cypher.append(ingress.cypher)
        ingress_rows = ingress.dicts()
        oncall = ro_query(ONCALL_CYPHER, {"sid": service_id})
        cypher.append(oncall.cypher)
        controls = ro_query(
            SERVICE_CONTROL_CYPHER,
            {"sid": service_id, "ingress_ids": [str(r["id"]) for r in ingress_rows]},
        )
        cypher.append(controls.cypher)
        stores = ro_query(SERVICE_STORE_CYPHER, {"sid": service_id})
        cypher.append(stores.cypher)
        roles = ro_query(SERVICE_ROLE_CYPHER, {"sid": service_id})
        cypher.append(roles.cypher)
        calls = ro_query(SERVICE_CALLS_CYPHER, {"sid": service_id})
        cypher.append(calls.cypher)
        findings = ro_query(SERVICE_FINDING_CYPHER, {"sid": service_id})
        cypher.append(findings.cypher)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("get_service_context failed", detail=str(exc), cypher=cypher)

    call_rows = calls.dicts()
    data = {
        "service": row,
        "on_call": oncall.dicts(),
        "ingress": ingress_rows,
        "controls": controls.dicts(),
        "data_stores": stores.dicts(),
        "iam_roles": roles.dicts(),
        "calls_out": [r for r in call_rows if str(r["src"]) == service_id],
        "calls_in": [r for r in call_rows if str(r["dst"]) == service_id],
        "open_findings": findings.dicts(),
    }
    touched = (
        [service_id]
        + [str(r["id"]) for r in ingress_rows]
        + [str(r["id"]) for r in data["controls"]]
        + [str(r["id"]) for r in data["data_stores"]]
        + [str(r["finding_id"]) for r in data["open_findings"]]
    )
    status = str(row.get("status") or "active")
    summary = (
        f"{service_id} ({status}, tier {row.get('tier')}, env {row.get('env')}, cluster {row.get('cluster')}) "
        f"owned by {row.get('team_name') or 'nobody'}; {len(ingress_rows)} ingress route(s), "
        f"{len(data['calls_in'])} inbound and {len(data['calls_out'])} outbound calls, "
        f"{len(data['open_findings'])} open findings."
    )
    return envelope(
        summary=summary,
        data=data,
        cypher=cypher,
        touched_ids=touched,
        rows=len(call_rows) + len(data["open_findings"]),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


OPEN_FINDINGS_CYPHER = """
MATCH (s:Service)-[:HAS_FINDING]->(f:Finding)-[:OF]->(v:Vulnerability)
WHERE f.status = 'open'
  AND ($scan_id = '' OR f.scan_id = $scan_id)
  AND ($service_id = '' OR s.id = $service_id)
  AND v.cvss >= $min_cvss
OPTIONAL MATCH (f)-[:VIA]->(pk:Package)
RETURN f.id AS finding_id, s.id AS service_id, s.tier AS tier, f.reachable_code AS reachable_code,
       f.scan_id AS scan_id, v.cve AS cve, v.cvss AS cvss, v.epss AS epss, v.kev AS kev,
       v.attack_vector AS attack_vector, coalesce(pk.name, '') AS package,
       coalesce(pk.version, '') AS version, coalesce(v.summary, '') AS summary
ORDER BY v.cvss DESC, v.epss DESC, f.id ASC
LIMIT $limit
"""


def list_open_findings(
    scan_id: Annotated[str | None, Field(description="Restrict to one scan id.")] = None,
    service_id: Annotated[str | None, Field(description="Restrict to one service id.")] = None,
    min_cvss: Annotated[float, Field(ge=0.0, le=10.0, description="Minimum CVSS.")] = 0.0,
    limit: Annotated[int, Field(ge=1, le=100, description="Maximum rows.")] = 25,
) -> dict[str, Any]:
    """The naive CVSS-sorted queue. Use it for context only; it says nothing about reachability."""
    started = time.perf_counter()
    try:
        outcome = ro_query(
            OPEN_FINDINGS_CYPHER,
            {
                "scan_id": scan_id or "",
                "service_id": service_id or "",
                "min_cvss": float(min_cvss),
                "limit": int(limit),
            },
        )
    except Exception as exc:  # noqa: BLE001
        return error_envelope("list_open_findings failed", detail=str(exc))
    rows = outcome.dicts()
    top = rows[0] if rows else None
    summary = (
        f"{len(rows)} open findings sorted by CVSS."
        + (
            f" Highest: {top['cve']} on {top['service_id']} at CVSS {top['cvss']}."
            if top
            else " Nothing open."
        )
        + " CVSS order says nothing about whether a path exists."
    )
    return envelope(
        summary=summary,
        data={"findings": rows},
        cypher=[outcome.cypher],
        touched_ids=[str(r["finding_id"]) for r in rows] + [str(r["service_id"]) for r in rows],
        rows=len(rows),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


LABEL_OF_CYPHER = "MATCH (n) WHERE n.id = $id RETURN labels(n)[0] AS label LIMIT 1"
RESOLVE_SERVICE_CYPHER = {
    "Finding": "MATCH (s:Service)-[:HAS_FINDING]->(:Finding {id: $id}) RETURN s.id AS sid LIMIT 1",
    "Package": "MATCH (s:Service)-[:DEPENDS_ON]->(:Package {id: $id}) RETURN s.id AS sid ORDER BY s.id LIMIT 1",
    "DataStore": "MATCH (s:Service)-[:READS_FROM|WRITES_TO]->(:DataStore {id: $id}) RETURN s.id AS sid ORDER BY s.id LIMIT 1",
    "Ingress": "MATCH (:Ingress {id: $id})-[:ROUTES_TO]->(s:Service) RETURN s.id AS sid ORDER BY s.id LIMIT 1",
    "Vulnerability": (
        "MATCH (s:Service)-[:HAS_FINDING]->(:Finding)-[:OF]->(:Vulnerability {id: $id}) "
        "RETURN s.id AS sid ORDER BY s.id LIMIT 1"
    ),
}
TEAM_CYPHER = """
MATCH (t:Team)-[:OWNS]->(s:Service {id: $sid})
RETURN t.id AS team_id, t.name AS team_name, t.slack_channel AS slack_channel
"""
TEAM_MEMBERS_CYPHER = """
MATCH (p:Person)-[:MEMBER_OF]->(:Team {id: $tid})
RETURN p.id AS id, p.name AS name, p.email AS email, p.role AS role ORDER BY p.name
"""


def owner_of(
    node_id: Annotated[str, Field(description="Any estate node id: service, finding, package or data store.")],
) -> dict[str, Any]:
    """Route a node to the team that owns it and the people on call, through the graph."""
    started = time.perf_counter()
    cypher: list[str] = []
    try:
        label_outcome = ro_query(LABEL_OF_CYPHER, {"id": node_id})
        cypher.append(label_outcome.cypher)
        label = str(label_outcome.scalar("") or "")
        if not label:
            return error_envelope(f"No node with id '{node_id}'.", detail="unknown id", cypher=cypher)
        service_id = node_id
        if label != "Service":
            resolver = RESOLVE_SERVICE_CYPHER.get(label)
            if resolver is None:
                return error_envelope(
                    f"{label} nodes have no owning service.", detail="unsupported label", cypher=cypher
                )
            resolved = ro_query(resolver, {"id": node_id})
            cypher.append(resolved.cypher)
            service_id = str(resolved.scalar("") or "")
            if not service_id:
                return error_envelope(
                    f"No service owns {node_id}.", detail="no OWNS path", cypher=cypher
                )
        team = ro_query(TEAM_CYPHER, {"sid": service_id})
        cypher.append(team.cypher)
        team_row = team.first()
        oncall = ro_query(ONCALL_CYPHER, {"sid": service_id})
        cypher.append(oncall.cypher)
        members: list[dict[str, Any]] = []
        if team_row:
            member_outcome = ro_query(TEAM_MEMBERS_CYPHER, {"tid": str(team_row["team_id"])})
            cypher.append(member_outcome.cypher)
            members = member_outcome.dicts()
    except Exception as exc:  # noqa: BLE001
        return error_envelope("owner_of failed", detail=str(exc), cypher=cypher)

    oncall_rows = oncall.dicts()
    data = {
        "node_id": node_id,
        "node_label": label,
        "service_id": service_id,
        "team": team_row,
        "on_call": oncall_rows,
        "members": members,
    }
    names = ", ".join(str(p["name"]) for p in oncall_rows) or "nobody listed"
    summary = (
        f"{node_id} -> {service_id} owned by {team_row['team_name'] if team_row else 'no team'}"
        f" ({team_row['slack_channel'] if team_row else 'no channel'}); on call: {names}."
    )
    return envelope(
        summary=summary,
        data=data,
        cypher=cypher,
        touched_ids=[node_id, service_id]
        + ([str(team_row["team_id"])] if team_row else [])
        + [str(p["id"]) for p in oncall_rows],
        rows=len(oncall_rows) + len(members),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


DESCRIPTIONS = {
    "graph_overview": (
        "Shape of the whole estate: node and relationship counts, scan ids, public ingress points, "
        "crown-jewel data stores, and the live headline numbers (open findings, internet-reachable "
        "findings, findings on a crown-jewel path, attack-path count). Call this first to orient "
        "yourself. Do not use it to decide what to fix."
    ),
    "find_entities": (
        "Resolve free text (service name, repo, CVE id, package name) to graph node ids. Use it "
        "before any tool that needs an id. Not a risk tool."
    ),
    "get_service_context": (
        "One service in full: owning team, on-call people, ingress routes and their authn, protective "
        "controls, data stores and IAM roles it can reach, one-hop calls in and out, and open findings. "
        "Use it to confirm or refute a claim about a specific service."
    ),
    "list_open_findings": (
        "The scanner queue sorted by CVSS descending - the naive view this product exists to beat. "
        "Use it only for context or to show what a severity-first triage would pick. It carries no "
        "reachability information; prefer find_attack_paths and check_exploitability."
    ),
    "owner_of": (
        "Walk the graph from any estate node to the owning team, its Slack channel, its members and "
        "the people on call. Use it before proposing an action so the ticket is routed correctly."
    ),
}


def register(mcp: Any) -> None:
    mcp.tool(name="graph_overview", description=DESCRIPTIONS["graph_overview"])(graph_overview)
    mcp.tool(name="find_entities", description=DESCRIPTIONS["find_entities"])(find_entities)
    mcp.tool(name="get_service_context", description=DESCRIPTIONS["get_service_context"])(
        get_service_context
    )
    mcp.tool(name="list_open_findings", description=DESCRIPTIONS["list_open_findings"])(
        list_open_findings
    )
    mcp.tool(name="owner_of", description=DESCRIPTIONS["owner_of"])(owner_of)
