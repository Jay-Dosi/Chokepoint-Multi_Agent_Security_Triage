"""Parameterised Cypher and the estate projection the analysis tools share.

Tools call :func:`load_projection` once and then reason over plain Python
structures. That keeps the number of round trips small, keeps the Cypher
dialect surface narrow, and makes path evaluation testable.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from app.config import settings
from app.db import ro_query

from .scoring import FindingFacts, VulnFacts

log = logging.getLogger("chokepoint.graph_ops")

# The variable-length candidate query named in PRD 7.1. The first two hops are
# pinned (internet -> public ingress -> active entry service) and the tail is
# the variable-length segment, so the search is anchored at both ends.
# Prefilters drop inactive services and mTLS call edges before Python evaluates
# the hop predicates and scores each path.
CANDIDATE_PATH_CYPHER = """
MATCH p = (:Internet)-[:REACHES]->(g:Ingress)-[:ROUTES_TO]->(entry:Service)
          -[:CALLS|READS_FROM|WRITES_TO|ASSUMES|CAN_ACCESS*1..__TAIL__]->(d:DataStore)
WHERE g.public = true
  AND d.crown_jewel = true
  AND entry.status = 'active'
  AND all(x IN nodes(p) WHERE labels(x)[0] <> 'Service' OR x.status = 'active')
  AND all(r IN relationships(p) WHERE type(r) <> 'CALLS' OR coalesce(r.authz, 'none') <> 'mtls')
RETURN [x IN nodes(p) | x.id] AS node_ids,
       [x IN nodes(p) | labels(x)[0]] AS node_labels,
       [r IN relationships(p) | type(r)] AS rel_types,
       [r IN relationships(p) | coalesce(r.authz, '')] AS rel_authz,
       length(p) AS hops
LIMIT $limit
"""

SERVICE_CYPHER = """
MATCH (s:Service)
RETURN s.id AS id, s.name AS name, s.repo AS repo, s.language AS language,
       s.tier AS tier, s.status AS status, s.internet_facing AS internet_facing,
       s.env AS env, s.cluster AS cluster
"""

INGRESS_CYPHER = """
MATCH (:Internet)-[:REACHES]->(g:Ingress)
OPTIONAL MATCH (g)-[r:ROUTES_TO]->(s:Service)
RETURN g.id AS ingress_id, g.host AS host, g.public AS public, g.waf AS waf,
       g.authn AS authn, s.id AS service_id, coalesce(r.path_prefix, '/') AS path_prefix
"""

CALLS_CYPHER = """
MATCH (a:Service)-[r:CALLS]->(b:Service)
RETURN a.id AS src, b.id AS dst, coalesce(r.authz, 'none') AS authz,
       coalesce(r.protocol, 'http') AS protocol, coalesce(r.rps, 0) AS rps
"""

STORE_ACCESS_CYPHER = """
MATCH (s:Service)-[r:READS_FROM|WRITES_TO]->(d:DataStore)
RETURN s.id AS service_id, type(r) AS rel, d.id AS store_id
"""

ROLE_ACCESS_CYPHER = """
MATCH (s:Service)-[:ASSUMES]->(ro:IAMRole)-[:CAN_ACCESS]->(d:DataStore)
RETURN s.id AS service_id, ro.id AS role_id, ro.name AS role_name,
       ro.privilege AS privilege, d.id AS store_id
"""

STORE_CYPHER = """
MATCH (d:DataStore)
RETURN d.id AS id, d.name AS name, d.kind AS kind, d.classification AS classification,
       d.records AS records, d.crown_jewel AS crown_jewel
"""

CONTROL_CYPHER = """
MATCH (c:Control)-[p:PROTECTS]->(t)
RETURN c.id AS id, c.name AS name, c.type AS type, c.active AS active,
       coalesce(p.against, '*') AS against, t.id AS target_id, labels(t)[0] AS target_label
"""

FINDING_CYPHER = """
MATCH (s:Service)-[:HAS_FINDING]->(f:Finding)-[:OF]->(v:Vulnerability)
OPTIONAL MATCH (f)-[:VIA]->(pk:Package)
RETURN f.id AS finding_id, s.id AS service_id, f.status AS status,
       f.reachable_code AS reachable_code, coalesce(f.scan_id, '') AS scan_id,
       coalesce(pk.id, '') AS package_id, coalesce(pk.name, '') AS package_name,
       coalesce(pk.version, '') AS package_version,
       v.cve AS cve, v.cvss AS cvss, v.epss AS epss, v.kev AS kev,
       v.attack_vector AS attack_vector, v.requires_auth AS requires_auth,
       coalesce(v.fixed_in, '') AS fixed_in, coalesce(v.summary, '') AS summary
"""

PACKAGE_USE_CYPHER = """
MATCH (s:Service)-[d:DEPENDS_ON]->(pk:Package)
RETURN pk.id AS package_id, pk.name AS name, pk.version AS version,
       pk.ecosystem AS ecosystem, coalesce(pk.internal, false) AS internal,
       s.id AS service_id, coalesce(d.direct, true) AS direct
"""

NODE_LABEL_CYPHER = """
MATCH (n)
WHERE n.id IS NOT NULL
RETURN n.id AS id, labels(n)[0] AS label, coalesce(n.name, n.host, n.cve, n.id) AS name
"""


@dataclass(slots=True)
class CallEdge:
    src: str
    dst: str
    authz: str
    protocol: str
    rps: int


@dataclass(slots=True)
class ControlFact:
    id: str
    name: str
    type: str
    active: bool
    against: str
    target_id: str
    target_label: str


@dataclass(slots=True)
class Projection:
    """Everything path evaluation needs, loaded with a handful of queries."""

    graph: str
    services: dict[str, dict[str, Any]] = field(default_factory=dict)
    ingress: dict[str, dict[str, Any]] = field(default_factory=dict)
    ingress_routes: dict[str, list[str]] = field(default_factory=dict)
    service_ingress: dict[str, list[str]] = field(default_factory=dict)
    calls: list[CallEdge] = field(default_factory=list)
    calls_out: dict[str, list[CallEdge]] = field(default_factory=dict)
    stores: dict[str, dict[str, Any]] = field(default_factory=dict)
    store_access: list[tuple[str, str, str]] = field(default_factory=list)
    role_access: list[tuple[str, str, str, str]] = field(default_factory=list)
    roles: dict[str, dict[str, Any]] = field(default_factory=dict)
    controls: list[ControlFact] = field(default_factory=list)
    findings: dict[str, FindingFacts] = field(default_factory=dict)
    service_findings: dict[str, list[str]] = field(default_factory=dict)
    package_services: dict[str, set[str]] = field(default_factory=dict)
    packages: dict[str, dict[str, Any]] = field(default_factory=dict)
    names: dict[str, tuple[str, str]] = field(default_factory=dict)
    cypher_used: list[str] = field(default_factory=list)
    load_ms: float = 0.0

    def name_of(self, node_id: str) -> str:
        return self.names.get(node_id, ("Unknown", node_id))[1]

    def public_entry_ingress(self, service_id: str) -> list[dict[str, Any]]:
        return [
            self.ingress[gid]
            for gid in self.service_ingress.get(service_id, [])
            if self.ingress.get(gid, {}).get("public")
        ]

    def best_entry_authn(self, service_id: str) -> str | None:
        """The weakest authentication among public ingresses routing to a service."""
        order = ["none", "basic", "oidc"]
        authns = [str(g.get("authn") or "oidc") for g in self.public_entry_ingress(service_id)]
        if not authns:
            return None
        return sorted(authns, key=lambda a: order.index(a) if a in order else len(order))[0]

    def blocking_controls_for(self, service_id: str, cve: str) -> list[str]:
        """Active controls on the service or one of its public ingresses."""
        targets = {service_id, *self.service_ingress.get(service_id, [])}
        blockers: list[str] = []
        for control in self.controls:
            if not control.active or control.target_id not in targets:
                continue
            if control.against in ("*", cve):
                blockers.append(f"{control.name} ({control.type}, against={control.against})")
        return blockers


def _rows(cypher: str, graph: str | None) -> tuple[list[dict[str, Any]], str]:
    outcome = ro_query(cypher, None, graph=graph)
    return outcome.dicts(), outcome.cypher


def load_projection(graph: str | None = None) -> Projection:
    """Load the estate layer into memory. Bounded by the size of the estate."""
    name = graph or settings.graph_name
    started = time.perf_counter()
    proj = Projection(graph=name)

    services, cy = _rows(SERVICE_CYPHER, name)
    proj.cypher_used.append(cy)
    for row in services:
        proj.services[str(row["id"])] = row

    ingress_rows, cy = _rows(INGRESS_CYPHER, name)
    proj.cypher_used.append(cy)
    for row in ingress_rows:
        gid = str(row["ingress_id"])
        proj.ingress[gid] = {
            "id": gid,
            "host": row.get("host"),
            "public": bool(row.get("public")),
            "waf": bool(row.get("waf")),
            "authn": row.get("authn") or "none",
        }
        sid = row.get("service_id")
        if sid:
            proj.ingress_routes.setdefault(gid, []).append(str(sid))
            proj.service_ingress.setdefault(str(sid), []).append(gid)

    call_rows, cy = _rows(CALLS_CYPHER, name)
    proj.cypher_used.append(cy)
    for row in call_rows:
        edge = CallEdge(
            src=str(row["src"]),
            dst=str(row["dst"]),
            authz=str(row.get("authz") or "none"),
            protocol=str(row.get("protocol") or "http"),
            rps=int(row.get("rps") or 0),
        )
        proj.calls.append(edge)
        proj.calls_out.setdefault(edge.src, []).append(edge)

    store_rows, cy = _rows(STORE_CYPHER, name)
    proj.cypher_used.append(cy)
    for row in store_rows:
        proj.stores[str(row["id"])] = {
            "id": str(row["id"]),
            "name": row.get("name"),
            "kind": row.get("kind"),
            "classification": row.get("classification") or "internal",
            "records": int(row.get("records") or 0),
            "crown_jewel": bool(row.get("crown_jewel")),
        }

    access_rows, cy = _rows(STORE_ACCESS_CYPHER, name)
    proj.cypher_used.append(cy)
    proj.store_access = [
        (str(r["service_id"]), str(r["rel"]), str(r["store_id"])) for r in access_rows
    ]

    role_rows, cy = _rows(ROLE_ACCESS_CYPHER, name)
    proj.cypher_used.append(cy)
    for row in role_rows:
        proj.role_access.append(
            (
                str(row["service_id"]),
                str(row["role_id"]),
                str(row["store_id"]),
                str(row.get("privilege") or "read"),
            )
        )
        proj.roles[str(row["role_id"])] = {
            "id": str(row["role_id"]),
            "name": row.get("role_name"),
            "privilege": row.get("privilege"),
        }

    control_rows, cy = _rows(CONTROL_CYPHER, name)
    proj.cypher_used.append(cy)
    proj.controls = [
        ControlFact(
            id=str(r["id"]),
            name=str(r.get("name") or r["id"]),
            type=str(r.get("type") or "unknown"),
            active=bool(r.get("active")),
            against=str(r.get("against") or "*"),
            target_id=str(r.get("target_id") or ""),
            target_label=str(r.get("target_label") or ""),
        )
        for r in control_rows
    ]

    finding_rows, cy = _rows(FINDING_CYPHER, name)
    proj.cypher_used.append(cy)
    for row in finding_rows:
        facts = FindingFacts(
            finding_id=str(row["finding_id"]),
            service_id=str(row["service_id"]),
            status=str(row.get("status") or "open"),
            reachable_code=bool(row.get("reachable_code")),
            scan_id=str(row.get("scan_id") or ""),
            package_id=str(row.get("package_id") or ""),
            package_name=str(row.get("package_name") or ""),
            package_version=str(row.get("package_version") or ""),
            vuln=VulnFacts(
                cve=str(row.get("cve") or ""),
                cvss=float(row.get("cvss") or 0.0),
                epss=float(row.get("epss") or 0.0),
                kev=bool(row.get("kev")),
                attack_vector=str(row.get("attack_vector") or "network"),
                requires_auth=bool(row.get("requires_auth")),
                fixed_in=str(row.get("fixed_in") or ""),
                summary=str(row.get("summary") or ""),
            ),
        )
        proj.findings[facts.finding_id] = facts
        proj.service_findings.setdefault(facts.service_id, []).append(facts.finding_id)

    package_rows, cy = _rows(PACKAGE_USE_CYPHER, name)
    proj.cypher_used.append(cy)
    for row in package_rows:
        pid = str(row["package_id"])
        proj.packages[pid] = {
            "id": pid,
            "name": row.get("name"),
            "version": row.get("version"),
            "ecosystem": row.get("ecosystem"),
            "internal": bool(row.get("internal")),
        }
        proj.package_services.setdefault(pid, set()).add(str(row["service_id"]))

    name_rows, cy = _rows(NODE_LABEL_CYPHER, name)
    proj.cypher_used.append(cy)
    for row in name_rows:
        proj.names[str(row["id"])] = (
            str(row.get("label") or "Unknown"),
            str(row.get("name") or row["id"]),
        )

    proj.load_ms = round((time.perf_counter() - started) * 1000.0, 2)
    return proj


def candidate_paths(
    graph: str | None, max_hops: int, limit: int | None = None
) -> tuple[list[dict[str, Any]], str]:
    """Run the variable-length candidate query (PRD 7.1).

    The hop bound is interpolated because a relationship-pattern range cannot
    be parameterised in Cypher; it is clamped to an integer first so no user
    input reaches the query text.
    """
    hops = max(3, min(int(max_hops), settings.path_max_hops))
    cap = int(limit or settings.path_candidate_limit)
    # Two hops are already spent on internet -> ingress -> entry service.
    cypher = CANDIDATE_PATH_CYPHER.replace("__TAIL__", str(hops - 2))
    outcome = ro_query(cypher, {"limit": cap}, graph=graph)
    return outcome.dicts(), outcome.cypher


def clip_payload(data: Any, budget: int | None = None) -> tuple[Any, bool]:
    """Shrink a result payload until it fits the per-tool JSON budget."""
    cap = int(budget or settings.tool_payload_budget_bytes)
    truncated = False
    current = data
    for _ in range(16):
        if len(json.dumps(current, default=str)) <= cap:
            return current, truncated
        current, shrunk = _halve_longest_list(current)
        truncated = truncated or shrunk
        if not shrunk:
            break
    if len(json.dumps(current, default=str)) > cap:
        return {"note": "payload exceeded the tool budget and was dropped"}, True
    return current, truncated


def _halve_longest_list(data: Any) -> tuple[Any, bool]:
    if isinstance(data, list):
        if len(data) > 1:
            return data[: max(1, len(data) // 2)], True
        if data:
            inner, shrunk = _halve_longest_list(data[0])
            return [inner], shrunk
        return data, False
    if isinstance(data, dict):
        best_key: str | None = None
        best_len = 1
        for key, value in data.items():
            if isinstance(value, list) and len(value) > best_len:
                best_key, best_len = key, len(value)
        if best_key is not None:
            out = dict(data)
            kept = data[best_key][: max(1, best_len // 2)]
            out[best_key] = kept
            omitted = out.get("_omitted")
            out["_omitted"] = {**omitted, best_key: best_len - len(kept)} if isinstance(omitted, dict) else {best_key: best_len - len(kept)}
            return out, True
        for key, value in data.items():
            if isinstance(value, dict):
                inner, shrunk = _halve_longest_list(value)
                if shrunk:
                    out = dict(data)
                    out[key] = inner
                    return out, True
    return data, False


# Keys merged through `extra` are NOT sent to the model: the provider strips
# them. That is how a tool can stay inside the LLM payload budget and still
# hand the orchestrator a complete result for the graph and the UI.
LLM_OMITTED_KEYS: tuple[str, ...] = ("full",)


def envelope(
    *,
    summary: str,
    data: Any,
    cypher: list[str] | None = None,
    touched_ids: list[str] | None = None,
    rows: int = 0,
    latency_ms: float = 0.0,
    engine: str = "falkordb",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The uniform tool result shape from PRD 8."""
    clipped, truncated = clip_payload(data)
    ids = list(dict.fromkeys([i for i in (touched_ids or []) if i]))
    out: dict[str, Any] = {
        "summary": summary,
        "data": clipped,
        "cypher": [c.strip() for c in (cypher or []) if c and c.strip()][:8],
        "touched_ids": ids[:60],
        "rows": int(rows),
        "latency_ms": round(float(latency_ms), 2),
        "engine": engine,
    }
    if truncated:
        out["truncated"] = True
    if extra:
        out.update(extra)
    return out


def error_envelope(summary: str, *, detail: str, cypher: list[str] | None = None) -> dict[str, Any]:
    return {
        "summary": summary,
        "error": detail,
        "data": {},
        "cypher": [c.strip() for c in (cypher or []) if c],
        "touched_ids": [],
        "rows": 0,
        "latency_ms": 0.0,
        "engine": "falkordb",
    }
