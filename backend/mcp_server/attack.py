"""Attack-path enumeration and the hop predicates of PRD 7.1.

Candidate paths come from the bounded variable-length Cypher in
:mod:`mcp_server.graph_ops`; this module owns the semantics. Every path is
re-derived here against a :class:`Modifications` overlay so the chokepoint
solver and the counterfactual simulator can ask "what if" questions without
touching the graph.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterator

from .graph_ops import CallEdge, Projection, candidate_paths
from .scoring import ExploitCheck, ScoreBreakdown, evaluate_finding, score_path

log = logging.getLogger("chokepoint.attack")

CHAIN_CAP = 20000
CROWN_CLASSIFICATIONS = frozenset({"pci", "pii", "secrets"})


@dataclass(slots=True)
class Modifications:
    """A hypothetical change to the estate, applied without writing to the graph."""

    removed_findings: set[str] = field(default_factory=set)
    hardened_edges: set[tuple[str, str]] = field(default_factory=set)
    controlled_services: set[str] = field(default_factory=set)

    def is_empty(self) -> bool:
        return not (self.removed_findings or self.hardened_edges or self.controlled_services)

    def copy(self) -> "Modifications":
        return Modifications(
            removed_findings=set(self.removed_findings),
            hardened_edges=set(self.hardened_edges),
            controlled_services=set(self.controlled_services),
        )


@dataclass(slots=True)
class AttackPath:
    """One internet-to-crown-jewel route with its score components."""

    id: str
    entry: str
    entry_ingress: str
    entry_authn: str
    target: str
    target_name: str
    target_classification: str
    target_records: int
    hops: int
    services: list[str]
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    breakdown: ScoreBreakdown
    live_exploits: list[dict[str, Any]]
    mitigating_controls: list[str]
    mitigated_only: bool = False

    @property
    def score(self) -> float:
        return self.breakdown.score

    def node_ids(self) -> list[str]:
        return [n["id"] for n in self.nodes]

    def finding_ids(self) -> list[str]:
        return [e["finding_id"] for e in self.live_exploits]

    def as_dict(self, *, verbose: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "score": round(self.breakdown.score, 4),
            "score_pct": round(self.breakdown.score * 100, 1),
            "hops": self.hops,
            "entry": self.entry,
            "entry_ingress": self.entry_ingress,
            "entry_authn": self.entry_authn,
            "target": self.target,
            "target_name": self.target_name,
            "target_classification": self.target_classification,
            "target_records": self.target_records,
            "components": self.breakdown.as_dict(),
            "nodes": self.nodes,
            "edges": self.edges,
            "live_exploits": self.live_exploits,
            "mitigating_controls": self.mitigating_controls,
        }
        if self.mitigated_only:
            out["mitigated_only"] = True
        if not verbose:
            out.pop("nodes", None)
            out.pop("edges", None)
            out["node_ids"] = self.node_ids()
        return out


def _crown_jewel(store: dict[str, Any]) -> bool:
    return bool(store.get("crown_jewel")) or str(store.get("classification", "")) in CROWN_CLASSIFICATIONS


def live_exploits(
    proj: Projection,
    mods: Modifications,
    *,
    as_entry: bool,
    ignore_controls: bool = False,
) -> dict[str, list[ExploitCheck]]:
    """Live exploits per service (PRD 7.2), as entry point or after lateral movement."""
    out: dict[str, list[ExploitCheck]] = {}
    for finding_id, facts in proj.findings.items():
        if finding_id in mods.removed_findings:
            continue
        service = proj.services.get(facts.service_id)
        if service is None:
            continue
        authn = proj.best_entry_authn(facts.service_id)
        blockers = [] if ignore_controls else proj.blocking_controls_for(facts.service_id, facts.vuln.cve)
        if facts.service_id in mods.controlled_services and not ignore_controls:
            blockers = [*blockers, f"simulated virtual patch on {facts.service_id} (virtual_patch, against=*)"]
        check = evaluate_finding(
            facts,
            service_status=str(service.get("status") or "active"),
            ingress_authn=authn,
            has_ingress_route=bool(proj.public_entry_ingress(facts.service_id)),
            blocking_controls=blockers,
            allow_adjacent=not as_entry,
        )
        if check.live:
            out.setdefault(facts.service_id, []).append(check)
    for checks in out.values():
        checks.sort(key=lambda c: (-c.exploitability, c.finding_id))
    return out


def check_finding(
    proj: Projection,
    finding_id: str,
    *,
    mods: Modifications | None = None,
    allow_adjacent: bool = False,
) -> ExploitCheck | None:
    """PRD 7.2 for a single finding, for `check_exploitability`."""
    facts = proj.findings.get(finding_id)
    if facts is None:
        return None
    overlay = mods or Modifications()
    service = proj.services.get(facts.service_id, {})
    blockers = proj.blocking_controls_for(facts.service_id, facts.vuln.cve)
    if facts.service_id in overlay.controlled_services:
        blockers = [*blockers, f"simulated virtual patch on {facts.service_id}"]
    if finding_id in overlay.removed_findings:
        blockers = [*blockers, "fix already applied in this simulation"]
    return evaluate_finding(
        facts,
        service_status=str(service.get("status") or "active"),
        ingress_authn=proj.best_entry_authn(facts.service_id),
        has_ingress_route=bool(proj.public_entry_ingress(facts.service_id)),
        blocking_controls=blockers,
        allow_adjacent=allow_adjacent,
    )


def _usable_calls(proj: Projection, mods: Modifications, service_id: str) -> list[CallEdge]:
    edges = proj.calls_out.get(service_id, [])
    usable = [
        e
        for e in edges
        if e.authz != "mtls"
        and (e.src, e.dst) not in mods.hardened_edges
        and str(proj.services.get(e.dst, {}).get("status") or "") == "active"
    ]
    return sorted(usable, key=lambda e: e.dst)


def _service_chains(
    proj: Projection, mods: Modifications, entry: str, max_services: int
) -> Iterator[list[str]]:
    """Every lateral-movement chain starting at `entry`, including prefixes."""
    produced = 0
    stack: list[list[str]] = [[entry]]
    while stack:
        chain = stack.pop()
        yield chain
        produced += 1
        if produced >= CHAIN_CAP:
            log.warning("chain cap reached while expanding from %s", entry)
            return
        if len(chain) >= max_services:
            continue
        for edge in _usable_calls(proj, mods, chain[-1]):
            if edge.dst in chain:
                continue
            stack.append([*chain, edge.dst])


def _node(proj: Projection, node_id: str) -> dict[str, Any]:
    label, name = proj.names.get(node_id, ("Unknown", node_id))
    return {"id": node_id, "label": label, "name": name}


def _edge(source: str, target: str, rel: str, authz: str = "") -> dict[str, Any]:
    return {"source": source, "target": target, "type": rel, "authz": authz}


def _mitigating_controls(proj: Projection, node_ids: set[str]) -> list[str]:
    """Active controls attached to a node on the path.

    mTLS call edges cannot appear on a path at all (they are excluded by the
    lateral-movement predicate), so the discount comes from controls only.
    """
    names = []
    for control in proj.controls:
        if control.active and control.target_id in node_ids:
            names.append(f"{control.name} ({control.type}, against={control.against})")
    return sorted(set(names))


def enumerate_paths(
    proj: Projection,
    *,
    mods: Modifications | None = None,
    max_hops: int = 7,
    top_k: int = 8,
    target: str | None = None,
    include_mitigated: bool = False,
) -> list[AttackPath]:
    """All internet-to-crown-jewel paths, best first, deduplicated by entry and target."""
    overlay = mods or Modifications()
    entry_live = live_exploits(proj, overlay, as_entry=True)
    lateral_live = live_exploits(proj, overlay, as_entry=False)
    unmitigated_entries = set(entry_live)
    if include_mitigated:
        entry_live = live_exploits(proj, overlay, as_entry=True, ignore_controls=True)
        lateral_live = live_exploits(proj, overlay, as_entry=False, ignore_controls=True)

    store_reads: dict[str, list[tuple[str, str]]] = {}
    for service_id, rel, store_id in proj.store_access:
        store_reads.setdefault(service_id, []).append((rel, store_id))
    role_reads: dict[str, list[tuple[str, str, str]]] = {}
    for service_id, role_id, store_id, privilege in proj.role_access:
        role_reads.setdefault(service_id, []).append((role_id, store_id, privilege))

    # Hop budget: internet->ingress and ingress->entry use two edges, the
    # final data-store access uses one (two through an IAM role).
    max_services = max(1, max_hops - 2)
    best: dict[tuple[str, str], AttackPath] = {}

    for entry_service in sorted(entry_live):
        ingresses = [g for g in proj.public_entry_ingress(entry_service)]
        if not ingresses:
            continue
        if str(proj.services.get(entry_service, {}).get("status") or "") != "active":
            continue
        ingress = min(ingresses, key=lambda g: ("none", "basic", "oidc").index(str(g.get("authn") or "oidc")) if str(g.get("authn") or "oidc") in ("none", "basic", "oidc") else 3)
        authn = str(ingress.get("authn") or "none")
        for chain in _service_chains(proj, overlay, entry_service, max_services):
            tail = chain[-1]
            targets: list[tuple[str, str, str | None]] = []
            for rel, store_id in store_reads.get(tail, []):
                targets.append((store_id, rel, None))
            for role_id, store_id, _privilege in role_reads.get(tail, []):
                targets.append((store_id, "CAN_ACCESS", role_id))
            for store_id, rel, role_id in targets:
                store = proj.stores.get(store_id)
                if store is None or not _crown_jewel(store):
                    continue
                if target and store_id != target and str(store.get("name") or "") != target:
                    continue
                path = _build_path(
                    proj,
                    chain=chain,
                    ingress=ingress,
                    authn=authn,
                    store=store,
                    rel=rel,
                    role_id=role_id,
                    lateral_live=lateral_live,
                    max_hops=max_hops,
                )
                if path is None:
                    continue
                path.mitigated_only = include_mitigated and entry_service not in unmitigated_entries
                key = (entry_service, store_id)
                current = best.get(key)
                if current is None or path.breakdown.score > current.breakdown.score:
                    best[key] = path

    ordered = sorted(best.values(), key=lambda p: (-p.breakdown.score, p.hops, p.id))
    for index, path in enumerate(ordered, start=1):
        path.id = f"AP-{index:03d}-{path.entry}-{path.target}"
    return ordered[: max(1, top_k)] if top_k else ordered


def _build_path(
    proj: Projection,
    *,
    chain: list[str],
    ingress: dict[str, Any],
    authn: str,
    store: dict[str, Any],
    rel: str,
    role_id: str | None,
    lateral_live: dict[str, list[ExploitCheck]],
    max_hops: int,
) -> AttackPath | None:
    internet_id = "internet"
    node_ids = [internet_id, str(ingress["id"]), *chain]
    edges = [
        _edge(internet_id, str(ingress["id"]), "REACHES"),
        _edge(str(ingress["id"]), chain[0], "ROUTES_TO"),
    ]
    for src, dst in zip(chain, chain[1:], strict=False):
        edge = next((e for e in proj.calls_out.get(src, []) if e.dst == dst), None)
        edges.append(_edge(src, dst, "CALLS", edge.authz if edge else "none"))
    if role_id:
        node_ids.append(role_id)
        edges.append(_edge(chain[-1], role_id, "ASSUMES"))
        edges.append(_edge(role_id, str(store["id"]), "CAN_ACCESS"))
    else:
        edges.append(_edge(chain[-1], str(store["id"]), rel))
    node_ids.append(str(store["id"]))

    hops = len(edges)
    if hops > max_hops:
        return None

    exploits: list[dict[str, Any]] = []
    for service_id in chain:
        for check in lateral_live.get(service_id, []):
            facts = proj.findings.get(check.finding_id)
            exploits.append(
                {
                    "finding_id": check.finding_id,
                    "service_id": service_id,
                    "cve": check.cve,
                    "cvss": facts.vuln.cvss if facts else 0.0,
                    "epss": facts.vuln.epss if facts else 0.0,
                    "kev": facts.vuln.kev if facts else False,
                    "package": f"{facts.package_name}@{facts.package_version}" if facts else "",
                    "exploitability": round(check.exploitability, 4),
                }
            )
    if not exploits:
        return None
    exploits.sort(key=lambda e: (-float(e["exploitability"]), str(e["finding_id"])))
    exploitability = float(exploits[0]["exploitability"])

    controls = _mitigating_controls(proj, set(node_ids))
    breakdown = score_path(
        exploitability=exploitability,
        authn=authn,
        classification=str(store.get("classification") or "internal"),
        records=int(store.get("records") or 0),
        hops=hops,
        mitigations=len(controls),
    )
    return AttackPath(
        id=f"AP-{chain[0]}-{store['id']}",
        entry=chain[0],
        entry_ingress=str(ingress["id"]),
        entry_authn=authn,
        target=str(store["id"]),
        target_name=str(store.get("name") or store["id"]),
        target_classification=str(store.get("classification") or "internal"),
        target_records=int(store.get("records") or 0),
        hops=hops,
        services=list(chain),
        nodes=[_node(proj, nid) for nid in node_ids],
        edges=edges,
        breakdown=breakdown,
        live_exploits=exploits[:6],
        mitigating_controls=controls,
    )


def cypher_candidates(proj: Projection, max_hops: int) -> tuple[int, str]:
    """Run the documented candidate query so its row count and text are reported."""
    try:
        rows, cypher = candidate_paths(proj.graph, max_hops)
        return len(rows), cypher
    except Exception as exc:  # noqa: BLE001 - candidate prefilter is advisory only
        log.warning("candidate path query failed, using in-process enumeration: %s", exc)
        return 0, ""


def reachable_set(
    proj: Projection, start: str, *, max_hops: int = 4, mods: Modifications | None = None
) -> dict[str, int]:
    """Breadth-first lateral reach over usable CALLS edges, depth per service."""
    overlay = mods or Modifications()
    depths = {start: 0}
    frontier = [start]
    for depth in range(1, max_hops + 1):
        nxt: list[str] = []
        for service_id in frontier:
            for edge in _usable_calls(proj, overlay, service_id):
                if edge.dst not in depths:
                    depths[edge.dst] = depth
                    nxt.append(edge.dst)
        frontier = nxt
        if not frontier:
            break
    return depths


def total_weight(paths: list[AttackPath]) -> float:
    return sum(p.breakdown.score for p in paths)
