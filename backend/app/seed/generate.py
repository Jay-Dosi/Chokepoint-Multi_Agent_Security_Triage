"""Deterministic estate generator.

Planted facts come from :mod:`app.seed.scenarios`; filler is generated from a
fixed RNG seed so ids are stable between runs. Filler never creates an attack
path: filler services have no public ingress, only mTLS call edges and no
crown-jewel access, and filler findings on planted services always have
`reachable_code` false.
"""

from __future__ import annotations

import json
import logging
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.config import settings
from app.db import delete_graph, rw_query

from . import scenarios
from .schema import ensure_indexes

log = logging.getLogger("chokepoint.seed.generate")

RNG_SEED = 1337
TARGET_FINDINGS = 320
TARGET_FILLER_VULNS = 24
WEAKNESS_CLASSES = (
    "deserialisation of untrusted input",
    "path traversal in archive extraction",
    "improper certificate validation",
    "uncontrolled resource consumption",
    "server-side request forgery in the URL handler",
    "improper neutralisation of template expressions",
    "integer overflow in the length prefix parser",
    "incorrect authorisation on a batch endpoint",
)


def package_id(name: str, version: str) -> str:
    return f"pkg-{name}@{version}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _repo(service_id: str) -> str:
    return f"acme/{service_id}"


class Generator:
    """Builds the whole estate layer in a deterministic order."""

    def __init__(self, scale: int = 1, graph: str | None = None) -> None:
        self.scale = max(1, int(scale))
        self.graph = graph or settings.graph_name
        self.rng = random.Random(RNG_SEED)
        self.created_at = _now()
        self.services: dict[str, dict[str, Any]] = {}
        self.packages: dict[str, dict[str, Any]] = {}
        self.vulnerabilities: dict[str, dict[str, Any]] = {}
        self.findings: dict[str, dict[str, Any]] = {}
        self.dependencies: set[tuple[str, str, bool]] = set()
        self.affected_by: set[tuple[str, str, str]] = set()
        self.people: list[dict[str, Any]] = []
        self.on_call: list[tuple[str, str]] = []
        self.calls: list[tuple[str, str, str, str, int]] = []
        self.store_access: list[tuple[str, str, str]] = []
        self.filler_vuln_ids: list[str] = []

    # --- model building ----------------------------------------------------

    def build(self) -> None:
        self._build_services()
        self._build_packages_and_vulns()
        self._build_people()
        self._build_calls()
        self._build_store_access()
        self._build_planted_findings()
        self._build_filler_findings()

    def _build_services(self) -> None:
        public_services = {ing["service"] for ing in scenarios.INGRESS if ing["public"]}
        for spec in scenarios.PLANTED_SERVICES:
            sid = str(spec["id"])
            self.services[sid] = {
                "id": sid,
                "name": spec.get("name", sid),
                "repo": _repo(sid),
                "language": spec["language"],
                "tier": int(spec["tier"]),
                "status": spec.get("status", "active"),
                "internet_facing": sid in public_services,
                "env": spec.get("env", "prod"),
                "cluster": spec["cluster"],
                "team": spec["team"],
                "planted": True,
                "created_at": self.created_at,
            }
        for copy_index in range(self.scale):
            suffix = "" if copy_index == 0 else f"-{copy_index + 1}"
            for spec in scenarios.FILLER_SERVICES:
                sid = f"{spec['id']}{suffix}"
                self.services[sid] = {
                    "id": sid,
                    "name": sid,
                    "repo": _repo(sid),
                    "language": spec["language"],
                    "tier": int(spec["tier"]),
                    "status": "deprecated" if spec["id"] == "chat-relay" else "active",
                    "internet_facing": False,
                    "env": spec.get("env", "prod"),
                    "cluster": spec["cluster"],
                    "team": spec["team"],
                    "planted": False,
                    "created_at": self.created_at,
                }

    def _add_package(self, name: str, version: str, ecosystem: str, internal: bool) -> str:
        pid = package_id(name, version)
        if pid not in self.packages:
            self.packages[pid] = {
                "id": pid,
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
                "internal": internal,
                "created_at": self.created_at,
            }
        return pid

    def _build_packages_and_vulns(self) -> None:
        for spec in scenarios.PLANTED_PACKAGES:
            self._add_package(spec["name"], spec["version"], spec["ecosystem"], bool(spec["internal"]))
        for vuln in scenarios.PLANTED_VULNERABILITIES:
            self.vulnerabilities[str(vuln["id"])] = {**vuln, "created_at": self.created_at}

        pool = [*scenarios.FILLER_PACKAGE_NAMES, *scenarios.INTERNAL_FILLER_PACKAGE_NAMES]
        counter = 0
        for copy_index in range(self.scale):
            for name, version, ecosystem in pool:
                internal = name.startswith("acme-")
                pkg_name = name if copy_index == 0 else f"{name}-v{copy_index + 1}"
                pid = self._add_package(pkg_name, version, ecosystem, internal)
                counter += 1
                # Roughly a quarter of packages carry no advisory, and the
                # advisory count is capped so the vulnerability table stays
                # near the target size however many packages exist.
                if counter % 4 == 3 or len(self.filler_vuln_ids) >= TARGET_FILLER_VULNS * self.scale:
                    continue
                vuln_id = f"SYN-2026-{counter:04d}"
                cvss = [9.8, 9.1, 8.8, 8.1, 7.5, 6.5, 5.9, 5.3, 4.3][counter % 9]
                self.vulnerabilities[vuln_id] = {
                    "id": vuln_id,
                    "cve": vuln_id,
                    "cvss": cvss,
                    "epss": round(0.002 + (counter % 23) * 0.013, 4),
                    "kev": counter % 11 == 0,
                    "attack_vector": ("network", "network", "adjacent", "local")[counter % 4],
                    "requires_auth": counter % 3 == 0,
                    "fixed_in": f"{version.split('.')[0]}.99.0",
                    "summary": (
                        f"Synthetic advisory for {pkg_name}: "
                        f"{WEAKNESS_CLASSES[counter % len(WEAKNESS_CLASSES)]}."
                    ),
                    "created_at": self.created_at,
                }
                self.filler_vuln_ids.append(vuln_id)
                self.affected_by.add((pid, vuln_id, str(self.vulnerabilities[vuln_id]["fixed_in"])))

        for name, version, service_ids, direct in scenarios.PLANTED_DEPENDENCIES:
            pid = package_id(name, version)
            for sid in service_ids:
                self.dependencies.add((sid, pid, bool(direct)))

        for finding in (*scenarios.PLANTED_FINDINGS, *scenarios.DELTA_FINDINGS):
            spec = next(p for p in scenarios.PLANTED_PACKAGES if p["name"] == finding["package"])
            pid = package_id(spec["name"], spec["version"])
            vuln = self.vulnerabilities[str(finding["cve"])]
            self.affected_by.add((pid, str(finding["cve"]), str(vuln["fixed_in"])))

    def _build_people(self) -> None:
        team_ids = [t["id"] for t in scenarios.TEAMS]
        for index, (name, role) in enumerate(scenarios.PERSON_NAMES):
            team = team_ids[index % len(team_ids)]
            handle = name.lower().replace(" ", ".")
            self.people.append(
                {
                    "id": f"per-{index + 1:03d}",
                    "name": name,
                    "email": f"{handle}@acme.example",
                    "role": role,
                    "team": team,
                    "created_at": self.created_at,
                }
            )
        by_team: dict[str, list[str]] = {}
        for person in self.people:
            by_team.setdefault(str(person["team"]), []).append(str(person["id"]))
        for sid, service in sorted(self.services.items()):
            members = by_team.get(str(service["team"])) or [p["id"] for p in self.people[:2]]
            count = 2 if service["tier"] == 1 else 1
            # A stable digest keeps on-call assignment identical between runs;
            # the builtin hash() of a str is salted per process.
            digest = sum(ord(ch) * (i + 1) for i, ch in enumerate(sid))
            picks = [members[(digest + i) % len(members)] for i in range(count)]
            for person_id in dict.fromkeys(picks):
                self.on_call.append((person_id, sid))

    def _build_calls(self) -> None:
        self.calls = list(scenarios.PLANTED_CALLS)
        for copy_index in range(self.scale):
            suffix = "" if copy_index == 0 else f"-{copy_index + 1}"
            for src, dst, authz, protocol, rps in scenarios.FILLER_CALLS:
                src_id = f"{src}{suffix}" if src in {s["id"] for s in scenarios.FILLER_SERVICES} else src
                dst_id = f"{dst}{suffix}" if dst in {s["id"] for s in scenarios.FILLER_SERVICES} else dst
                if src_id in self.services and dst_id in self.services:
                    # Filler edges are always mTLS so filler can never carry a path.
                    self.calls.append((src_id, dst_id, "mtls", protocol, rps))

    def _build_store_access(self) -> None:
        self.store_access = list(scenarios.STORE_ACCESS)
        for copy_index in range(self.scale):
            suffix = "" if copy_index == 0 else f"-{copy_index + 1}"
            for service, rel, store in scenarios.FILLER_STORE_ACCESS:
                sid = f"{service}{suffix}"
                if sid in self.services:
                    self.store_access.append((sid, rel, store))

    def _build_planted_findings(self) -> None:
        for spec in scenarios.PLANTED_FINDINGS:
            pkg_spec = next(p for p in scenarios.PLANTED_PACKAGES if p["name"] == spec["package"])
            pid = package_id(pkg_spec["name"], pkg_spec["version"])
            vuln = self.vulnerabilities[str(spec["cve"])]
            self.findings[str(spec["id"])] = {
                "id": str(spec["id"]),
                "service": str(spec["service"]),
                "package": pid,
                "cve": str(spec["cve"]),
                "cvss": float(vuln["cvss"]),
                "status": str(spec["status"]),
                "reachable_code": bool(spec["reachable_code"]),
                "scan_id": scenarios.SCAN_DAY1,
                "first_seen": _iso_days_ago(21),
                "last_seen": _iso_days_ago(1),
                "planted": True,
                "created_at": self.created_at,
            }

    def _build_filler_findings(self) -> None:
        """Fill up to the target count from (service, vulnerable package) pairs."""
        target = TARGET_FINDINGS * self.scale
        vulnerable: list[tuple[str, str, str]] = sorted(self.affected_by)
        filler_pairs = [
            (pid, vid, fixed)
            for pid, vid, fixed in vulnerable
            if vid in set(self.filler_vuln_ids)
        ]
        if not filler_pairs:
            return
        service_ids = sorted(self.services)
        planted_ids = {s for s, v in self.services.items() if v["planted"]}
        pairs = [
            (service_id, pid, vid)
            for service_id in service_ids
            for pid, vid, _fixed in filler_pairs
        ]
        self.rng.shuffle(pairs)
        counter = 0
        for service_id, pid, vid in pairs:
            if len(self.findings) >= target:
                break
            if (service_id, pid, True) in self.dependencies or (service_id, pid, False) in self.dependencies:
                continue
            counter += 1
            finding_id = f"F-{1000 + counter}"
            self.dependencies.add((service_id, pid, counter % 3 != 0))
            status = ("open", "open", "open", "suppressed", "fixed")[counter % 5]
            # A filler finding on a planted service is never reachable code, so
            # it can never become a live exploit and disturb the planted story.
            reachable = False if service_id in planted_ids else counter % 3 == 0
            self.findings[finding_id] = {
                "id": finding_id,
                "service": service_id,
                "package": pid,
                "cve": vid,
                "cvss": float(self.vulnerabilities[vid]["cvss"]),
                "status": status,
                "reachable_code": reachable,
                "scan_id": scenarios.SCAN_DAY1,
                "first_seen": _iso_days_ago(10 + counter % 40),
                "last_seen": _iso_days_ago(1),
                "planted": False,
                "created_at": self.created_at,
            }

    # --- writing -----------------------------------------------------------

    def write(self) -> dict[str, Any]:
        started = time.perf_counter()
        delete_graph(self.graph)
        rw_query(
            "CREATE (:Internet {id: 'internet', name: 'internet', created_at: $now})",
            {"now": self.created_at},
            graph=self.graph,
        )
        indexes = ensure_indexes(self.graph)

        self._write_nodes()
        self._write_relationships()

        stats = self._stats()
        stats["seconds"] = round(time.perf_counter() - started, 2)
        stats["indexes"] = indexes
        stats["ground_truth_path"] = str(self._write_ground_truth())
        return stats

    def _batch(self, cypher: str, rows: list[dict[str, Any]], chunk: int = 500) -> None:
        for start in range(0, len(rows), chunk):
            rw_query(cypher, {"rows": rows[start : start + chunk]}, graph=self.graph)

    def _write_nodes(self) -> None:
        self._batch(
            "UNWIND $rows AS r CREATE (:Service {id: r.id, name: r.name, repo: r.repo, "
            "language: r.language, tier: r.tier, status: r.status, "
            "internet_facing: r.internet_facing, env: r.env, cluster: r.cluster, "
            "created_at: r.created_at})",
            [
                {k: v for k, v in service.items() if k not in ("team", "planted")}
                for service in self.services.values()
            ],
        )
        self._batch(
            "UNWIND $rows AS r CREATE (:Ingress {id: r.id, host: r.host, public: r.public, "
            "waf: r.waf, authn: r.authn, created_at: r.created_at})",
            [
                {
                    "id": ing["id"],
                    "host": ing["host"],
                    "public": bool(ing["public"]),
                    "waf": bool(ing["waf"]),
                    "authn": ing["authn"],
                    "created_at": self.created_at,
                }
                for ing in scenarios.INGRESS
            ],
        )
        self._batch(
            "UNWIND $rows AS r CREATE (:DataStore {id: r.id, name: r.name, kind: r.kind, "
            "classification: r.classification, records: r.records, crown_jewel: r.crown_jewel, "
            "created_at: r.created_at})",
            [{**store, "created_at": self.created_at} for store in scenarios.DATA_STORES],
        )
        self._batch(
            "UNWIND $rows AS r CREATE (:Package {id: r.id, name: r.name, version: r.version, "
            "ecosystem: r.ecosystem, internal: r.internal, created_at: r.created_at})",
            list(self.packages.values()),
        )
        self._batch(
            "UNWIND $rows AS r CREATE (:Vulnerability {id: r.id, cve: r.cve, cvss: r.cvss, "
            "epss: r.epss, kev: r.kev, summary: r.summary, attack_vector: r.attack_vector, "
            "requires_auth: r.requires_auth, fixed_in: r.fixed_in, created_at: r.created_at})",
            [
                {
                    "id": v["id"],
                    "cve": v["cve"],
                    "cvss": float(v["cvss"]),
                    "epss": float(v["epss"]),
                    "kev": bool(v["kev"]),
                    "summary": v["summary"],
                    "attack_vector": v["attack_vector"],
                    "requires_auth": bool(v["requires_auth"]),
                    "fixed_in": v["fixed_in"],
                    "created_at": self.created_at,
                }
                for v in self.vulnerabilities.values()
            ],
        )
        self._batch(
            "UNWIND $rows AS r CREATE (:Finding {id: r.id, status: r.status, "
            "first_seen: r.first_seen, last_seen: r.last_seen, scan_id: r.scan_id, "
            "reachable_code: r.reachable_code, created_at: r.created_at})",
            [
                {
                    "id": f["id"],
                    "status": f["status"],
                    "first_seen": f["first_seen"],
                    "last_seen": f["last_seen"],
                    "scan_id": f["scan_id"],
                    "reachable_code": bool(f["reachable_code"]),
                    "created_at": self.created_at,
                }
                for f in self.findings.values()
            ],
        )
        self._batch(
            "UNWIND $rows AS r CREATE (:IAMRole {id: r.id, name: r.name, privilege: r.privilege, "
            "created_at: r.created_at})",
            [
                {"id": role["id"], "name": role["name"], "privilege": role["privilege"], "created_at": self.created_at}
                for role in scenarios.IAM_ROLES
            ],
        )
        self._batch(
            "UNWIND $rows AS r CREATE (:Control {id: r.id, name: r.name, type: r.type, "
            "active: r.active, created_at: r.created_at})",
            [
                {
                    "id": c["id"],
                    "name": c["name"],
                    "type": c["type"],
                    "active": bool(c["active"]),
                    "created_at": self.created_at,
                }
                for c in scenarios.CONTROLS
            ],
        )
        self._batch(
            "UNWIND $rows AS r CREATE (:Team {id: r.id, name: r.name, "
            "slack_channel: r.slack_channel, created_at: r.created_at})",
            [{**team, "created_at": self.created_at} for team in scenarios.TEAMS],
        )
        self._batch(
            "UNWIND $rows AS r CREATE (:Person {id: r.id, name: r.name, email: r.email, "
            "role: r.role, created_at: r.created_at})",
            [
                {k: v for k, v in person.items() if k != "team"}
                for person in self.people
            ],
        )

    def _write_relationships(self) -> None:
        self._batch(
            "UNWIND $rows AS r MATCH (i:Internet {id: 'internet'}), (g:Ingress {id: r.id}) "
            "CREATE (i)-[:REACHES]->(g)",
            [{"id": ing["id"]} for ing in scenarios.INGRESS],
        )
        self._batch(
            "UNWIND $rows AS r MATCH (g:Ingress {id: r.ingress}), (s:Service {id: r.service}) "
            "CREATE (g)-[:ROUTES_TO {path_prefix: r.path_prefix}]->(s)",
            [
                {"ingress": ing["id"], "service": ing["service"], "path_prefix": ing["path_prefix"]}
                for ing in scenarios.INGRESS
            ],
        )
        self._batch(
            "UNWIND $rows AS r MATCH (a:Service {id: r.src}), (b:Service {id: r.dst}) "
            "CREATE (a)-[:CALLS {authz: r.authz, protocol: r.protocol, rps: r.rps}]->(b)",
            [
                {"src": src, "dst": dst, "authz": authz, "protocol": protocol, "rps": rps}
                for src, dst, authz, protocol, rps in self.calls
            ],
        )
        for rel in ("READS_FROM", "WRITES_TO"):
            self._batch(
                f"UNWIND $rows AS r MATCH (s:Service {{id: r.service}}), (d:DataStore {{id: r.store}}) "
                f"CREATE (s)-[:{rel}]->(d)",
                [
                    {"service": service, "store": store}
                    for service, access, store in self.store_access
                    if access == rel
                ],
            )
        self._batch(
            "UNWIND $rows AS r MATCH (s:Service {id: r.service}), (ro:IAMRole {id: r.role}) "
            "CREATE (s)-[:ASSUMES]->(ro)",
            [
                {"service": role["service"], "role": role["id"]}
                for role in scenarios.IAM_ROLES
                if role["service"] in self.services
            ],
        )
        self._batch(
            "UNWIND $rows AS r MATCH (ro:IAMRole {id: r.role}), (d:DataStore {id: r.store}) "
            "CREATE (ro)-[:CAN_ACCESS]->(d)",
            [
                {"role": role["id"], "store": store}
                for role in scenarios.IAM_ROLES
                for store in role["stores"]
            ],
        )
        self._batch(
            "UNWIND $rows AS r MATCH (s:Service {id: r.service}), (p:Package {id: r.package}) "
            "CREATE (s)-[:DEPENDS_ON {direct: r.direct}]->(p)",
            [
                {"service": service, "package": package, "direct": bool(direct)}
                for service, package, direct in sorted(self.dependencies)
                if service in self.services and package in self.packages
            ],
        )
        package_edges = []
        for parent, child in scenarios.PACKAGE_DEPENDENCIES:
            parent_spec = next((p for p in scenarios.PLANTED_PACKAGES if p["name"] == parent), None)
            child_spec = next((p for p in scenarios.PLANTED_PACKAGES if p["name"] == child), None)
            if parent_spec and child_spec:
                package_edges.append(
                    {
                        "parent": package_id(parent_spec["name"], parent_spec["version"]),
                        "child": package_id(child_spec["name"], child_spec["version"]),
                    }
                )
        self._batch(
            "UNWIND $rows AS r MATCH (a:Package {id: r.parent}), (b:Package {id: r.child}) "
            "CREATE (a)-[:DEPENDS_ON {direct: true}]->(b)",
            package_edges,
        )
        self._batch(
            "UNWIND $rows AS r MATCH (p:Package {id: r.package}), (v:Vulnerability {id: r.vuln}) "
            "CREATE (p)-[:AFFECTED_BY {fixed_in: r.fixed_in}]->(v)",
            [
                {"package": pid, "vuln": vid, "fixed_in": fixed}
                for pid, vid, fixed in sorted(self.affected_by)
                if pid in self.packages
            ],
        )
        self._batch(
            "UNWIND $rows AS r MATCH (s:Service {id: r.service}), (f:Finding {id: r.finding}) "
            "CREATE (s)-[:HAS_FINDING]->(f)",
            [{"service": f["service"], "finding": f["id"]} for f in self.findings.values()],
        )
        self._batch(
            "UNWIND $rows AS r MATCH (f:Finding {id: r.finding}), (v:Vulnerability {id: r.vuln}) "
            "CREATE (f)-[:OF]->(v)",
            [{"finding": f["id"], "vuln": f["cve"]} for f in self.findings.values()],
        )
        self._batch(
            "UNWIND $rows AS r MATCH (f:Finding {id: r.finding}), (p:Package {id: r.package}) "
            "CREATE (f)-[:VIA]->(p)",
            [{"finding": f["id"], "package": f["package"]} for f in self.findings.values()],
        )
        self._batch(
            "UNWIND $rows AS r MATCH (c:Control {id: r.control}), (t {id: r.target}) "
            "CREATE (c)-[:PROTECTS {against: r.against}]->(t)",
            [
                {"control": c["id"], "target": c["target"], "against": c["against"]}
                for c in scenarios.CONTROLS
            ],
        )
        self._batch(
            "UNWIND $rows AS r MATCH (t:Team {id: r.team}), (s:Service {id: r.service}) "
            "CREATE (t)-[:OWNS]->(s)",
            [{"team": service["team"], "service": sid} for sid, service in self.services.items()],
        )
        self._batch(
            "UNWIND $rows AS r MATCH (p:Person {id: r.person}), (t:Team {id: r.team}) "
            "CREATE (p)-[:MEMBER_OF]->(t)",
            [{"person": person["id"], "team": person["team"]} for person in self.people],
        )
        self._batch(
            "UNWIND $rows AS r MATCH (p:Person {id: r.person}), (s:Service {id: r.service}) "
            "CREATE (p)-[:ON_CALL_FOR]->(s)",
            [{"person": person, "service": service} for person, service in self.on_call],
        )

    def _stats(self) -> dict[str, Any]:
        nodes = (
            len(self.services)
            + len(scenarios.INGRESS)
            + len(scenarios.DATA_STORES)
            + len(self.packages)
            + len(self.vulnerabilities)
            + len(self.findings)
            + len(scenarios.IAM_ROLES)
            + len(scenarios.CONTROLS)
            + len(scenarios.TEAMS)
            + len(self.people)
            + 1
        )
        relationships = (
            len(scenarios.INGRESS) * 2
            + len(self.calls)
            + len(self.store_access)
            + len(scenarios.IAM_ROLES)
            + sum(len(r["stores"]) for r in scenarios.IAM_ROLES)
            + len(self.dependencies)
            + len(scenarios.PACKAGE_DEPENDENCIES)
            + len(self.affected_by)
            + len(self.findings) * 3
            + len(scenarios.CONTROLS)
            + len(self.services)
            + len(self.people)
            + len(self.on_call)
        )
        return {
            "graph": self.graph,
            "scale": self.scale,
            "nodes": nodes,
            "relationships": relationships,
            "findings": len(self.findings),
            "services": len(self.services),
            "packages": len(self.packages),
            "vulnerabilities": len(self.vulnerabilities),
            "scan_id": scenarios.SCAN_DAY1,
        }

    def _write_ground_truth(self) -> Path:
        """Regenerate ground_truth.json so it always matches the graph."""
        document = scenarios.ground_truth(self.findings)
        path = settings.ground_truth_file
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
            return path
        except OSError as exc:
            fallback = Path(settings.outbox_dir).parent / "ground_truth.json"
            log.warning("could not write %s (%s); writing %s instead", path, exc, fallback)
            fallback.parent.mkdir(parents=True, exist_ok=True)
            fallback.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
            return fallback


def generate(scale: int | None = None, graph: str | None = None) -> dict[str, Any]:
    """Drop and rebuild the estate layer. Returns write statistics."""
    generator = Generator(scale=scale or settings.seed_scale, graph=graph)
    generator.build()
    stats = generator.write()
    log.info(
        "seeded graph '%s' scale %s: %d services, %d packages, %d vulns, %d findings in %.2fs",
        stats["graph"],
        stats["scale"],
        stats["services"],
        stats["packages"],
        stats["vulnerabilities"],
        stats["findings"],
        stats["seconds"],
    )
    return stats
