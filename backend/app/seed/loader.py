"""Graph loading entry points and the import seam for real scanner output.

`generate` writes the synthetic estate. `load_findings` is the generic writer a
CycloneDX or Trivy importer would target: an importer only has to yield
:class:`ImportedFinding` rows, which keeps parser code out of the graph layer.
No importer ships with this build.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol

from app.config import settings
from app.db import graph_is_empty, node_count, rw_query

from . import scenarios
from .generate import generate, package_id
from .schema import ensure_indexes

log = logging.getLogger("chokepoint.seed.loader")

UPSERT_FINDING_CYPHER = """
MERGE (p:Package {id: $package_id})
  ON CREATE SET p.name = $package_name, p.version = $package_version,
                p.ecosystem = $ecosystem, p.internal = $internal, p.created_at = $now
MERGE (v:Vulnerability {id: $cve})
  ON CREATE SET v.cve = $cve, v.cvss = $cvss, v.epss = $epss, v.kev = $kev,
                v.attack_vector = $attack_vector, v.requires_auth = $requires_auth,
                v.fixed_in = $fixed_in, v.summary = $summary, v.created_at = $now
MERGE (p)-[:AFFECTED_BY {fixed_in: $fixed_in}]->(v)
WITH p, v
MATCH (s:Service {id: $service_id})
MERGE (f:Finding {id: $finding_id})
  ON CREATE SET f.first_seen = $now
SET f.status = $status, f.reachable_code = $reachable_code, f.scan_id = $scan_id,
    f.last_seen = $now, f.created_at = coalesce(f.created_at, $now)
MERGE (s)-[:HAS_FINDING]->(f)
MERGE (f)-[:OF]->(v)
MERGE (f)-[:VIA]->(p)
MERGE (s)-[:DEPENDS_ON {direct: $direct}]->(p)
RETURN f.id AS id
"""


@dataclass(slots=True)
class ImportedFinding:
    """One scanner row, already normalised. The unit an importer must produce."""

    finding_id: str
    service_id: str
    package_name: str
    package_version: str
    ecosystem: str
    cve: str
    cvss: float
    epss: float
    kev: bool
    attack_vector: str
    requires_auth: bool
    fixed_in: str
    summary: str
    status: str = "open"
    reachable_code: bool = False
    scan_id: str = ""
    direct: bool = True
    internal_package: bool = False


class FindingSource(Protocol):
    """What an importer implements. `scan_id` labels the batch."""

    scan_id: str

    def __iter__(self) -> Iterable[ImportedFinding]:  # pragma: no cover - protocol
        ...


def load_findings(source: FindingSource) -> dict[str, Any]:
    """Upsert findings from any source into the estate layer."""
    now = datetime.now(timezone.utc).isoformat()
    written: list[str] = []
    for row in source:
        rw_query(
            UPSERT_FINDING_CYPHER,
            {
                "finding_id": row.finding_id,
                "service_id": row.service_id,
                "package_id": package_id(row.package_name, row.package_version),
                "package_name": row.package_name,
                "package_version": row.package_version,
                "ecosystem": row.ecosystem,
                "internal": bool(row.internal_package),
                "cve": row.cve,
                "cvss": float(row.cvss),
                "epss": float(row.epss),
                "kev": bool(row.kev),
                "attack_vector": row.attack_vector,
                "requires_auth": bool(row.requires_auth),
                "fixed_in": row.fixed_in,
                "summary": row.summary,
                "status": row.status,
                "reachable_code": bool(row.reachable_code),
                "scan_id": row.scan_id or source.scan_id,
                "direct": bool(row.direct),
                "now": now,
            },
        )
        written.append(row.finding_id)
    return {"scan_id": source.scan_id, "findings_written": len(written), "finding_ids": written}


def reset(scale: int | None = None) -> dict[str, Any]:
    """Drop the graph and regenerate the planted estate."""
    return generate(scale=scale)


def ensure_seeded(scale: int | None = None) -> dict[str, Any]:
    """Seed only when the graph is empty, so a restart keeps existing work."""
    if graph_is_empty():
        log.info("graph '%s' is empty; seeding", settings.graph_name)
        return reset(scale)
    ensure_indexes()
    return {
        "graph": settings.graph_name,
        "scale": scale or settings.seed_scale,
        "nodes": node_count(),
        "relationships": 0,
        "findings": 0,
        "scan_id": scenarios.SCAN_DAY1,
        "seconds": 0.0,
        "ground_truth_path": str(settings.ground_truth_file),
        "indexes": {},
        "skipped": True,
    }


def read_ground_truth() -> dict[str, Any]:
    """Ground truth lives on disk, never in the graph."""
    path: Path = settings.ground_truth_file
    for candidate in (path, Path(settings.outbox_dir).parent / "ground_truth.json"):
        try:
            return json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
    log.warning("no ground_truth.json found; using the planted labels from scenarios.py")
    return scenarios.ground_truth()
