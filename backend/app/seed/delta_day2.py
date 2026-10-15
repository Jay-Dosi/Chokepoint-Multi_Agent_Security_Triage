"""The day-2 scan: scenario S7 plus the S6 follow-up.

Publishes `search.acme.example`, adds an injection finding on `search-api`
(which already calls `catalog-svc` with `authz:'none'`, and `catalog-svc`
reads `customers-pg`), and adds the `feature-lab` finding that the sandbox
lesson should downgrade.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.db import ro_query, rw_query

from . import scenarios
from .generate import package_id

log = logging.getLogger("chokepoint.seed.delta")

EXISTS_CYPHER = "MATCH (f:Finding {id: $fid}) RETURN count(f) AS c"

CREATE_INGRESS_CYPHER = """
MERGE (g:Ingress {id: $id})
SET g.host = $host, g.public = $public, g.waf = $waf, g.authn = $authn, g.created_at = $now
WITH g
MATCH (i:Internet {id: 'internet'})
MERGE (i)-[:REACHES]->(g)
WITH g
MATCH (s:Service {id: $service})
MERGE (g)-[:ROUTES_TO {path_prefix: $path_prefix}]->(s)
SET s.internet_facing = true
RETURN g.id AS id
"""

CREATE_FINDING_CYPHER = """
MATCH (s:Service {id: $service})
MATCH (v:Vulnerability {id: $cve})
MATCH (p:Package {id: $package})
MERGE (f:Finding {id: $fid})
SET f.status = $status, f.reachable_code = $reachable, f.scan_id = $scan_id,
    f.first_seen = $now, f.last_seen = $now, f.created_at = $now
MERGE (s)-[:HAS_FINDING]->(f)
MERGE (f)-[:OF]->(v)
MERGE (f)-[:VIA]->(p)
MERGE (s)-[:DEPENDS_ON {direct: true}]->(p)
MERGE (p)-[:AFFECTED_BY {fixed_in: $fixed_in}]->(v)
RETURN f.id AS id
"""

TOUCH_OPEN_FINDINGS_CYPHER = """
MATCH (f:Finding)
WHERE f.status = 'open'
SET f.last_seen = $now, f.scan_id = $scan_id
RETURN count(f) AS c
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def already_applied() -> bool:
    try:
        outcome = ro_query(EXISTS_CYPHER, {"fid": scenarios.DELTA_FINDINGS[0]["id"]})
    except Exception as exc:  # noqa: BLE001
        log.warning("could not check delta state: %s", exc)
        return False
    return int(outcome.scalar(0) or 0) > 0


def apply_delta() -> dict[str, Any]:
    """Apply the day-2 scan. Idempotent: a second call reports nothing new."""
    if already_applied():
        return {
            "applied": False,
            "scan_id": scenarios.SCAN_DAY2,
            "new_findings": [],
            "new_ingress": [],
            "message": "Day-2 scan is already applied. Reset the seed to run it again.",
        }

    now = _now()
    ingress = scenarios.DELTA_INGRESS
    rw_query(
        CREATE_INGRESS_CYPHER,
        {
            "id": ingress["id"],
            "host": ingress["host"],
            "public": bool(ingress["public"]),
            "waf": bool(ingress["waf"]),
            "authn": ingress["authn"],
            "service": ingress["service"],
            "path_prefix": ingress["path_prefix"],
            "now": now,
        },
    )

    created: list[str] = []
    for spec in scenarios.DELTA_FINDINGS:
        pkg_spec = next(p for p in scenarios.PLANTED_PACKAGES if p["name"] == spec["package"])
        vuln = next(v for v in scenarios.PLANTED_VULNERABILITIES if v["id"] == spec["cve"])
        rw_query(
            CREATE_FINDING_CYPHER,
            {
                "fid": spec["id"],
                "service": spec["service"],
                "cve": spec["cve"],
                "package": package_id(pkg_spec["name"], pkg_spec["version"]),
                "status": spec["status"],
                "reachable": bool(spec["reachable_code"]),
                "scan_id": scenarios.SCAN_DAY2,
                "fixed_in": vuln["fixed_in"],
                "now": now,
            },
        )
        created.append(str(spec["id"]))

    touched = rw_query(TOUCH_OPEN_FINDINGS_CYPHER, {"now": now, "scan_id": scenarios.SCAN_DAY2})
    log.info("day-2 delta applied: %s new findings, %s open findings re-stamped", created, touched.scalar(0))
    return {
        "applied": True,
        "scan_id": scenarios.SCAN_DAY2,
        "new_findings": created,
        "new_ingress": [str(ingress["id"])],
        "message": (
            f"Day-2 scan {scenarios.SCAN_DAY2}: {ingress['host']} is now public and routes to "
            f"{ingress['service']}; {len(created)} new findings."
        ),
    }
