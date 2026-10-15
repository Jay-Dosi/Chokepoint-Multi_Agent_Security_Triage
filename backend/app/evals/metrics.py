"""Evaluation against the planted ground truth (PRD 13).

Ground truth lives on disk, never in the graph. Both baselines and the agent
column are ranked with the same deterministic scoring the tools use, so the
comparison is apples to apples.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.db import ro_query
from app.models import ChokepointFix, EvalResponse, EvalRow, MethodMetrics
from app.seed.loader import read_ground_truth
from mcp_server.attack import Modifications, enumerate_paths, live_exploits, total_weight
from mcp_server.graph_ops import load_projection
from mcp_server.solver import find_chokepoints

log = logging.getLogger("chokepoint.evals")

TOP_N = 10
RECALL_AT = 20
COVERAGE_TARGET = 0.90
BASELINE_FIX_CAP = 30
ROW_CAP = 140

CAPTION = (
    "Ground truth is planted in a synthetic estate and read from seed/ground_truth.json, which is "
    "never written into the graph. Both baselines rank the same open findings with the same data the "
    "agent sees; only the ordering differs."
)

LATEST_INVESTIGATION_CYPHER = """
MATCH (i:Investigation)
WHERE i.status = 'done'
RETURN i.id AS id, coalesce(i.chokepoints_json, '[]') AS chokepoints_json,
       i.started_at AS started_at
ORDER BY i.started_at DESC
LIMIT 1
"""
VERDICTS_CYPHER = """
MATCH (v:Verdict)-[:ON]->(f:Finding)
RETURN f.id AS finding_id, v.kind AS kind, coalesce(v.created_at, '') AS created_at
ORDER BY v.created_at
"""
GROUNDING_CYPHER = """
MATCH (:Investigation {id: $iid})-[:PRODUCED]->(v:Verdict)
RETURN v.id AS id, coalesce(v.rationale_json, '{}') AS rationale
"""
STEP_COUNT_CYPHER = """
MATCH (i:Investigation)-[:HAS_STEP]->(s:Step)
RETURN i.id AS id, count(s) AS steps
"""


def _latest_verdicts() -> dict[str, str]:
    try:
        rows = ro_query(VERDICTS_CYPHER).dicts()
    except Exception as exc:  # noqa: BLE001
        log.warning("verdict read failed: %s", exc)
        return {}
    latest: dict[str, str] = {}
    for row in rows:
        latest[str(row["finding_id"])] = str(row.get("kind") or "")
    return latest


def _grounded_rate(investigation_id: str) -> float | None:
    if not investigation_id:
        return None
    try:
        rows = ro_query(GROUNDING_CYPHER, {"iid": investigation_id}).dicts()
    except Exception:  # noqa: BLE001
        return None
    total = 0
    grounded = 0
    for row in rows:
        try:
            rationale = json.loads(str(row.get("rationale") or "{}"))
        except json.JSONDecodeError:
            continue
        claims = ((rationale.get("grounding") or {}).get("claims")) or []
        for claim in claims:
            if isinstance(claim, dict):
                total += 1
                grounded += 1 if claim.get("grounded") else 0
    if not total:
        return None
    return round(grounded / total, 3)


def _mean_tool_calls() -> float | None:
    try:
        rows = ro_query(STEP_COUNT_CYPHER).dicts()
    except Exception:  # noqa: BLE001
        return None
    counts = [int(r.get("steps") or 0) for r in rows]
    if not counts:
        return None
    return round(sum(counts) / len(counts), 1)


def _fixes_to_target(projection: Any, ranked: list[str], baseline_weight: float) -> int:
    """How many findings from this ranking must be fixed to remove 90% of weight."""
    if baseline_weight <= 0:
        return 0
    mods = Modifications()
    for index, finding_id in enumerate(ranked[:BASELINE_FIX_CAP], start=1):
        mods.removed_findings.add(finding_id)
        remaining = total_weight(enumerate_paths(projection, mods=mods, top_k=0))
        if baseline_weight - remaining >= COVERAGE_TARGET * baseline_weight:
            return index
    return min(len(ranked), BASELINE_FIX_CAP)


def run_evaluation() -> EvalResponse:
    """Compute the three method columns and the per-finding table."""
    truth = read_ground_truth()
    exploitable = {str(f) for f in truth.get("exploitable_findings") or []}
    decoys = {str(f) for f in truth.get("decoys") or []}

    projection = load_projection()
    paths = enumerate_paths(projection, top_k=0)
    baseline_weight = total_weight(paths)
    lateral = live_exploits(projection, Modifications(), as_entry=False)
    on_path_services = {s for p in paths for s in p.services}

    best_score: dict[str, float] = {}
    for path in paths:
        for exploit in path.live_exploits:
            finding_id = str(exploit["finding_id"])
            best_score[finding_id] = max(best_score.get(finding_id, 0.0), path.breakdown.score)

    open_findings = {
        fid: facts for fid, facts in projection.findings.items() if facts.status == "open"
    }
    present_exploitable = exploitable & set(open_findings)
    present_decoys = decoys & set(open_findings)

    cvss_ranked = sorted(
        open_findings,
        key=lambda fid: (
            -open_findings[fid].vuln.cvss,
            -open_findings[fid].vuln.epss,
            fid,
        ),
    )
    kev_ranked = sorted(
        open_findings,
        key=lambda fid: (
            0 if open_findings[fid].vuln.kev else 1,
            -open_findings[fid].vuln.epss,
            -open_findings[fid].vuln.cvss,
            fid,
        ),
    )

    verdicts = _latest_verdicts()
    latest = ro_query(LATEST_INVESTIGATION_CYPHER).first() or {}
    investigation_id = str(latest.get("id") or "")
    fix_now = [fid for fid, kind in verdicts.items() if kind == "FIX_NOW" and fid in open_findings]
    chokepoint_ranked = sorted(fix_now, key=lambda fid: (-best_score.get(fid, 0.0), fid))

    try:
        agent_fixes_raw = json.loads(str(latest.get("chokepoints_json") or "[]"))
    except json.JSONDecodeError:
        agent_fixes_raw = []
    if not agent_fixes_raw:
        agent_fixes_raw = find_chokepoints(projection, max_fixes=8).fixes
    agent_fixes = [
        ChokepointFix(**{k: v for k, v in fix.items() if k in ChokepointFix.model_fields})
        for fix in agent_fixes_raw
        if isinstance(fix, dict)
    ]
    agent_fix_count = 0
    for index, fix in enumerate(agent_fixes, start=1):
        agent_fix_count = index
        if fix.cumulative_risk_removed_pct >= COVERAGE_TARGET * 100:
            break

    def metrics(method: str, label: str, ranked: list[str], *, agent: bool = False) -> MethodMetrics:
        head = ranked[:TOP_N]
        denominator = max(1, len(head))
        correct = sum(1 for fid in head if fid in present_exploitable)
        # Recall at a fixed depth: every baseline ranks the whole queue, so
        # recall over the full list would be 1.0 for all of them and say nothing.
        reached = [fid for fid in ranked[:RECALL_AT] if fid in present_exploitable]
        recall = len(reached) / len(present_exploitable) if present_exploitable else 0.0
        return MethodMetrics(
            method=method,
            label=label,
            precision_at_10=round(correct / denominator, 3),
            recall=round(recall, 3),
            decoys_in_top10=sum(1 for fid in head if fid in present_decoys),
            fixes_to_90pct=(
                agent_fix_count if agent else _fixes_to_target(projection, ranked, baseline_weight)
            ),
            ranked=head,
            grounded_claim_rate=_grounded_rate(investigation_id) if agent else None,
            mean_tool_calls=_mean_tool_calls() if agent else None,
        )

    methods = [
        metrics("cvss", "CVSS-first", cvss_ranked),
        metrics("kev_epss", "KEV/EPSS-first", kev_ranked),
        metrics("chokepoint", "CHOKEPOINT", chokepoint_ranked, agent=True),
    ]

    cvss_rank = {fid: i for i, fid in enumerate(cvss_ranked, start=1)}
    kev_rank = {fid: i for i, fid in enumerate(kev_ranked, start=1)}
    labelled = [fid for fid in cvss_ranked if fid in exploitable or fid in decoys]
    extra = [fid for fid in cvss_ranked if fid not in labelled]
    selected = (labelled + extra)[:ROW_CAP]
    rows = []
    for fid in selected:
        facts = open_findings[fid]
        rows.append(
            EvalRow(
                finding_id=fid,
                service_id=facts.service_id,
                cve=facts.vuln.cve,
                cvss=facts.vuln.cvss,
                epss=facts.vuln.epss,
                kev=facts.vuln.kev,
                ground_truth=(
                    "exploitable" if fid in exploitable else "decoy" if fid in decoys else "unlabelled"
                ),
                cvss_rank=cvss_rank.get(fid, 0),
                kev_rank=kev_rank.get(fid, 0),
                chokepoint_verdict=verdicts.get(fid, ""),
                on_attack_path=fid in best_score,
                best_path_score_pct=round(best_score.get(fid, 0.0) * 100, 1),
            )
        )
    rows.sort(key=lambda r: (r.ground_truth != "exploitable", -r.best_path_score_pct, r.cvss_rank))

    ready = bool(investigation_id and chokepoint_ranked)
    message = (
        ""
        if ready
        else (
            "No completed investigation has produced FIX_NOW verdicts yet. Run 'Triage the latest "
            "scan' and reload this page to fill the CHOKEPOINT column."
        )
    )
    live_on_path = sum(len(lateral.get(service, [])) for service in on_path_services)
    return EvalResponse(
        methods=methods,
        rows=rows,
        investigation_id=investigation_id,
        exploitable_count=len(present_exploitable),
        decoy_count=len(present_decoys),
        chokepoint_fixes=[str(f) for f in truth.get("chokepoint_fixes") or []],
        agent_fixes=agent_fixes,
        caption=(
            f"{CAPTION} {len(paths)} attack paths carry {round(baseline_weight, 3)} weighted risk and "
            f"{live_on_path} live exploits sit on them."
        ),
        ready=ready,
        message=message,
    )
