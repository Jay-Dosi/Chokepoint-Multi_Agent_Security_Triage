"""The blackboard run loop: memory pass, Scout, Skeptic, one rebuttal, Scribe.

Agents never exchange text. Each one writes to the graph and reads the graph
back through `list_blackboard`. Every tool call becomes a `Step` node with
`TOUCHED` edges and a streamed pair of SSE events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import settings
from app.db import ro_query, rw_query
from app.events import bus

from .mcp_client import client
from .providers import ToolCall, ToolOutcome, classify, get_provider
from .providers.base import LLMProvider, for_llm

log = logging.getLogger("chokepoint.runner")

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"
REBUTTAL_CONFIDENCE = 0.55
MAX_TOUCHED_EDGES = 25
STEP_RESULT_BUDGET = 20000

CREATE_INVESTIGATION_CYPHER = """
CREATE (i:Investigation {id: $iid, goal: $goal, mode: $mode, status: 'running',
                         started_at: $now, ended_at: '', scan_id: $scan_id, model: $model,
                         preset: $preset, error: ''})
RETURN i.id AS id
"""
CREATE_STEP_CYPHER = """
MATCH (i:Investigation {id: $iid})
CREATE (s:Step {id: $sid, n: $n, agent: $agent, tool: $tool, args_json: $args,
                cypher_json: $cypher, rows: $rows, latency_ms: $latency, summary: $summary,
                touched_ids_json: $touched, engine: $engine, ok: $ok,
                result_json: $result, created_at: $now})
CREATE (i)-[:HAS_STEP]->(s)
RETURN s.id AS id
"""
LINK_TOUCHED_CYPHER = """
MATCH (s:Step {id: $sid})
UNWIND $ids AS nid
MATCH (n) WHERE n.id = nid
MERGE (s)-[:TOUCHED]->(n)
RETURN count(n) AS linked
"""
CREATE_PATH_CYPHER = """
MATCH (i:Investigation {id: $iid})
MERGE (p:AttackPath {id: $pid})
SET p.score = $score, p.hops = $hops, p.entry = $entry, p.target = $target,
    p.nodes_json = $nodes, p.edges_json = $edges, p.weight_json = $weights,
    p.findings_json = $findings, p.exploits_json = $exploits,
    p.controls_json = $controls, p.entry_ingress = $entry_ingress,
    p.entry_authn = $entry_authn, p.target_name = $target_name,
    p.target_classification = $target_classification, p.target_records = $target_records,
    p.created_at = $now
MERGE (i)-[:FOUND_PATH]->(p)
RETURN p.id AS id
"""
LINK_PATH_STEP_CYPHER = """
MATCH (p:AttackPath {id: $pid})
UNWIND $rows AS r
MATCH (n) WHERE n.id = r.id
MERGE (p)-[:STEP {idx: r.idx}]->(n)
RETURN count(n) AS linked
"""
FINISH_INVESTIGATION_CYPHER = """
MATCH (i:Investigation {id: $iid})
SET i.status = $status, i.ended_at = $now, i.duration_ms = $duration,
    i.snapshot_json = $snapshot, i.chokepoints_json = $chokepoints,
    i.simulation_json = $simulation, i.memory_json = $memory, i.error = $error
RETURN i.id AS id
"""
WEAKEN_HYPOTHESIS_CYPHER = """
MATCH (h:Hypothesis {id: $hid})
SET h.status = 'weakened'
RETURN h.id AS id, h.status AS status
"""
USED_LESSON_CYPHER = """
MATCH (i:Investigation {id: $iid})
MATCH (l:Lesson {id: $lid})
MERGE (i)-[u:USED_LESSON]->(l)
SET u.influence = $influence, l.uses = coalesce(l.uses, 0) + 1
RETURN l.id AS id
"""
LATEST_SCAN_CYPHER = """
MATCH (f:Finding)
WHERE f.status = 'open'
RETURN f.scan_id AS scan_id, count(f) AS c
ORDER BY c DESC
LIMIT 1
"""
OPEN_FINDINGS_CYPHER = "MATCH (f:Finding) WHERE f.status = 'open' RETURN f.id AS id ORDER BY f.id"
CROWN_CYPHER = "MATCH (d:DataStore) WHERE d.crown_jewel = true RETURN d.id AS id, d.name AS name"

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_prompt(name: str) -> str:
    path = PROMPT_DIR / f"{name}.md"
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:  # noqa: BLE001 - prompts ship with the image
        log.error("prompt %s unreadable: %s", path, exc)
        return f"You are {name}. Use the tools you were given and never state a number a tool did not return."


def next_investigation_id() -> str:
    outcome = ro_query("MATCH (i:Investigation) RETURN count(i) AS c")
    return f"INV-{int(outcome.scalar(0) or 0) + 1:04d}"


def current_scan_id() -> str:
    try:
        row = ro_query(LATEST_SCAN_CYPHER).first()
    except Exception:  # noqa: BLE001
        return ""
    return str((row or {}).get("scan_id") or "")


def create_investigation(goal: str, preset: str) -> dict[str, str]:
    """Create the Investigation node so the UI can open it immediately."""
    iid = next_investigation_id()
    mode = settings.effective_mode
    rw_query(
        CREATE_INVESTIGATION_CYPHER,
        {
            "iid": iid,
            "goal": goal.strip(),
            "mode": mode,
            "now": _now(),
            "scan_id": current_scan_id(),
            "model": settings.anthropic_model if mode == "live" else "scripted",
            "preset": preset or classify(goal, ""),
        },
    )
    return {"id": iid, "mode": mode, "status": "running"}


class Investigation:
    """One run. Owns step numbering, event emission and the phase sequence."""

    def __init__(self, investigation_id: str, goal: str, preset: str = "") -> None:
        self.id = investigation_id
        self.goal = goal.strip()
        self.preset = preset or classify(goal, "")
        self.provider: LLMProvider = get_provider()
        self.step_n = 0
        self.started = time.monotonic()
        self.context: dict[str, Any] = {
            "investigation_id": investigation_id,
            "goal": self.goal,
            "preset": self.preset,
            "lessons": [],
            "diff": {},
            # The orchestrator's own ledger: exact step ids for citation, which
            # does not depend on how much of list_blackboard survived clipping.
            "steps": [],
        }
        self.ledger: list[dict[str, Any]] = []
        self.paths: list[dict[str, Any]] = []
        self.chokepoints: list[dict[str, Any]] = []
        self.simulation: dict[str, Any] = {}
        self.memory_brief: dict[str, Any] = {}
        self.verdict_count = 0
        self.error = ""

    # --- plumbing ----------------------------------------------------------

    async def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        await bus.emit(self.id, event_type, payload)

    def _narrator(self, agent: str):
        async def narrate(text: str) -> None:
            await self.emit("agent_message", {"agent": agent, "text": text})

        return narrate

    def _executor(self, agent: str, role: str | None = None):
        """`agent` labels the ledger row; `role` is what the allow-list checks."""
        acting_role = role or agent

        async def execute(call: ToolCall) -> ToolOutcome:
            self.step_n += 1
            n = self.step_n
            step_id = f"{self.id}-S{n}"
            await self.emit(
                "tool_call",
                {"step_id": step_id, "n": n, "agent": agent, "tool": call.name, "args": call.args},
            )
            started = time.perf_counter()
            outcome = await client.call_tool(acting_role, call)
            elapsed = (time.perf_counter() - started) * 1000.0
            outcome.step_id = step_id
            result = outcome.result if outcome.ok else {"error": outcome.error}
            summary = str(result.get("summary") or outcome.error or "")
            cypher = [str(c) for c in (result.get("cypher") or [])]
            touched = [str(t) for t in (result.get("touched_ids") or [])]
            rows = int(result.get("rows") or 0)
            engine = str(result.get("engine") or "falkordb")
            latency = float(result.get("latency_ms") or round(elapsed, 2))
            await asyncio.to_thread(
                self._persist_step,
                step_id=step_id,
                n=n,
                agent=agent,
                tool=call.name,
                args=call.args,
                cypher=cypher,
                rows=rows,
                latency=latency,
                summary=summary,
                touched=touched,
                engine=engine,
                ok=outcome.ok,
                # The ledger stores what the agent actually saw, so the
                # grounding check cannot be satisfied by data the agent never
                # received.
                result=for_llm(result),
            )
            self.ledger.append(
                {
                    "id": step_id,
                    "n": n,
                    "agent": agent,
                    "tool": call.name,
                    "ok": outcome.ok,
                    "touched_ids": touched[:20],
                }
            )
            self.context["steps"] = self.ledger
            await self.emit(
                "tool_result",
                {
                    "step_id": step_id,
                    "n": n,
                    "agent": agent,
                    "tool": call.name,
                    "ok": outcome.ok,
                    "summary": summary,
                    "rows": rows,
                    "latency_ms": latency,
                    "cypher": cypher,
                    "touched_ids": touched,
                    "engine": engine,
                },
            )
            if not outcome.ok:
                await self.emit(
                    "error",
                    {"message": outcome.error, "step_id": step_id, "phase": agent},
                )
            else:
                await self._derive_events(agent, call, result, step_id, touched)
            return outcome

        return execute

    def _persist_step(
        self,
        *,
        step_id: str,
        n: int,
        agent: str,
        tool: str,
        args: dict[str, Any],
        cypher: list[str],
        rows: int,
        latency: float,
        summary: str,
        touched: list[str],
        engine: str,
        ok: bool,
        result: dict[str, Any],
    ) -> None:
        try:
            rw_query(
                CREATE_STEP_CYPHER,
                {
                    "iid": self.id,
                    "sid": step_id,
                    "n": n,
                    "agent": agent,
                    "tool": tool,
                    "args": json.dumps(args, default=str)[:4000],
                    "cypher": json.dumps(cypher, default=str)[:12000],
                    "rows": rows,
                    "latency": latency,
                    "summary": summary[:1200],
                    "touched": json.dumps(touched, default=str)[:6000],
                    "engine": engine,
                    "ok": bool(ok),
                    "result": json.dumps(result, default=str)[:STEP_RESULT_BUDGET],
                    "now": _now(),
                },
            )
            if touched:
                rw_query(LINK_TOUCHED_CYPHER, {"sid": step_id, "ids": touched[:MAX_TOUCHED_EDGES]})
        except Exception as exc:  # noqa: BLE001 - a failed ledger write must not stop the run
            log.warning("could not persist step %s: %s", step_id, exc)

    async def _derive_events(
        self,
        agent: str,
        call: ToolCall,
        result: dict[str, Any],
        step_id: str,
        touched: list[str],
    ) -> None:
        data = result.get("data") if isinstance(result.get("data"), dict) else {}
        full = result.get("full") if isinstance(result.get("full"), dict) else {}
        if call.name == "find_attack_paths":
            source = full.get("paths") if isinstance(full.get("paths"), list) else data.get("paths")
            paths = [p for p in (source or []) if isinstance(p, dict)]
            if paths:
                self.paths = paths
                self.context["path_exploits"] = {
                    str(p.get("id")): list(p.get("live_exploits") or []) for p in paths
                }
                self.context["live_finding_ids"] = [
                    str(e.get("finding_id"))
                    for p in paths
                    for e in (p.get("live_exploits") or [])
                    if isinstance(e, dict)
                ]
            for path in paths:
                await self.emit("path_found", {"path": path, "step_id": step_id})
        elif call.name == "find_chokepoints":
            self.chokepoints = [f for f in (data.get("fixes") or []) if isinstance(f, dict)]
            self.context["chokepoints"] = self.chokepoints
        elif call.name == "simulate_fix":
            self.simulation = dict(data)
            self.context["simulation"] = self.simulation
        elif call.name == "blast_radius":
            self.context["blast"] = {"summary": result.get("summary"), **data}
        elif call.name == "post_hypothesis":
            await self.emit(
                "hypothesis",
                {
                    "id": str(data.get("hypothesis_id") or ""),
                    "agent": agent,
                    "claim": str(data.get("claim") or call.args.get("claim") or ""),
                    "status": str(data.get("status") or "open"),
                    "confidence": float(data.get("confidence") or call.args.get("confidence") or 0.0),
                    "about_ids": [str(a) for a in call.args.get("about_ids") or []],
                    "based_on_step_ids": [str(s) for s in data.get("based_on_step_ids") or []],
                },
            )
        elif call.name == "post_challenge":
            await self.emit(
                "challenge",
                {
                    "id": str(data.get("challenge_id") or ""),
                    "kind": str(data.get("kind") or ""),
                    "claim": str(call.args.get("claim") or ""),
                    "outcome": str(data.get("outcome") or ""),
                    "hypothesis_id": str(data.get("hypothesis_id") or ""),
                    "hypothesis_claim": "",
                    "based_on_step_ids": [str(s) for s in data.get("based_on_step_ids") or []],
                },
            )
        elif call.name == "recall":
            for lesson in data.get("lessons") or []:
                if isinstance(lesson, dict):
                    await self.emit("memory_hit", dict(lesson))
                    await asyncio.to_thread(self._record_lesson_use, str(lesson.get("lesson_id") or ""), agent)
        elif call.name == "record_verdict":
            self.verdict_count += 1
            grounding = data.get("grounding") if isinstance(data.get("grounding"), dict) else {}
            await self.emit(
                "verdict",
                {
                    "id": str(data.get("verdict_id") or ""),
                    "kind": str(data.get("kind") or ""),
                    "requested_kind": str(data.get("requested_kind") or ""),
                    "confidence": float(data.get("confidence") or 0.0),
                    "grounded": bool(data.get("grounded")),
                    "safety_valve": bool((data.get("safety_valve") or {}).get("applied")),
                    "headline": str(data.get("headline") or ""),
                    "finding_ids": [str(f) for f in call.args.get("finding_ids") or []],
                    "claims": list(call.args.get("claims") or []),
                    "grounding": grounding,
                    "evidence_path_ids": [str(p) for p in data.get("evidence_path_ids") or []],
                },
            )
        elif call.name == "propose_action":
            await self.emit(
                "action_proposed",
                {
                    "id": str(data.get("action_id") or ""),
                    "kind": str(data.get("kind") or ""),
                    "status": "proposed",
                    "title": str(data.get("title") or ""),
                    "verdict_id": str(data.get("verdict_id") or ""),
                    "team": str(data.get("team") or ""),
                    "slack_channel": str(data.get("slack_channel") or ""),
                    "on_call": [str(p) for p in data.get("on_call") or []],
                    "finding_ids": [str(f) for f in data.get("finding_ids") or []],
                },
            )
        if touched and call.name not in ("post_hypothesis", "post_challenge"):
            await self.emit(
                "graph_highlight",
                {"ids": touched[:40], "reason": f"{call.name} (step {step_id.split('-S')[-1]})"},
            )

    def _record_lesson_use(self, lesson_id: str, agent: str) -> None:
        if not lesson_id:
            return
        try:
            rw_query(USED_LESSON_CYPHER, {"iid": self.id, "lid": lesson_id, "influence": agent})
        except Exception as exc:  # noqa: BLE001
            log.debug("could not record lesson use %s: %s", lesson_id, exc)

    # --- phases ------------------------------------------------------------

    async def _phase(self, phase: str, status: str) -> None:
        await self.emit("phase", {"phase": phase, "status": status})

    async def _memory_pass(self) -> None:
        await self._phase("memory", "start")
        execute = self._executor("orchestrator", role="backend")
        subjects: list[str] = []
        entities = await execute(
            ToolCall(id="mem-1", name="find_entities", args={"query": self.goal, "limit": 8})
        )
        if entities.ok:
            data = entities.result.get("data") or {}
            subjects += [
                str(m.get("id"))
                for m in (data.get("matches") or [])
                if isinstance(m, dict) and m.get("id")
            ]
        target = self._goal_target()
        if target:
            subjects.append(target)
            self.context["target"] = target

        diff = await execute(
            ToolCall(
                id="mem-2",
                name="diff_since_last",
                args={"investigation_id": self.id},
            )
        )
        diff_data = (diff.result.get("data") or {}) if diff.ok else {}
        subjects += [str(f) for f in (diff_data.get("new_findings") or [])][:6]

        recalled = await execute(
            ToolCall(
                id="mem-3",
                name="recall",
                args={
                    "subject_ids": list(dict.fromkeys(s for s in subjects if s))[:12],
                    "query_text": self.goal,
                },
            )
        )
        recall_data = (recalled.result.get("data") or {}) if recalled.ok else {}
        lessons = [lesson for lesson in (recall_data.get("lessons") or []) if isinstance(lesson, dict)]
        self.context["lessons"] = lessons
        self.context["diff"] = diff_data
        self.memory_brief = {
            "subjects": list(dict.fromkeys(s for s in subjects if s))[:12],
            "retrieval": str(recall_data.get("retrieval") or "graph + keyword"),
            "vector_search": bool(recall_data.get("vector_search")),
            "lessons": lessons,
            "past_verdicts": list(recall_data.get("past_verdicts") or [])[:10],
            "diff": _diff_summary(diff_data),
            "note": str(recalled.result.get("summary") or "") if recalled.ok else "",
        }
        narrate = self._narrator("orchestrator")
        if lessons:
            await narrate(
                f"Memory brief: {len(lessons)} lesson(s) apply, retrieved by "
                f"{self.memory_brief['retrieval']}."
            )
        else:
            await narrate("Memory brief: no lesson applies to these subjects yet.")
        if diff.ok:
            await narrate(str(diff.result.get("summary") or ""))
        await self._phase("memory", "end")

    def _goal_target(self) -> str:
        try:
            rows = ro_query(CROWN_CYPHER).dicts()
        except Exception:  # noqa: BLE001
            return ""
        lowered = self.goal.lower()
        for row in rows:
            for candidate in (str(row.get("id") or ""), str(row.get("name") or "")):
                if candidate and candidate.lower() in lowered:
                    return str(row.get("id"))
        return ""

    def _brief_text(self) -> str:
        lessons = self.context.get("lessons") or []
        diff = self.memory_brief.get("diff") or {}
        lines = [f"Goal: {self.goal}", f"Investigation id: {self.id}"]
        if lessons:
            lines.append("Memory brief - lessons that apply:")
            for lesson in lessons[:6]:
                lines.append(
                    f"- [{lesson.get('lesson_id')}] {lesson.get('text')} "
                    f"(scope {lesson.get('scope_kind')}={lesson.get('scope_value')}, "
                    f"effect {lesson.get('effect')}, retrieved by {lesson.get('why_retrieved')})"
                )
        else:
            lines.append("Memory brief: no lesson applies to these subjects yet.")
        if diff:
            lines.append(
                f"Diff against {diff.get('baseline_investigation_id') or 'no baseline'}: "
                f"{diff.get('new_paths', 0)} new path(s), {diff.get('resolved_paths', 0)} resolved, "
                f"{len(diff.get('new_findings') or [])} new finding(s)."
            )
        if self.context.get("target"):
            lines.append(f"The goal names this target: {self.context['target']}.")
        return "\n".join(lines)

    async def _run_agent(self, agent: str, prompt_name: str, budget: int, extra: str = "") -> None:
        tools = await client.tools_for(agent)
        if not tools:
            await self.emit(
                "error",
                {"message": f"no MCP tools available for {agent}", "step_id": "", "phase": agent},
            )
            return
        user = self._brief_text()
        if extra:
            user = f"{user}\n\n{extra}"
        await self.provider.run_agent(
            agent=agent,
            system=load_prompt(prompt_name),
            user=user,
            tools=tools,
            executor=self._executor(agent),
            max_tool_calls=budget,
            narrate=self._narrator(agent),
            context=dict(self.context),
        )

    async def _persist_paths(self) -> None:
        if not self.paths:
            return
        for path in self.paths[:12]:
            nodes = list(path.get("nodes") or [])
            try:
                await asyncio.to_thread(self._write_path, path, nodes)
            except Exception as exc:  # noqa: BLE001
                log.warning("could not persist path %s: %s", path.get("id"), exc)

    def _write_path(self, path: dict[str, Any], nodes: list[dict[str, Any]]) -> None:
        findings = [
            str(e.get("finding_id"))
            for e in (path.get("live_exploits") or [])
            if isinstance(e, dict)
        ]
        rw_query(
            CREATE_PATH_CYPHER,
            {
                "iid": self.id,
                "pid": str(path.get("id")),
                "score": float(path.get("score") or 0.0),
                "hops": int(path.get("hops") or 0),
                "entry": str(path.get("entry") or ""),
                "target": str(path.get("target") or ""),
                "nodes": json.dumps(nodes, default=str)[:8000],
                "edges": json.dumps(path.get("edges") or [], default=str)[:8000],
                "weights": json.dumps(path.get("components") or {}, default=str)[:2000],
                "findings": json.dumps(findings, default=str)[:2000],
                "exploits": json.dumps(path.get("live_exploits") or [], default=str)[:6000],
                "controls": json.dumps(path.get("mitigating_controls") or [], default=str)[:2000],
                "entry_ingress": str(path.get("entry_ingress") or ""),
                "entry_authn": str(path.get("entry_authn") or ""),
                "target_name": str(path.get("target_name") or ""),
                "target_classification": str(path.get("target_classification") or ""),
                "target_records": int(path.get("target_records") or 0),
                "now": _now(),
            },
        )
        rows = [
            {"id": str(node.get("id")), "idx": index}
            for index, node in enumerate(nodes)
            if node.get("id")
        ]
        if rows:
            rw_query(LINK_PATH_STEP_CYPHER, {"pid": str(path.get("id")), "rows": rows})

    async def _rebuttal_candidate(self) -> dict[str, Any] | None:
        try:
            rows = ro_query(
                """
                MATCH (:Investigation {id: $iid})-[:HAS_CHALLENGE]->(c:Challenge)-[:TARGETS]->(h:Hypothesis)
                WHERE c.outcome = 'upheld' AND h.confidence >= $floor
                OPTIONAL MATCH (h)-[:ABOUT]->(n)
                RETURN h.id AS hypothesis_id, h.claim AS claim, h.confidence AS confidence,
                       c.kind AS kind, c.claim AS challenge, collect(DISTINCT n.id) AS about_ids
                ORDER BY h.confidence DESC
                LIMIT 1
                """,
                {"iid": self.id, "floor": REBUTTAL_CONFIDENCE},
            ).first()
        except Exception as exc:  # noqa: BLE001
            log.warning("rebuttal lookup failed: %s", exc)
            return None
        if not rows:
            return None
        about = [str(a) for a in (rows.get("about_ids") or [])]
        return {
            "hypothesis_id": str(rows.get("hypothesis_id")),
            "claim": str(rows.get("claim") or ""),
            "kind": str(rows.get("kind") or ""),
            "challenge_claim": str(rows.get("challenge") or ""),
            "finding_id": next((a for a in about if a.startswith("F-")), ""),
            "service_id": next((a for a in about if not a.startswith("F-")), ""),
        }

    async def _rebuttal(self) -> None:
        candidate = await self._rebuttal_candidate()
        if candidate is None:
            return
        await self._phase("rebuttal", "start")
        self.context["phase"] = "rebuttal"
        self.context["rebuttal"] = {
            **candidate,
            "claim": candidate["challenge_claim"],
        }
        extra = (
            "A Skeptic challenge was upheld against one of your claims.\n"
            f"Your claim: {candidate['claim']}\n"
            f"Challenge ({candidate['kind']}): {candidate['challenge_claim']}\n"
            "You have four tool calls. Re-check it and either amend the claim or defend it. "
            "Post the amended claim with post_hypothesis."
        )
        await self._run_agent("scout", "scout", 4, extra=extra)
        try:
            await asyncio.to_thread(
                rw_query, WEAKEN_HYPOTHESIS_CYPHER, {"hid": candidate["hypothesis_id"]}
            )
            await self.emit(
                "hypothesis",
                {
                    "id": candidate["hypothesis_id"],
                    "agent": "scout",
                    "claim": candidate["claim"],
                    "status": "weakened",
                    "confidence": 0.0,
                    "about_ids": [],
                    "based_on_step_ids": [],
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("could not weaken hypothesis: %s", exc)
        self.context.pop("phase", None)
        await self._phase("rebuttal", "end")

    def _snapshot(self) -> str:
        try:
            findings = [str(v) for v in ro_query(OPEN_FINDINGS_CYPHER).column("id")]
        except Exception:  # noqa: BLE001
            findings = []
        paths = [
            {
                "id": str(p.get("id")),
                "entry": str(p.get("entry")),
                "target": str(p.get("target")),
                "hops": int(p.get("hops") or 0),
                "score_pct": float(p.get("score_pct") or 0.0),
            }
            for p in self.paths
        ]
        total = sum(float(p.get("score") or 0.0) for p in self.paths)
        return json.dumps(
            {"findings": findings, "paths": paths, "total_weight": round(total, 4)}, default=str
        )[:120000]

    async def run(self) -> None:
        """Memory -> Scout -> Skeptic -> Rebuttal -> Scribe, then persist."""
        status = "done"
        try:
            await client.connect()
            await self.emit(
                "run_started",
                {
                    "goal": self.goal,
                    "mode": settings.effective_mode,
                    "model": settings.anthropic_model if settings.effective_mode == "live" else "scripted",
                    "preset": self.preset,
                    "provider": self.provider.name,
                },
            )
            await self._memory_pass()

            await self._phase("scout", "start")
            await self._run_agent("scout", "scout", settings.scout_max_tool_calls)
            await self._persist_paths()
            await self._phase("scout", "end")

            await self._phase("skeptic", "start")
            await self._run_agent("skeptic", "skeptic", settings.skeptic_max_tool_calls)
            await self._phase("skeptic", "end")

            await self._rebuttal()

            await self._phase("scribe", "start")
            await self._run_agent("scribe", "scribe", settings.scribe_max_tool_calls)
            await self._phase("scribe", "end")
        except Exception as exc:  # noqa: BLE001 - a run must always finish cleanly
            status = "failed"
            self.error = f"{exc.__class__.__name__}: {exc}"
            log.exception("investigation %s failed", self.id)
            await self.emit("error", {"message": self.error, "step_id": "", "phase": "run"})

        duration = round((time.monotonic() - self.started) * 1000.0, 2)
        try:
            await asyncio.to_thread(
                rw_query,
                FINISH_INVESTIGATION_CYPHER,
                {
                    "iid": self.id,
                    "status": status,
                    "now": _now(),
                    "duration": duration,
                    "snapshot": self._snapshot(),
                    "chokepoints": json.dumps(self.chokepoints, default=str)[:40000],
                    "simulation": json.dumps(self.simulation, default=str)[:40000],
                    "memory": json.dumps(self.memory_brief, default=str)[:40000],
                    "error": self.error,
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("could not finalise investigation %s: %s", self.id, exc)
        await self.emit(
            "run_finished",
            {
                "status": status,
                "duration_ms": duration,
                "steps": self.step_n,
                "verdicts": self.verdict_count,
                "paths": len(self.paths),
                "error": self.error,
            },
        )


def _diff_summary(diff: dict[str, Any]) -> dict[str, Any]:
    baseline = diff.get("baseline") if isinstance(diff.get("baseline"), dict) else {}
    return {
        "baseline_investigation_id": str((baseline or {}).get("investigation_id") or ""),
        "new_findings": [str(f) for f in (diff.get("new_findings") or [])][:40],
        "resolved_findings": [str(f) for f in (diff.get("resolved_findings") or [])][:40],
        "unchanged_findings": len(diff.get("unchanged_findings") or []),
        "new_paths": len(diff.get("new_paths") or []),
        "resolved_paths": len(diff.get("resolved_paths") or []),
        "changed_paths": len(diff.get("changed_paths") or []),
        "current_total_weight": float(diff.get("current_total_weight") or 0.0),
        "previous_total_weight": float(diff.get("previous_total_weight") or 0.0),
    }


async def run_investigation(investigation_id: str, goal: str, preset: str = "") -> None:
    """Entry point for the background task started by POST /api/investigations."""
    await Investigation(investigation_id, goal, preset).run()
