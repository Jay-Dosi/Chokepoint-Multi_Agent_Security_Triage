# CHOKEPOINT

**Stop ranking vulnerabilities. Start cutting attack paths.**

A multi-agent security triage system whose entire context, memory, coordination and explanations
live in FalkorDB.

---

## Why a graph

1. An attack path is a path. Finding "internet → ingress → service → service → IAM role → data
   store" is a multi-hop traversal with a predicate on every hop; a table cannot express it.
2. The chokepoint question — *which smallest set of fixes removes the most risk* — is weighted set
   cover over those paths, re-evaluated on a modified graph after each pick.
3. The three agents never talk to each other. They post hypotheses, challenges and verdicts as
   nodes and read each other's work back with one query. The graph **is** the shared context.
4. Memory is graph proximity. A lesson learned from an override is attached to the nodes it applies
   to, so the next investigation finds it by walking two hops from the service in question.
5. Explanations are subgraphs. Every claim in a verdict cites the step that produced it, and every
   step records the nodes it touched, so "why" is a traversal rather than a promise.

---

## Architecture

```
┌────────────────────┐   SSE / REST    ┌───────────────────────────────┐
│  Frontend (React)  │ ◄─────────────► │  Backend (FastAPI)            │
│  Cytoscape graph   │                 │  Orchestrator                 │
│  Ledger / Dossier  │                 │   ├─ Scout   (LLM loop)       │
└────────────────────┘                 │   ├─ Skeptic (LLM loop)       │
                                       │   └─ Scribe  (LLM loop)       │
                                       │  MCP Client ──────────┐       │
                                       └───────────────────────┼───────┘
                                                               │ MCP (streamable HTTP; stdio too)
                                       ┌───────────────────────▼───────┐
                                       │  MCP Server "chokepoint-mcp"  │
                                       │  tools: read/analysis/memory/ │
                                       │         blackboard/action     │
                                       └───────────────────────┬───────┘
                                                               │ Cypher + algo.* + vector + GRAPH.COPY
                                       ┌───────────────────────▼───────┐
                                       │  FalkorDB                     │
                                       │  graph "chokepoint"           │
                                       │  (estate + reasoning + memory)│
                                       └───────────────────────────────┘
```

Two rules hold everywhere:

- **Agents never touch the database.** Every tool call goes out over MCP, and the server enforces
  the role allow-list again on arrival.
- **The model never computes a risk number.** Scores come from `mcp_server/scoring.py` and
  `mcp_server/solver.py`. The model picks tools, reads results, argues and writes the verdict.

---

## Quick start

```bash
cp .env.example .env
# Either put a key in ANTHROPIC_API_KEY, or set AGENT_MODE=scripted.
docker compose up --build
```

Then open <http://localhost:8080>.

| Service | URL |
|---|---|
| Frontend | http://localhost:8080 |
| API | http://localhost:8000/api/health |
| OpenAPI | http://localhost:8000/docs |
| MCP server | http://localhost:8765/mcp |
| FalkorDB browser | http://localhost:3000 |

The backend waits for FalkorDB, seeds the graph on first boot if it is empty, and connects to the
MCP server in the background. `make up`, `make seed`, `make delta`, `make evals`, `make logs` and
`make mcp-stdio` wrap the same operations.

**No API key?** Leave `ANTHROPIC_API_KEY` empty. `/api/health` reports it, the masthead shows a
`scripted run` badge, and the agents run a fixed per-scenario sequence of **real MCP tool calls**
against the live graph. Every number on screen still comes from the graph.

---

## Demo script

1. **Case Board.** The naive view puts the CVSS 10.0 Log4Shell in `report-renderer` at the top. The
   headline reads `<n> findings · <m> internet-reachable · <k> reach a crown jewel`, computed live.
2. Click **Triage the latest scan**. Watch `Memory → Scout → Skeptic → Rebuttal → Scribe`. The
   ledger fills; the map lights the five-hop route from `session.acme.example` to `payments-vault`.
   The Scout explains why the CVSS 10.0 is on no path at all.
3. The Skeptic challenges the `edge-gw` finding with `control_present` and the challenge is upheld,
   so that verdict is downgraded to `SCHEDULE`.
4. The Scribe issues `FIX NOW` on the session library and the reveal states how much of the
   weighted path risk the top three fixes remove. **Show simulation** gives before and after from a
   `GRAPH.COPY` run.
5. Hover a citation such as `[S4]` in a verdict claim: the ledger row and the graph nodes it touched
   highlight. Each verdict carries `GROUNDED` or `UNVERIFIED`.
6. Approve the ticket. An outbox file appears, routed to the owning team and the on-call people the
   graph resolved.
7. Override the `ml-notebooks` verdict to `ACCEPT` with a reason. A lesson appears on **Memory**.
8. **Apply day-2 scan**, then run **What changed since yesterday?**. The run reports only the delta
   and the Scribe cites the sandbox lesson when it accepts the new `feature-lab` finding.
9. **Evals**: CVSS-first and KEV/EPSS-first against CHOKEPOINT on planted ground truth.
10. **Explorer**: run the saved attack-path query. Same graph, same answer.

---

## MCP tools

21 tools, discovered at run time. `GET /api/mcp/tools` returns exactly what the agents see.

| # | Tool | Group | Roles | What it is for |
|---|---|---|---|---|
| 1 | `graph_overview` | read | scout, skeptic, scribe, backend | Counts, scan ids, public ingress, crown jewels, live headline numbers |
| 2 | `find_entities` | read | all | Resolve free text to node ids |
| 3 | `get_service_context` | read | scout, skeptic, scribe | One service in full: owners, ingress, controls, data, calls, findings |
| 4 | `list_open_findings` | read | scout, skeptic, backend | The CVSS-sorted queue: the naive view |
| 5 | `owner_of` | read | scout, skeptic, scribe | Team, channel and on-call, resolved through the graph |
| 6 | `find_attack_paths` | analysis | scout, skeptic, backend | Internet-to-crown-jewel paths with every score component |
| 7 | `blast_radius` | analysis | scout, skeptic, scribe | What one compromise reaches over non-mTLS edges |
| 8 | `check_exploitability` | analysis | scout, skeptic | Live-exploit predicates, one boolean and one reason each |
| 9 | `rank_centrality` | analysis | scout, skeptic | Betweenness or PageRank, with the engine reported |
| 10 | `find_chokepoints` | analysis | scout, skeptic, scribe, backend | Greedy weighted set cover over the path set |
| 11 | `simulate_fix` | analysis | scout, skeptic | Counterfactual on a `GRAPH.COPY`, always deleted |
| 12 | `connected_components` | analysis | scout, skeptic | WCC over the call graph: which segments cannot reach each other |
| 13 | `shortest_path` | analysis | scout, skeptic | Cheap reachability proof, including proving there is none |
| 14 | `recall` | memory | all | Lessons by graph proximity and vector similarity, plus past verdicts |
| 15 | `diff_since_last` | memory | scout, skeptic, backend | New, resolved and changed since the last completed run |
| 16 | `post_hypothesis` | blackboard | scout | One falsifiable claim with its citations |
| 17 | `post_challenge` | blackboard | skeptic | A falsification attempt, upheld or rejected |
| 18 | `list_blackboard` | blackboard | scout, skeptic, scribe | The only way an agent sees another agent's work |
| 19 | `record_verdict` | action | scribe | Decision plus grounding check plus lesson safety valve |
| 20 | `propose_action` | action | scribe | Human-approved ticket, routed through the graph |
| 21 | `record_lesson` | action | backend | Lesson write. No agent role may call it |

### Claude Desktop (stdio)

```json
{ "mcpServers": { "chokepoint": { "command": "python", "args": ["-m", "mcp_server.server", "--transport", "stdio"], "env": { "FALKORDB_HOST": "localhost", "GRAPH_NAME": "chokepoint" } } } }
```

Run it from `backend/` with FalkorDB reachable on `localhost:6379` (`docker compose up falkordb`).
`make mcp-stdio` does the same thing.

---

## Graph schema

One graph, `chokepoint`, three layers that are linked so memory retrieval can walk from a service to
past verdicts about its neighbourhood.

**Estate.** `Internet`, `Ingress`, `Service`, `Package`, `Vulnerability`, `Finding`, `DataStore`,
`IAMRole`, `Control`, `Team`, `Person`.

```
(:Internet)-[:REACHES]->(:Ingress)-[:ROUTES_TO {path_prefix}]->(:Service)
(:Service)-[:CALLS {authz, protocol, rps}]->(:Service)
(:Service)-[:READS_FROM|:WRITES_TO]->(:DataStore)
(:Service)-[:ASSUMES]->(:IAMRole)-[:CAN_ACCESS]->(:DataStore)
(:Service)-[:DEPENDS_ON {direct}]->(:Package)-[:AFFECTED_BY {fixed_in}]->(:Vulnerability)
(:Service)-[:HAS_FINDING]->(:Finding)-[:OF]->(:Vulnerability)
(:Finding)-[:VIA]->(:Package)
(:Control)-[:PROTECTS {against}]->(:Service|:Ingress)
(:Team)-[:OWNS]->(:Service)   (:Person)-[:MEMBER_OF]->(:Team)   (:Person)-[:ON_CALL_FOR]->(:Service)
```

**Reasoning.** `Investigation`, `Step`, `AttackPath`, `Hypothesis`, `Challenge`, `Verdict`,
`Action`, `Event`, joined by `HAS_STEP`, `TOUCHED`, `FOUND_PATH`, `STEP`, `HAS_HYPOTHESIS`,
`HAS_CHALLENGE`, `ABOUT`, `BASED_ON`, `TARGETS`, `PRODUCED`, `ON`, `CITES`, `EVIDENCE`,
`RESULTED_IN`, `ROUTED_TO`, `NOTIFY`, `HAS_EVENT`.

**Memory.** `Feedback`, `Lesson`, joined by `ON`, `TAUGHT`, `APPLIES_TO`, `USED_LESSON`.

### Scoring

```
exploitability = max over live exploits on the path of 0.45·epss + 0.25·(cvss/10) + 0.30·kev
exposure       = 1.0 authn none | 0.6 basic | 0.35 oidc
impact         = 0.6·classification weight + 0.4·min(1, log10(records+1)/9)
length_penalty = clamp(0.92^(hops−3), 0.5, 1.0)
control_disc   = 0.5 per active control on the path
score          = exploitability · exposure · impact · length_penalty · control_disc
```

A finding is a **live exploit** when it is open, its service is active, the vector is `network` (or
`adjacent` after lateral movement), authentication is satisfied, the vulnerable code is reached, and
no active control blocks it. Fix effort is a proxy: `upgrade_package` costs
`1 + 0.3·(services using it)`, `patch_service_dependency` 1, `harden_edge` 2, `add_control` 1.5.

---

## Evaluation and its caveat

`GET /api/evals/run` ranks the same open findings three ways and scores each against
`backend/app/seed/ground_truth.json`:

- **CVSS-first** — descending CVSS, then EPSS.
- **KEV/EPSS-first** — KEV, then EPSS, then CVSS.
- **CHOKEPOINT** — findings with a `FIX_NOW` verdict, ordered by their best attack-path score.

Metrics: precision@10 of truly exploitable findings, recall at depth 20 of the exploitable set
(every baseline ranks the whole queue, so recall over the full list would be 1.0 for all of them),
decoys in the top 10, fixes needed to remove 90% of weighted path risk, the share of verdict claims that passed
the grounding check, and mean tool calls per investigation.

**The caveat, stated plainly:** the estate is synthetic and the labels were planted when it was
generated. This measures whether path-aware ranking beats severity-first ranking *on data built to
contain that distinction*. It is an illustration of the mechanism, not a field trial. Public CVE
ids carry approximate real severity; ids beginning `ACME-` or `SYN-` are invented, as are all
internal package names.

The planted cases are S1 decoy CVSS 10.0 with no route, S2 the quiet five-hop killer, S3 the shared
internal HTTP client behind most paths, S4 a mitigated finding, S5 a decommissioned zombie, S6 a
sandbox cluster with no route to production data, and S7 the day-2 delta.

---

## Known limitations

- **Synthetic data.** No scanner integration ships. `backend/app/seed/loader.py` defines the
  `ImportedFinding` / `FindingSource` seam a CycloneDX or Trivy importer would target.
- **Heuristic effort costs.** The fix costs are proxies, not estimates from your backlog. They
  change which fix the greedy solver picks first, so treat the ordering as a hypothesis.
- **Single tenant, no auth.** Anyone who can reach the port can run an investigation and approve an
  action. There is no user model and no audit identity beyond the `by` field on feedback.
- **The LLM still writes the prose.** Numbers are checked by the grounding check, but a claim can be
  grounded and still be badly worded or beside the point.
- **Exactly one light theme.** No dark mode, and the three-pane layout wants 1280px or more.
- **Bounded search.** Paths are capped at 7 hops and the candidate query is limited, so a very large
  estate will be summarised rather than enumerated; the tool result says when it truncated.

---

## Troubleshooting

**FalkorDB is not ready yet.** The backend retries for about a minute and logs
`waiting for FalkorDB`. `docker compose logs falkordb` should end with `Ready to accept
connections`. If the port is taken, change the host side of `6379:6379`.

**`/api/health` says `mcp: false`.** The MCP container starts alongside the backend and the backend
reconnects in the background; give it a few seconds and reload. `docker compose logs mcp` should
show `chokepoint-mcp starting on streamable-http`. The health document carries the last connection
error verbatim.

**Missing API key.** `/api/health` reports `agent_mode: scripted` with a `mode_warning`, and the UI
shows a `scripted run` badge. Nothing crashes. Set `AGENT_MODE=scripted` in `.env` to make that the
intent rather than a fallback.

**Embeddings on first run.** `fastembed` downloads `BAAI/bge-small-en-v1.5` the first time a lesson
is embedded, which takes a few tens of seconds and needs network access. Without it the status
strip reads `vector memory off` and `recall` falls back to keyword matching plus graph proximity,
which is enough for the demo. Set `EMBEDDINGS=none` to skip it deliberately.

**Algorithms report `networkx`.** Procedure names differ between FalkorDB builds. The server probes
them at start-up, every algorithm has a networkx fallback, and each tool result names the `engine`
it used. The status strip shows how many ran natively.

**The graph looks wrong after experimenting.** `make seed` drops and regenerates it deterministically
and rewrites `ground_truth.json`. `make delta` applies the day-2 scan; it is idempotent.

---

## Repository layout

```
backend/app          FastAPI app, orchestrator, providers, prompts, memory, seed, evals, actions
backend/mcp_server   chokepoint-mcp: scoring, attack paths, solver, algorithms, grounding, tools
frontend/src         React 18 + Vite + Cytoscape, plain CSS with paper/ink tokens
docker-compose.yml   falkordb · mcp · backend · frontend
```

Checks you can run yourself: `make typecheck` for the frontend, `make lint` for the Python source
(both install their own tooling).
