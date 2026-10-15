# CHOKEPOINT — PRD

> **Stop ranking vulnerabilities. Start cutting attack paths.**
> A multi-agent security triage system whose entire context, memory, coordination and explanations live in FalkorDB.

Hackathon track: **Agents That Act on Connected Data** (FalkorDB as the context layer).
Required focus: multi-hop reasoning · graph queries and algorithms as agent tools · tool selection through MCP · actions based on what the graph shows · explainable results.

---

## 0. How to read this document (instructions to the implementing agent)

This PRD is the single source of truth. Build **everything** described here. Where a detail is unspecified, choose the option that is more rigorous, more explainable, and less generic-looking. Do not stub features. Do not leave TODOs. Do not invent extra product surface that is not in this document.

Hard rules:
1. Every agent decision must be traceable to a graph query. No decision may rest on LLM guesswork alone.
2. The LLM never computes risk scores. Scores are computed deterministically inside tools. The LLM chooses which tools to call, interprets results, argues, and writes the verdict.
3. All agent tools are exposed through a real **MCP server** and the agents discover and call them through an **MCP client** (`list_tools` → tool schemas → Anthropic tool-use). No hard-wired function calls from the agent to the database.
4. The frontend must follow Section 12 exactly. It must not look like a generic AI-generated dashboard.

---

## 1. Product in one paragraph

Security teams drown in scanner output sorted by CVSS. A CVSS 10 in a batch job with no network path is noise; a CVSS 5 in a session library sitting between the internet and the payments vault is the breach. CHOKEPOINT models the whole estate (packages, vulnerabilities, services, ingress, call edges, IAM roles, data stores, controls, owners) as one FalkorDB graph. Three cooperating agents — **Scout**, **Skeptic**, **Scribe** — coordinate *through the graph* (a blackboard, not chat messages), enumerate real internet-to-crown-jewel attack paths, try to falsify their own conclusions, compute the **smallest set of fixes that cuts the most attack-path risk** (weighted min-cut / set cover), simulate those fixes on a copy of the graph, and then act: write verdicts, open owner-routed fix tickets (human-approved), and store what they learned. Analyst overrides become **Lessons** in the graph that change the next investigation. Every answer ships with an evidence subgraph and a step-by-step ledger the user can click through.

### The three lines for judges
- **Without the graph, this agent cannot exist.** Attack paths, chokepoints, counterfactuals, memory retrieval and agent coordination are all graph operations.
- **It acts.** Verdicts, suppressions, owner-routed tickets, all written back to the graph.
- **It shows its work and it improves.** Every claim is grounded to a tool result; every override teaches it.

---

## 2. Why this wins (mapping to the brief)

| Brief requirement | How CHOKEPOINT delivers it | Where it shows in the demo |
|---|---|---|
| Multi-hop reasoning | Internet → Ingress → Service → Service → IAM Role → DataStore paths up to 7 hops, with per-hop exploitability predicates | Attack-path ribbon above the graph |
| Graph queries and algorithms as tools | Variable-length path search, BFS blast radius, PageRank, betweenness, WCC, shortest path, weighted greedy min-cut, `GRAPH.COPY` counterfactuals | Tool Ledger rows with the Cypher shown |
| Tool selection through MCP | Dedicated MCP server with role-scoped tool allow-lists; agents discover tools at runtime; server also usable from Claude Desktop | "Tools discovered over MCP" panel and README snippet |
| Actions based on what the graph shows | `record_verdict`, `propose_action`, human approval, status writes back to graph | Dossier → Actions tab |
| Explainable results | Evidence subgraph + claim-level citations validated by a grounding checker | Verdict "Why" view; hover a citation → highlights ledger row and nodes |
| Memory across sessions | Investigations, steps, verdicts, feedback and Lessons persisted as nodes; retrieval is graph proximity + vector similarity | Memory tab; "Day 2" delta run |
| Beyond the brief | Adversarial Skeptic agent; counterfactual simulation; ground-truth eval vs CVSS baseline | Evals page |

---

## 3. Users and stories

**Primary user: AppSec / security engineer on triage duty.**
- U1. As an engineer I start an investigation with a goal ("Triage today's scan") and watch agents work live.
- U2. I see which 3 fixes remove most of the exploitable risk, with the before/after simulated.
- U3. I click any claim in a verdict and see the exact tool result and graph nodes that support it.
- U4. I override a verdict with a reason; the next related investigation uses that lesson and says so.
- U5. I approve a proposed ticket and it is routed to the owning team/on-call person found via the graph.
- U6. I inject "Day 2" scan changes and the agent reports only what changed, referencing its earlier decisions.

**Secondary: judge/evaluator.**
- J1. Understands the idea in 20 seconds from the home screen.
- J2. Can open the Evals page and see agent vs CVSS baseline on planted ground truth.
- J3. Can run read-only Cypher in the Explorer and see the same graph the agents see.

---

## 4. Architecture

```
┌────────────────────┐   SSE / REST    ┌───────────────────────────────┐
│  Frontend (React)  │ ◄─────────────► │  Backend (FastAPI)            │
│  Cytoscape graph   │                 │  Orchestrator                 │
│  Ledger / Dossier  │                 │   ├─ Scout   (LLM loop)       │
└────────────────────┘                 │   ├─ Skeptic (LLM loop)       │
                                       │   └─ Scribe  (LLM loop)       │
                                       │  MCP Client ──────────┐       │
                                       └───────────────────────┼───────┘
                                                               │ MCP (streamable HTTP; stdio also supported)
                                       ┌───────────────────────▼───────┐
                                       │  MCP Server "chokepoint-mcp"  │
                                       │  tools: read/analysis/memory/ │
                                       │         blackboard/action     │
                                       └───────────────────────┬───────┘
                                                               │ Cypher + algo.* + vector + GRAPH.COPY
                                       ┌───────────────────────▼───────┐
                                       │  FalkorDB                     │
                                       │  graph "chokepoint"           │
                                       │  (estate + memory + reasoning)│
                                       └───────────────────────────────┘
```

Stack (do not substitute):
- **FalkorDB** (docker image `falkordb/falkordb`), Python client `falkordb`.
- **Backend:** Python 3.11, FastAPI, Uvicorn, Pydantic v2, `anthropic` SDK, `mcp` Python SDK (FastMCP server + client), `networkx` (fallback algorithms only), `numpy`, optional `fastembed`.
- **Frontend:** React 18, Vite, TypeScript (strict), Zustand, Cytoscape.js + `cytoscape-fcose`, plain CSS with design tokens (CSS variables + CSS Modules). **No Tailwind, no MUI, no shadcn, no component library, no icon library.** Fonts via `@fontsource/*` packages (no CDN).
- **Orchestration:** `docker-compose.yml` with services `falkordb`, `mcp`, `backend`, `frontend` (frontend served by Nginx from the Vite build).

The same graph (`chokepoint`) holds three layers:
1. **Estate layer** – the world (services, packages, vulns, data, owners).
2. **Reasoning layer** – what agents did (investigations, steps, hypotheses, challenges, paths, verdicts, actions).
3. **Memory layer** – what was learned (feedback, lessons with embeddings).

Layers are linked, so memory retrieval can walk from a *service in the estate* to *past verdicts and lessons about its neighbourhood*.

---

## 5. Graph data model

### 5.1 Estate layer

Nodes (all have `id` string, unique per label, and `created_at` ISO string):

| Label | Key properties |
|---|---|
| `Internet` | singleton `id:"internet"` |
| `Ingress` | `host`, `public` (bool), `waf` (bool), `authn` (`none`/`basic`/`oidc`) |
| `Service` | `name`, `repo`, `language`, `tier` (1–3), `status` (`active`/`deprecated`/`decommissioned`), `internet_facing` (derived, bool), `env` (`prod`/`staging`/`sandbox`), `cluster` |
| `Package` | `name`, `version`, `ecosystem` (`maven`/`npm`/`pypi`/`go`), `internal` (bool) |
| `Vulnerability` | `cve`, `cvss` (float), `epss` (float 0–1), `kev` (bool), `summary`, `attack_vector` (`network`/`adjacent`/`local`), `requires_auth` (bool), `fixed_in` |
| `Finding` | `status` (`open`/`suppressed`/`accepted`/`fixed`), `first_seen`, `last_seen`, `scan_id`, `reachable_code` (bool: scanner says vulnerable function is called) |
| `DataStore` | `name`, `kind` (`postgres`/`s3`/`vault`/`kafka`/`redis`), `classification` (`public`/`internal`/`pii`/`pci`/`secrets`), `records` (int), `crown_jewel` (bool) |
| `IAMRole` | `name`, `privilege` (`read`/`write`/`admin`) |
| `Control` | `name`, `type` (`waf_rule`/`network_policy`/`mtls`/`virtual_patch`/`authz_middleware`), `active` (bool) |
| `Team` | `name`, `slack_channel` |
| `Person` | `name`, `email`, `role` |

Relationships:
```
(:Internet)-[:REACHES]->(:Ingress)
(:Ingress)-[:ROUTES_TO {path_prefix}]->(:Service)
(:Service)-[:CALLS {authz:'none'|'jwt'|'mtls', protocol, rps}]->(:Service)
(:Service)-[:READS_FROM|:WRITES_TO]->(:DataStore)
(:Service)-[:ASSUMES]->(:IAMRole)-[:CAN_ACCESS]->(:DataStore)
(:Service)-[:DEPENDS_ON {direct:bool}]->(:Package)
(:Package)-[:DEPENDS_ON {direct:true}]->(:Package)
(:Package)-[:AFFECTED_BY {fixed_in}]->(:Vulnerability)
(:Service)-[:HAS_FINDING]->(:Finding)-[:OF]->(:Vulnerability)
(:Finding)-[:VIA]->(:Package)
(:Control)-[:PROTECTS {against}]->(:Service|:Ingress)         // against = CVE id or '*'
(:Team)-[:OWNS]->(:Service)
(:Person)-[:MEMBER_OF]->(:Team)
(:Person)-[:ON_CALL_FOR]->(:Service)
```

### 5.2 Reasoning layer (agents write here; this is the blackboard)

```
(:Investigation {id, goal, mode, status:'running'|'done'|'failed', started_at, ended_at, scan_id, model})
(:Step {id, n, agent:'scout'|'skeptic'|'scribe', tool, args_json, cypher, rows, latency_ms, summary, touched_ids_json})
(:Investigation)-[:HAS_STEP]->(:Step)
(:Step)-[:TOUCHED]->(any estate node)                              // for click-through highlighting

(:AttackPath {id, score, hops, entry, target, nodes_json, edges_json, weight_json})
(:AttackPath)-[:STEP {idx}]->(estate node)                           // ordered path nodes
(:Hypothesis {id, agent, claim, status:'open'|'supported'|'falsified'|'weakened', confidence})
(:Hypothesis)-[:ABOUT]->(:AttackPath|:Finding|:Service)
(:Hypothesis)-[:BASED_ON]->(:Step)
(:Challenge {id, agent:'skeptic', kind:'control_present'|'edge_dead'|'service_inactive'|'auth_required'|'unreachable_code'|'prior_lesson', claim, outcome:'upheld'|'rejected'})
(:Challenge)-[:TARGETS]->(:Hypothesis)
(:Challenge)-[:BASED_ON]->(:Step)
(:Verdict {id, kind:'FIX_NOW'|'SCHEDULE'|'ACCEPT'|'SUPPRESS', confidence, rationale_json, grounded:bool, created_at})
(:Verdict)-[:ON]->(:Finding)
(:Verdict)-[:CITES {claim_id}]->(:Step)
(:Verdict)-[:EVIDENCE]->(:AttackPath)
(:Investigation)-[:PRODUCED]->(:Verdict)
(:Action {id, kind:'ticket'|'suppress'|'virtual_patch_request', status:'proposed'|'approved'|'executed'|'rejected', title, body_md, created_at})
(:Verdict)-[:RESULTED_IN]->(:Action)-[:ROUTED_TO]->(:Team)
(:Action)-[:NOTIFY]->(:Person)
```

### 5.3 Memory layer

```
(:Feedback {id, action:'agree'|'override', new_kind, note, by, at})-[:ON]->(:Verdict)
(:Lesson {id, text, scope_kind:'cluster'|'service'|'package'|'team'|'control', scope_value, effect:'downgrade'|'upgrade'|'suppress'|'require_check', strength:0..1, uses:int, embedding:vecf32[384]})
(:Feedback)-[:TAUGHT]->(:Lesson)
(:Lesson)-[:APPLIES_TO]->(:Service|:Package|:Team|:Control)
(:Investigation)-[:USED_LESSON {influence}]->(:Lesson)
```

### 5.4 Indexes (create at seed time, idempotent)
```cypher
CREATE INDEX FOR (n:Service) ON (n.id)
CREATE INDEX FOR (n:Service) ON (n.name)
CREATE INDEX FOR (n:Vulnerability) ON (n.cve)
CREATE INDEX FOR (n:Finding) ON (n.id)
CREATE INDEX FOR (n:Package) ON (n.name)
CREATE INDEX FOR (n:DataStore) ON (n.id)
CREATE INDEX FOR (n:Investigation) ON (n.id)
CREATE INDEX FOR (n:Lesson) ON (n.id)
CALL db.idx.fulltext.createNodeIndex('Service','name','repo')
CALL db.idx.fulltext.createNodeIndex('Vulnerability','cve','summary')
CREATE VECTOR INDEX FOR (l:Lesson) ON (l.embedding) OPTIONS {dimension:384, similarityFunction:'cosine'}
```
Wrap each in try/except (indexes may already exist). Embeddings are written with `vecf32($vec)` and queried with `CALL db.idx.vector.queryNodes('Lesson','embedding', $k, vecf32($q)) YIELD node, score`. If `fastembed` is not importable or `EMBEDDINGS=none`, skip the vector path and use fulltext on `Lesson.text` plus graph proximity only (log a clear warning, show "vector memory off" in the UI Memory tab).

---

## 6. Seed data (the planted story)

Generate deterministically (fixed RNG seed) with a Python generator `backend/app/seed/generate.py`, plus a hand-authored `scenarios.py` that plants the cases below. Environment is **synthetic and labelled as such in the UI footer**. Use well-known public CVE ids and approximate real CVSS values where possible (Log4Shell CVE-2021-44228, Spring4Shell CVE-2022-22965, Text4Shell CVE-2022-42889, minimist CVE-2021-44906, jsonwebtoken CVE-2022-23529, node-fetch CVE-2022-0235, HTTP/2 Rapid Reset CVE-2023-44487, etc.); invent internal package names for the planted ones.

Scale: default (`SEED_SCALE=1`): ~45 services, ~110 packages, ~40 vulnerabilities, ~320 findings, 6 crown-jewel data stores, 9 teams, ~35 people, 8 controls. `SEED_SCALE=10` produces ~10× nodes for the performance demo (the backend shows per-query latency in ms regardless).

### Planted scenarios (each has ground truth in `seed/ground_truth.json`, **never stored in the graph**)

| # | Scenario | Seeded shape | Expected correct outcome |
|---|---|---|---|
| S1 | **Decoy 10.0** | `report-renderer` (internal batch, no Ingress route, no CALLS in) has a Log4Shell-class finding, CVSS 10, KEV true | `SUPPRESS`/`SCHEDULE`, not exploitable from the internet |
| S2 | **Quiet killer** | `session-sdk@2.3` has CVSS 5.3 info-leak (network, no auth). `gateway` (public ingress, authn none on `/session`) depends on it → calls `auth-svc` with `authz:'none'` → calls `payments-api` → writes `payments-vault` (PCI, crown jewel). `auth-svc` has a second medium CVSS 6.1 pivot bug | `FIX_NOW`; path of 5 hops |
| S3 | **The chokepoint** | internal package `internal-http-client@2.x` used by 11 services; two vulns in it participate in ~70% of all weighted attack paths | `chokepoints` recommends upgrading it first; simulate shows large drop |
| S4 | **Mitigated** | CVE on `edge-gw` is virtually patched by an active `Control{type:'virtual_patch'}` `PROTECTS {against: CVE}` | Scout flags it, Skeptic proves `control_present`, verdict downgrades to `SCHEDULE` |
| S5 | **Zombie** | `legacy-export` `status:'decommissioned'`, no ingress route, no traffic, scary vulns | `SUPPRESS` via Skeptic `service_inactive` challenge |
| S6 | **Sandbox lesson** | `ml-notebooks` in `cluster:'sandbox-eu'`, reachable code true, looks bad; but there is no CALLS/ASSUMES edge from sandbox cluster to any prod DataStore | Day 1: agent says `SCHEDULE` with low confidence; analyst overrides to `ACCEPT` with note; creates Lesson. Day 2: new finding in `sandbox-eu` service `feature-lab` is auto-downgraded citing the Lesson |
| S7 | **Day-2 delta** | `POST /api/scan/delta` adds a new CVE on `search-api` (public) which `CALLS {authz:'none'}` `catalog-svc` → `customers-pg` (PII), plus a new Ingress route. Also adds a `feature-lab` finding (S6) | New path detected by diffing against previous investigation memory; reported as "NEW" |

Each service has an owner `Team`, with 1–2 on-call `Person`s so routing works.

Ground truth file format:
```json
{ "exploitable_findings": ["F-0001", "..."], "decoys": ["F-0102"], "chokepoint_fixes": ["internal-http-client@2.x"], "expected_verdicts": {"F-0001":"FIX_NOW", "...":"SUPPRESS"} }
```
Finding ids must be stable between runs.

---

## 7. Algorithms and scoring (deterministic, inside the tool layer)

### 7.1 Attack-graph semantics
A service is **compromisable-from-outside** if either:
- (a) it has an `Ingress` with `public:true` routing to it and it has ≥1 *live exploit* (Section 7.2), or
- (b) it is `CALLS`-reachable from a compromisable service over an edge where `authz != 'mtls'` (lateral movement), or the callee itself has a live exploit.

An **attack path** is an ordered chain `Internet → Ingress → Service(+) → [IAMRole] → DataStore(crown_jewel or classification in pii/pci/secrets)` where every service hop is entered via (a)/(b). Max hops default 7, returned top-K by score.

Implementation: fetch candidate paths with variable-length Cypher over `REACHES|ROUTES_TO|CALLS|READS_FROM|WRITES_TO|ASSUMES|CAN_ACCESS`, prefiltered with list predicates (`all(n IN nodes(p) WHERE NOT (n:Service AND n.status <> 'active'))` etc.), then evaluate hop predicates and compute scores in Python. Keep result sets bounded (LIMIT, parameterised). Always use parameters, never string-interpolate user input.

### 7.2 Live exploit
A `Finding` is a live exploit iff: `status='open'` AND vuln `attack_vector='network'` (or the service is reachable from a compromised neighbour for `adjacent`) AND (`requires_auth=false` OR ingress `authn='none'`) AND `reachable_code=true` AND no active `Control` with `PROTECTS {against: cve or '*'}` on the service or its ingress.
Return the reason for any negative evaluation (needed by the Skeptic and for explanations).

### 7.3 Path score
```
exploitability = max over live exploits on path of: 0.45*epss + 0.25*(cvss/10) + 0.30*(kev?1:0)
exposure       = 1.0 if ingress.authn=='none' else 0.6 if 'basic' else 0.35
impact         = classification_weight(pci=1.0, secrets=1.0, pii=0.85, internal=0.3, public=0.05) * min(1, log10(records+1)/9) blended: 0.6*weight + 0.4*scaled_records
length_penalty = 0.92 ** (hops-3) clipped to [0.5,1]
control_disc   = 0.5 per partially mitigating control on path (e.g. mtls on an edge), else 1.0
score          = exploitability * exposure * impact * length_penalty * control_disc   (0..1, display ×100)
```
Expose all components in the tool result so the UI can render the breakdown.

### 7.4 Chokepoint solver (the signature feature)
Inputs: set of attack paths `P` with weights `w(p)=score`. Candidate **fixes** `F`:
- `upgrade_package(package@version → fixed_in)`: removes every `Finding` via that package across all services. cost = 1 + 0.3·(number of distinct services using it) (effort proxy).
- `patch_service_dependency(service, package)`: removes findings for one service. cost = 1.
- `harden_edge(service→service)`: set `authz:'mtls'`. cost = 2.
- `add_control(control, service)`: virtual patch/WAF. cost = 1.5, only if a matching control type is feasible.
A fix **covers** a path if applying it makes the path no longer satisfy 7.1.
Algorithm: greedy weighted set cover — repeatedly pick the fix maximising `(sum of w(p) of uncovered paths it covers) / cost`, recompute coverage by re-evaluating path viability on the *modified* state (not just precomputed sets, so interactions are handled), stop when ≥95% of weight removed or `max_fixes=8`. Return the ordered fixes with `cumulative_risk_removed_pct`, `paths_removed`, `cost`.
Also compute **graph-theoretic corroboration**: `algo.betweenness` (or PageRank on a reversed attack subgraph) over the services on attack paths; report the top-5 central nodes and whether they coincide with the greedy picks ("structural agreement"). If a procedure is unavailable, fall back to `networkx` on the exported subgraph and set `engine:"networkx"` in the result.

### 7.5 Counterfactual simulation
`simulate_fix(fixes[])`: `g.copy('sim_<uuid>')`, apply the fixes to the copy (delete `AFFECTED_BY`/`Finding` links, set `authz:'mtls'`, add `Control`), rerun path search + scoring against the copy by pointing the same functions at that graph handle, return before/after: path count, total weight, top path score, crown jewels still reachable. **Always delete the scratch graph in a `finally`.** Never write to the real graph.

### 7.6 Capability detection
At MCP server start, run `CALL dbms.procedures() YIELD name` (or the nearest equivalent that works) and cache which `algo.*` procedures exist. Tools that use algorithms choose FalkorDB-native or networkx fallback and report `engine`. Log what was detected.

---

## 8. MCP server and tools

Server name: `chokepoint-mcp`, built with the official `mcp` Python SDK (`FastMCP`). Transports: `streamable-http` on port `8765` (default in Docker) and `stdio` via `--transport stdio`. Every tool:
- has a precise name, a strict JSON-schema (via typed args/Pydantic) and a description written *for an LLM* (when to use it, when not to);
- returns a compact JSON object: `{ "summary": str, "data": {...}, "cypher": [str], "touched_ids": [str], "rows": int, "latency_ms": float, "engine": "falkordb"|"networkx" }`;
- never returns more than ~6 KB of JSON to the LLM (truncate with an explicit `"truncated": true` and counts);
- is read-only unless in the write groups below.

**Role allow-lists** are enforced in the orchestrator *and* each tool re-checks a `role` header/arg for write tools.

### 8.1 Read & discovery (Scout, Skeptic)
1. `graph_overview()` – counts by label/relationship, scan ids, last investigation, public ingress count, crown jewels list.
2. `find_entities(query, label?, limit=10)` – fulltext lookup of Service/Vulnerability/Package by name/CVE/summary.
3. `get_service_context(service_id)` – service, owners, on-call, ingress, controls, data stores, IAM roles, one-hop CALLS in/out, open findings.
4. `list_open_findings(scan_id?, service_id?, min_cvss?, limit=25)` – baseline listing (sorted by CVSS: this is the *naive view* the agents are expected to look past).
5. `owner_of(node_id)` – team, slack channel, on-call people, via graph.

### 8.2 Analysis (Scout, Skeptic)
6. `find_attack_paths(target?, max_hops=7, top_k=8, include_mitigated=false)` – Section 7.1/7.3; returns paths with node/edge lists and score components. Persists nothing.
7. `blast_radius(service_id, max_hops=4)` – BFS (`algo.BFS` or variable-length) from a service: reachable services/data stores/roles with classification and a summary of crown jewels reachable.
8. `check_exploitability(finding_id)` – Section 7.2 with explicit boolean breakdown and reason strings (reachable code, auth, network vector, control present, service active, ingress route exists).
9. `rank_centrality(scope='attack_paths'|'services', algorithm='betweenness'|'pagerank')` – algorithm tool with engine reporting.
10. `find_chokepoints(max_fixes=8)` – Section 7.4.
11. `simulate_fix(fixes[])` – Section 7.5.
12. `connected_components(scope)` – WCC on the CALLS graph to show isolated segments (used to justify S6).
13. `shortest_path(from_id, to_id, rel_types?)` – shortest path between two nodes for explanations.

### 8.3 Memory (Scout, Skeptic, Scribe)
14. `recall(subject_ids[], query_text)` – hybrid retrieval: (a) lessons `APPLIES_TO` nodes within 2 hops of subjects (graph proximity), (b) vector similarity on `query_text` if enabled; merge, de-duplicate, return `lesson_id, text, effect, scope, strength, why_retrieved` (`'graph'|'vector'|'both'`), and the past verdicts on the same findings/services with feedback.
15. `diff_since_last(scan_id)` – compare current open findings and attack paths with those stored from the most recent completed investigation; return `new`, `resolved`, `changed`.

### 8.4 Blackboard writes (role-scoped)
16. `post_hypothesis(investigation_id, claim, about_ids[], based_on_step_ids[], confidence)` – Scout.
17. `post_challenge(investigation_id, hypothesis_id, kind, claim, based_on_step_ids[], outcome)` – Skeptic.
18. `list_blackboard(investigation_id)` – all agents: hypotheses, paths, challenges, current statuses.

### 8.5 Verdicts and actions (Scribe)
19. `record_verdict(investigation_id, finding_ids[], kind, confidence, claims[])` – `claims` is a list of `{id, text, cites: [step_id], node_ids: [..]}`. Runs the **grounding check** (Section 9.5), stores `Verdict`, `CITES`, `EVIDENCE`, sets `grounded`. Does *not* change `Finding.status` until approved.
20. `propose_action(verdict_id, kind, title, body_md)` – creates `Action{status:'proposed'}`, routes to the owner team and on-call people via graph. Ticket body is Markdown with: what, why (attack path in text), fix, blast radius, simulated risk reduction, how to verify.
21. `record_lesson(...)` – **not** exposed to agents; used by backend when an analyst overrides.

### 8.6 Tool-selection transparency
The backend exposes `GET /api/mcp/tools` returning tools discovered live from the MCP server (name, description, group, allowed roles). The UI shows these in a "Toolbelt" panel, marking which were used in the current investigation.

---

## 9. Agents

All agents use the Anthropic Messages API with tool use. Model from env `ANTHROPIC_MODEL` (default `claude-sonnet-5-5`). Temperature low (0.2). Use prompt caching on the system prompt and tool list. Parallel tool calls allowed. Hard limits: Scout 14 tool calls, Skeptic 10, Scribe 8, each with a wall-clock timeout. Every tool call, success or error, is written to the graph as a `Step` (with `TOUCHED` edges) and streamed to the UI.

### 9.1 Orchestration (blackboard pattern)
```
Investigation(goal)
 1. Memory pass (programmatic, before agents): recall() on subjects derived from the goal + diff_since_last → inject a "Memory brief" into Scout's context. Record USED_LESSON edges when a lesson influences an outcome.
 2. Scout   – explore → find_attack_paths → check_exploitability → find_chokepoints → simulate_fix → post_hypothesis (one per candidate path/finding)
 3. Skeptic – list_blackboard → for each open hypothesis, try to FALSIFY with targeted tools; post_challenge with outcome upheld/rejected
 4. Rebuttal (≤1 round) – if any challenge is upheld against a hypothesis the Scout rated high, orchestrator re-opens Scout with only that challenge and 4 tool calls; Scout may amend hypothesis (status 'weakened' or keeps 'supported')
 5. Scribe  – list_blackboard → decide verdict per finding group → record_verdict (with claims) → propose_action
```
Agents never receive each other's chat text. They only see the blackboard (graph) via `list_blackboard`. This is the central design claim: *shared context is the graph*.

### 9.2 Scout system prompt (store as a file `prompts/scout.md`)
Must instruct (write full prose, not a stub):
- Role: find real, multi-hop, internet-to-crown-jewel risk; treat CVSS order as a distraction, not a plan.
- Begin from the Memory brief and `graph_overview`; always prefer `find_attack_paths` and `check_exploitability` over `list_open_findings`.
- For each candidate finding verify exploitability explicitly before claiming it matters.
- Run `find_chokepoints` and `simulate_fix` for the best fix set and report numbers exactly as returned.
- Post hypotheses as one-sentence falsifiable claims, each with `based_on_step_ids` it actually used.
- Never state a number that is not in a tool result. If a tool errors, say so and adapt.
- Stop when the top paths and best fix set are established; do not exhaustively enumerate.

### 9.3 Skeptic system prompt (`prompts/skeptic.md`)
- Role: adversarial reviewer paid to prove the Scout wrong; success = finding a true flaw, not agreeing.
- For each hypothesis run at least one falsification check from this list and name the `kind`: `control_present` (active protective control), `edge_dead` (no live traffic/route/rps), `service_inactive` (deprecated/decommissioned), `auth_required` (path assumes unauthenticated but auth is required), `unreachable_code`, `prior_lesson` (a recalled Lesson applies).
- Use `check_exploitability`, `get_service_context`, `shortest_path`, `connected_components`, `recall`.
- Mark `outcome:'upheld'` only when a tool result supports the challenge; otherwise `'rejected'`. Do not invent doubts.

### 9.4 Scribe system prompt (`prompts/scribe.md`)
- Role: adjudicate and act. Read the blackboard. For each finding group choose `FIX_NOW | SCHEDULE | ACCEPT | SUPPRESS`.
- Decision policy: live exploit + path to crown jewel + not falsified → FIX_NOW; falsified by control/inactive/lesson → downgrade with reason; no path → SUPPRESS/ACCEPT.
- Every sentence of rationale is a **claim** `{id, text, cites:[step ids], node_ids}`. No claim without a citation. Keep claims short, concrete, and in plain language.
- Call `record_verdict`; if the grounding check returns failures, fix the offending claims once and retry.
- Then `propose_action` for each FIX_NOW and for the top chokepoint fix. Ticket text must read like a competent engineer wrote it.

### 9.5 Grounding check (backend + `record_verdict`)
For each claim: (1) every cited `step_id` exists in this investigation; (2) every `node_id` in the claim appears in `touched_ids` of at least one cited step; (3) every number that appears in the claim text (percentages, counts, scores) appears verbatim (after rounding) in at least one cited step's result. Failing claims are returned to the Scribe with the reason. If still failing after one retry, store the verdict with `grounded:false` and show an "unverified claim" mark in the UI. The UI shows the grounding status on every verdict.

### 9.6 Provider abstraction
`LLMProvider` interface with two implementations:
- `AnthropicProvider` (live, uses MCP-discovered tools converted to Anthropic tool schemas).
- `ScriptedProvider` (`AGENT_MODE=scripted`): deterministic, no API key. It executes a fixed, per-scenario sequence of **real MCP tool calls** against the live graph and produces templated narration from the actual tool results. Purpose: reliable offline demo; the graph still determines the output. The UI shows a small "scripted run" badge when active.

---

## 10. Memory behaviour (cross-session learning)

- Every investigation, step, hypothesis, challenge, path, verdict and action persists. The Investigations list reads from the graph.
- **Feedback loop:** analyst clicks *Agree* or *Override* on a verdict (with new kind + required note). Backend writes `Feedback`, then calls a small LLM step (or, in scripted mode, a rule) to distill a `Lesson`:
  - `scope_kind/scope_value` derived from the finding's service/cluster/package,
  - `effect` from override direction,
  - `text` one sentence,
  - embed the text, write `Lesson` + `APPLIES_TO` edges to the relevant nodes (e.g. all services in cluster `sandbox-eu`).
- **Use:** `recall` runs before Scout (Memory brief) and is available to Skeptic. When a lesson changes a verdict, the Scribe must cite the lesson in a claim and the backend writes `USED_LESSON {influence}`; `Lesson.uses` increments.
- **Safety valve:** lessons never override a verdict to `ACCEPT/SUPPRESS` if a *live exploit with a path to a crown jewel* is present and the lesson's scope does not explicitly cover that service; in that case the Scribe must say "lesson considered, not applied" and why. Implement this check in `record_verdict`.
- **Delta mode:** `diff_since_last` lets the Day-2 run say "1 new path, 3 findings resolved, 2 unchanged and previously accepted".

---

## 11. Backend API

Base path `/api`. JSON. CORS enabled for the frontend origin. All handlers typed with Pydantic.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | falkordb ping, MCP ping, algorithm capabilities, embeddings status, agent mode |
| POST | `/seed/reset` | drop and regenerate graph (`scale` param) |
| POST | `/scan/delta` | apply Day-2 delta (S7 + S6 follow-up) |
| GET | `/graph/overview` | counts, crown jewels, public ingress |
| GET | `/graph/subgraph?ids=a,b,c&hops=1` | nodes/edges for Cytoscape in a normalised shape `{nodes:[{id,label,props}], edges:[{id,source,target,type,props}]}` |
| GET | `/graph/focus?kind=attack_surface` | default view: public ingress + services on top paths + crown jewels (bounded to ≤ 120 nodes) |
| POST | `/cypher/readonly` | Explorer: executes read-only Cypher through `ro_query`, rejects anything containing write keywords, 5 s timeout, row cap 200 |
| GET | `/mcp/tools` | discovered tools (Section 8.6) |
| GET | `/investigations` | list with status, goal, counts, top verdict kinds |
| POST | `/investigations` | body `{goal, preset?}` → `{id}`; starts the run in a background task |
| GET | `/investigations/{id}` | full record: steps, paths, hypotheses, challenges, verdicts, actions, lessons used |
| GET | `/investigations/{id}/stream` | **SSE** live events (below) with replay of past events for a finished run |
| POST | `/verdicts/{id}/feedback` | `{action:'agree'|'override', new_kind?, note}` → creates Feedback + Lesson |
| POST | `/actions/{id}/approve` | marks executed; writes to `outbox/` as `.md` + `.json`; optional Slack webhook if `SLACK_WEBHOOK_URL`; optional GitHub issue if `GITHUB_TOKEN`+`GITHUB_REPO` set; sets finding statuses as relevant |
| POST | `/actions/{id}/reject` | marks rejected |
| GET | `/memory/lessons` | lessons with uses, source feedback, scope nodes |
| GET | `/evals/run` | executes the evaluation (Section 13) and returns metrics + per-finding table |

### SSE event types (all JSON with `type`, `ts`, `investigation_id`)
`run_started` · `phase` (`memory|scout|skeptic|rebuttal|scribe`) · `agent_message` (short narration text, agent name) · `tool_call` (step id, tool, args) · `tool_result` (step id, summary, rows, latency_ms, cypher[], touched_ids[], engine) · `graph_highlight` (ids, reason) · `path_found` (AttackPath) · `hypothesis` · `challenge` · `memory_hit` (lesson, why) · `verdict` (with grounding status) · `action_proposed` · `error` · `run_finished`.

Persist events as they happen so the stream endpoint can replay them for finished investigations (store `events_json` chunks on `Investigation` or a `:Event` chain; choose the simpler robust option).

---

## 12. Frontend — design system and screens

### 12.1 Design intent
The product should feel like a **field-manual / incident case file** printed on warm paper and annotated in ink — dense, precise, calm, a little severe. It must not look like a generic AI dashboard. Reference points (do not copy): technical wiring manuals, cartographic atlases, trading-terminal density with editorial typography.

**Forbidden:** purple/blue-violet gradients, glassmorphism, glow/neon, drop-shadow cards, `rounded-xl/2xl`, pill buttons everywhere, emoji, sparkle/robot iconography, "AI-powered" copy, big hero illustration, centred marketing layouts, default system-ui fonts, stock chart colours, placeholder lorem ipsum, gratuitous animation.

### 12.2 Tokens (`src/styles/tokens.css`)
```
--paper:        #F3EFE6;   /* page */
--paper-2:      #EAE5D8;   /* panels */
--paper-3:      #DDD6C5;   /* wells, row hover */
--ink:          #16140F;   /* text, primary lines */
--ink-2:        #4A463B;   /* secondary text */
--ink-3:        #857F70;   /* tertiary, disabled */
--rule:         #1B1913;   /* hairlines at 1px, 100% */
--rule-soft:    #BDB5A1;   /* inner hairlines */
--threat:       #C8321B;   /* attack paths, FIX NOW */
--threat-wash:  #F0D5CC;
--caution:      #A8741A;   /* SCHEDULE */
--safe:         #3E6B4D;   /* SUPPRESS / mitigated */
--structure:    #1F3345;   /* graph structure, links, focus */
--accept:       #6B5E86;   /* ACCEPT — only place a violet-ish tone is allowed, desaturated */
```
Dark mode is **not** required. Provide a single light "paper" theme done properly. Radius max 2px. Borders: 1px solid `--rule` for primary containers, `--rule-soft` for inner dividers. No box-shadows except a 1px offset `0 1px 0 var(--rule)` on sticky headers.

### 12.3 Typography (via @fontsource)
- Display / headings: **Newsreader** (variable or 500/600) — editorial serif for page titles, verdict statements, big numerals.
- UI: **IBM Plex Sans** 400/500/600.
- Data / ids / Cypher / ledger: **IBM Plex Mono** 400/500, `font-variant-numeric: tabular-nums`.
Scale: 11/12/13/14/16/20/28/44 px. Base 13.5px UI, line-height 1.45. Labels are small caps via `letter-spacing:.06em; text-transform:uppercase; font-size:11px; color:var(--ink-2)`. Numbers that matter (risk %, path counts) set in Newsreader at 44px with a mono caption.

### 12.4 Layout and components
- 12-column grid, 24px gutters, app max-width fluid; **three-pane case file** on Investigation screen. Visible 1px rules separate regions (like a form). Section headings are numbered (`01 Brief`, `02 Map`, `03 Ledger`) in mono.
- Buttons: rectangular, 28px height, 1px ink border; primary = ink background with paper text; destructive = threat border + text. Hover: invert (paper/ink swap), 80ms. Focus: 2px `--structure` outline offset 2px.
- Tables: hairline rows, mono ids, right-aligned numerics, sticky header, zebra none.
- Tags/stamps: bordered uppercase mono rectangles — `FIX NOW` (threat), `SCHEDULE` (caution), `SUPPRESS` (safe), `ACCEPT` (accept). Grounded verdicts show a small check mark glyph and `GROUNDED`; unverified show a dashed border and `UNVERIFIED`.
- Icons: **hand-authored inline SVG**, 16px, 1.5px stroke, square caps; about 18 glyphs (search, play, check, x, arrow, node types, link, clock, memory, branch, flag, copy, expand, filter). Put them in `src/components/icons.tsx`.
- Empty/loading/error states are designed: loading = hairline progress rule with mono "reading graph…" text; empty = one-line statement + the next action; errors = bordered block with the failing step id and retry. No spinners except a 12px ticking square.
- Motion: only three — (1) attack-path edges use a slow `stroke-dashoffset` march (2.4s linear) in `--threat`; (2) ledger rows slide in 120ms; (3) verdict stamp fades/settles 160ms. All off under `prefers-reduced-motion`.
- Keyboard: `g` focus graph, `l` ledger, `/` search, `j/k` move through ledger rows, `Enter` open, `Esc` clear highlight, `?` shortcuts sheet. All interactive elements reachable by keyboard; WCAG AA contrast for text.
- Responsive: desktop-first (≥1280px). At ≥900px collapse right pane to a drawer. Below 900px show a calm "best viewed on a larger screen" note with read-only ledger; do not break.

### 12.5 Graph rendering (Cytoscape)
- Layout: `fcose` with node-type-aware constraints: ingress/Internet on the left rank, services in the middle, data stores on the right (use relative placement constraints or manual x-bands then fcose refinement). Deterministic seed so layout is stable.
- Node glyphs by type (shape + fill, no icons inside): Internet = hollow double ring; Ingress = diamond; Service = circle (size by `tier`); DataStore = square (fill by classification: pci/secrets = `--ink`, pii = `--structure`, other = `--paper-3`); Package = small hollow triangle; Vulnerability = small solid triangle in `--threat`; Control = hexagon in `--safe`; IAMRole = small rounded-rect.
- Edges: 1px `--rule-soft`; `CALLS` with `authz:'none'` drawn dashed to read as "unprotected"; attack-path edges 2.5px `--threat` with the dash march; mitigated edges `--safe` dotted.
- Labels: mono 10px, shown at zoom ≥ 0.8 or on hover/selected; collision-avoid by truncation (`payments-api`), full name in tooltip.
- Interaction: hover = neighbour emphasis; click node = Dossier opens "Entity" tab (properties, owners, controls, open findings); click ledger row = highlight its `touched_ids` and fit; click a citation in a verdict = highlight cited step + nodes; select attack path in ribbon = dim everything else; toggle layers (Estate / Paths / Controls / Memory).
- Provide a legend strip under the map (hand-set, no library) and a small "scale bar" showing node/edge counts of the current view.
- Cap on-screen nodes to ≤ 150 with a "+N more hidden — expand" affordance.

### 12.6 Screens

**A. Case Board (`/`)**
- Masthead: wordmark `CHOKEPOINT` in Newsreader, caption `attack-path triage · FalkorDB`, status strip (graph ok / MCP ok / mode live|scripted / embeddings on|off) in mono.
- Left: **"The naive view"** — top 10 findings by CVSS (table). Right: **"The graph's view"** — after an investigation, top paths by score; before any investigation, a single clear call to action.
- Headline numerals: `<n> findings · <m> internet-reachable · <k> reach a crown jewel` computed live from graph.
- Start-investigation panel: goal textarea + 4 presets (`Triage the latest scan`, `Is payments-vault reachable from the internet?`, `What are the 3 fixes that matter most?`, `What changed since yesterday?`).
- Recent investigations table (goal, status, verdict stamps, duration, steps count).
- Admin strip (small, bottom): `Reset seed`, `Apply Day-2 scan`.

**B. Investigation (`/i/:id`)** — the hero screen
- Top bar: goal, status, phase indicator showing `Memory → Scout → Skeptic → Rebuttal → Scribe` as a horizontal hairline track with current phase inked.
- Left pane (≈26%): `01 Brief` — Memory brief (lessons recalled with why: graph/vector/both), diff summary, Toolbelt (MCP tools, used ones inked).
- Center (≈48%): `02 Map` Cytoscape + **Path Ribbon** above it (selectable attack paths as horizontal sequences of glyphs with score numerals) + legend. Under the map: `Risk before → after` mini bar for the best simulated fix set.
- Right pane (≈26%): Dossier tabs — `Verdicts` · `Evidence` · `Blackboard` · `Actions` · `Entity`.
  - *Verdicts:* stamp, one-sentence headline in Newsreader, confidence, claims list with numbered citations `[S4]` (hover/click = highlight), grounding status, Agree/Override controls (override requires note).
  - *Evidence:* score breakdown table for selected path (exploitability/exposure/impact/length/control), exploitability check booleans with reasons.
  - *Blackboard:* hypotheses and challenges as a two-column debate: claim → challenge → outcome with stamps (`UPHELD`/`REJECTED`), linking to steps.
  - *Actions:* proposed tickets rendered as Markdown with routing (team, on-call, Slack channel), Approve / Reject, and approved ones show outbox file path.
- Bottom (full width): `03 Ledger` — dense mono table: `#`, agent, tool, args (truncated), rows, ms, engine, summary; expandable row shows the exact Cypher (syntax-tinted in ink/structure/threat, no rainbow) and raw JSON. Live rows slide in. Failed calls are shown, not hidden.
- Verdict Reveal: when the Scribe finishes, headline counts animate to rest once (e.g. `3 fixes remove 71% of exploitable path risk`), with a "Show simulation" action.

**C. Memory (`/memory`)**
- Table of Lessons: text, scope chips, effect, uses, strength, source feedback (who/when/note), linked investigations; click shows the lesson's neighbourhood in a small graph. Banner explains how lessons are retrieved (graph + vector).

**D. Evals (`/evals`)**
- Side-by-side columns: **CVSS-first** · **KEV/EPSS-first** · **CHOKEPOINT**. Metrics: precision@10 of truly exploitable findings, recall of exploitable set, decoys in top 10, number of fixes/tickets needed to cover ≥90% of exploitable path weight, and grounded-claim rate. Per-finding table with ground-truth label vs each method's verdict. A single honest caption states ground truth is planted in a synthetic environment.
- Computation is deterministic from tools + the latest verdicts; if no investigation exists, the page offers to run one.

**E. Explorer (`/explorer`)**
- Left: schema (labels, rel types, counts). Center: read-only Cypher editor (monospaced textarea with line numbers; no heavy editor lib), `Run` and 6 saved example queries (including the attack-path query the tools use). Right/below: results as table and "show as graph" toggle. Shows query latency.

### 12.7 Copy and microcopy
Terse and factual, present tense, no exclamation marks, no filler. Examples: "Reading graph." · "No path from internet to payments-vault under current controls." · "Skeptic upheld 1 of 4 challenges." · "Lesson applied: sandbox-eu has no route to prod data stores." Verdict headlines are claims, e.g. "Patch session-sdk. It is the shortest route from the open internet to card data."

---

## 13. Evaluation (ships in the product)

Compute from `seed/ground_truth.json` (outside the graph):
- **Baselines:** (1) top-N by CVSS desc; (2) top-N by KEV desc then EPSS desc.
- **CHOKEPOINT:** findings with verdict `FIX_NOW` ordered by path score.
- Metrics: precision@10, recall of `exploitable_findings`, decoys in top-10, fixes needed to reach ≥90% exploitable path weight (agent: from `find_chokepoints`; baselines: count of top-ranked findings until 90% of weight covered), % claims grounded, mean tool calls per investigation.
- Expected on the planted data (the tests are for the user to run; design the data so these hold): CVSS-first has ≥ 3 decoys in top-10 and misses the S2 quiet killer; CHOKEPOINT ranks S2 first and S1 as non-exploitable.

---

## 14. Repository layout (create exactly this)

```
/
├─ PRD.md                          (already present; do not modify)
├─ README.md
├─ docker-compose.yml
├─ .env.example
├─ Makefile                        (targets: up, down, seed, logs, mcp-stdio)
├─ backend/
│  ├─ Dockerfile
│  ├─ requirements.txt
│  ├─ pyproject.toml               (ruff + basic config only)
│  ├─ app/
│  │  ├─ main.py                   FastAPI app, routers, lifespan
│  │  ├─ config.py                 env via pydantic-settings
│  │  ├─ db.py                     FalkorDB handle helpers, ro/rw queries, timing
│  │  ├─ models.py                 Pydantic schemas (API, SSE events)
│  │  ├─ events.py                 event bus + persistence + replay
│  │  ├─ routers/ (health, graph, cypher, investigations, feedback, actions, memory, evals, mcp_tools, admin).py
│  │  ├─ orchestrator/
│  │  │   ├─ runner.py             phases, limits, timeouts
│  │  │   ├─ mcp_client.py         connect, list_tools, call_tool, role allow-lists
│  │  │   ├─ providers/ (base.py, anthropic_provider.py, scripted_provider.py)
│  │  │   └─ prompts/ (scout.md, skeptic.md, scribe.md, lesson_distill.md)
│  │  ├─ memory/ (embeddings.py, lessons.py)
│  │  ├─ seed/ (schema.py, generate.py, scenarios.py, delta_day2.py, ground_truth.json, loader.py)
│  │  ├─ evals/ (metrics.py)
│  │  └─ actions/ (outbox.py, slack.py, github.py)
│  └─ mcp_server/
│     ├─ server.py                 FastMCP, transports, role checks, capability detection
│     ├─ graph_ops.py              Cypher builders & helpers (parameterised)
│     ├─ scoring.py                7.2 / 7.3
│     ├─ attack.py                 path enumeration & predicates
│     ├─ solver.py                 chokepoints + simulation
│     ├─ algos.py                  native algo wrappers + networkx fallback
│     ├─ grounding.py              claim validation
│     └─ tools/ (read.py, analysis.py, memory.py, blackboard.py, actions.py)
└─ frontend/
   ├─ Dockerfile, nginx.conf, index.html, package.json, tsconfig.json, vite.config.ts
   └─ src/
      ├─ main.tsx, App.tsx, router.tsx
      ├─ styles/ (tokens.css, base.css, typography.css, layout.css)
      ├─ api/ (client.ts, sse.ts, types.ts)
      ├─ store/ (useInvestigation.ts, useGraph.ts, useUI.ts)
      ├─ components/ (icons.tsx, Stamp.tsx, Button.tsx, Table.tsx, Tabs.tsx, Rule.tsx, Numeral.tsx, Legend.tsx, Kbd.tsx, StatusStrip.tsx, ...)
      ├─ graph/ (GraphView.tsx, cyStyle.ts, layout.ts, glyphs.ts, PathRibbon.tsx)
      ├─ features/
      │   ├─ board/ (CaseBoard.tsx, NaiveView.tsx, GraphView.tsx, StartPanel.tsx)
      │   ├─ investigation/ (InvestigationPage.tsx, PhaseTrack.tsx, BriefPane.tsx, Dossier/*.tsx, Ledger.tsx, CypherBlock.tsx, VerdictReveal.tsx)
      │   ├─ memory/ (MemoryPage.tsx)
      │   ├─ evals/ (EvalsPage.tsx)
      │   └─ explorer/ (ExplorerPage.tsx)
      └─ lib/ (format.ts, hotkeys.ts, cypherTint.ts)
```
Share tool logic between `mcp_server` and `backend` by importing `mcp_server` as a package inside the backend image (single Python source tree; the `mcp` compose service runs `python -m mcp_server.server --transport streamable-http --port 8765`).

---

## 15. Configuration

`.env.example`:
```
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-5-5
AGENT_MODE=live                # live | scripted
FALKORDB_HOST=falkordb
FALKORDB_PORT=6379
GRAPH_NAME=chokepoint
MCP_URL=http://mcp:8765/mcp
EMBEDDINGS=fastembed           # fastembed | none
EMBEDDING_MODEL=BAAI/bge-small-en-v1.5
SEED_SCALE=1
OUTBOX_DIR=/data/outbox
SLACK_WEBHOOK_URL=
GITHUB_TOKEN=
GITHUB_REPO=
```
If `ANTHROPIC_API_KEY` is empty and `AGENT_MODE=live`, `/health` reports the problem and the UI offers to switch to scripted mode; the backend must not crash.

`docker-compose.yml`: falkordb (ports 6379, 3000 for the FalkorDB browser, volume `falkor-data`), mcp, backend (port 8000, depends on falkordb+mcp, auto-seeds on first boot if the graph is empty), frontend (port 8080 → Nginx; proxies `/api` to backend with SSE-safe settings: `proxy_buffering off`, `proxy_read_timeout 3600`). Healthchecks on all.

---

## 16. Demo script (build the product so this flows without edits)

1. **Case Board.** Naive view shows the CVSS 10 in `report-renderer` at the top. Headline: `322 findings · 41 internet-reachable · 9 reach a crown jewel`.
2. Click *Triage the latest scan*. Watch phases. Ledger fills; the map lights up the 5-hop path to `payments-vault`. Scout says why S1 isn't on any path.
3. Skeptic challenges the `edge-gw` finding with `control_present` (upheld) → verdict downgrades.
4. Scribe: `FIX NOW` on `session-sdk`; headline `3 fixes remove 71% of exploitable path risk`. Simulation shows before/after.
5. Hover a claim citation → ledger row + nodes highlight. Show grounding status.
6. Approve the ticket → outbox file appears; routed to the right team and on-call.
7. Override the `ml-notebooks` verdict → Lesson created (Memory page).
8. **Apply Day-2 scan** → run *What changed since yesterday?* → agent reports 1 new path and cites the sandbox lesson on `feature-lab`.
9. **Evals** page: CVSS-first vs CHOKEPOINT.
10. **Explorer**: run the saved attack-path Cypher; same graph, same answer.

---

## 17. Quality bar and acceptance checklist

- [ ] All 21 tools exist, are discoverable over MCP, have strict schemas, and respect role allow-lists.
- [ ] Agents call tools only through the MCP client; role-restricted tools cannot be called by the wrong agent.
- [ ] Scores computed only in `scoring.py`/`solver.py`; LLM prompts forbid inventing numbers.
- [ ] `find_chokepoints` re-evaluates coverage on modified state; `simulate_fix` uses `GRAPH.COPY` and always deletes the scratch graph.
- [ ] Algorithm calls have native + networkx paths with `engine` reported.
- [ ] Every step persists as `Step` with `TOUCHED` edges; every verdict has `CITES` edges.
- [ ] Grounding check implemented and visible in UI.
- [ ] Override → Lesson → recall → applied-with-citation works end to end, with the safety valve.
- [ ] `ScriptedProvider` runs all demo flows with no API key.
- [ ] SSE replay works for completed investigations.
- [ ] Read-only Cypher endpoint rejects `CREATE|MERGE|DELETE|SET|REMOVE|DROP|CALL db.idx.*create|LOAD`, caps rows, and times out.
- [ ] Frontend follows Section 12: tokens, fonts, no forbidden patterns, designed empty/loading/error states, keyboard shortcuts, reduced-motion support.
- [ ] No secrets in code; `.env.example` complete; outbox dir created automatically.
- [ ] Type hints throughout Python; TypeScript `strict`; no `any` without a comment; no dead code; no commented-out blocks.
- [ ] Code is idiomatic, small modules, meaningful names, docstrings only where they add information.

---

## 18. README requirements

`README.md` must contain: the one-line pitch; a 5-line "why a graph" explanation; architecture diagram (ASCII is fine); quick start (`cp .env.example .env`, set key or `AGENT_MODE=scripted`, `docker compose up --build`, open `http://localhost:8080`); the demo script (Section 16); the MCP tool table; a Claude Desktop MCP config snippet (stdio):
```json
{ "mcpServers": { "chokepoint": { "command": "python", "args": ["-m", "mcp_server.server", "--transport", "stdio"], "env": { "FALKORDB_HOST": "localhost", "GRAPH_NAME": "chokepoint" } } } }
```
; the graph schema summary; evaluation explanation and its honesty caveat; known limitations (synthetic data, heuristic effort costs, single-tenant); and troubleshooting (FalkorDB not ready, missing API key, embeddings model download on first run).

---

## 19. Non-goals
Auth/multi-user, real scanner integrations (design the loader so a CycloneDX/Trivy importer could be added; do not build it), cloud deployment, mobile layout, dark theme.

---

## 20. Risks and how the build handles them

| Risk | Mitigation in build |
|---|---|
| Algorithm procedures differ by FalkorDB version | Capability detection + networkx fallback, `engine` reported |
| LLM hallucinated numbers | Deterministic scoring in tools; grounding check |
| LLM latency/cost during demo | Step caps, prompt caching, `ScriptedProvider` |
| Path explosion on large graphs | Bounded variable-length matches, LIMITs, hop cap, pre-filters, truncation flags |
| Embedding model not available | `EMBEDDINGS=none` path with fulltext + graph proximity |
| UI looks generic | Section 12 is binding; tokens, type, glyphs and interactions are specified |
