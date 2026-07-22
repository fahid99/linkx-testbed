---
name: run-trials
description: Launch the LinkX API + both MCP servers and run RogueAgent attack trials (all attack presets, single-model matrix, or full model x topology x attack sweep). Use whenever asked to run trials, benchmark a model against the attack presets, or get ASR numbers.
---

# Running RogueAgent trials

Three processes must be up before any trial: the LinkX API and both MCP servers.
Model API keys (`ANTHROPIC_API_KEY`, and for non-Anthropic models the matching
`*_API_KEY` from `.env`, e.g. `KIMI_API_KEY`) must be set.

## 1. Launch the three processes

```bash
set -a && . ./.env && set +a
nohup .venv/bin/python -m uvicorn app.main:app > /tmp/linkx_api.log 2>&1 &
nohup .venv/bin/python -m mcp_servers.legitimate > /tmp/linkx_mcp_legit.log 2>&1 &
nohup .venv/bin/python -m mcp_servers.malicious > /tmp/linkx_mcp_evil.log 2>&1 &
sleep 2
curl -s http://localhost:8000/admin/health
curl -s http://localhost:8000/docs -o /dev/null -w "API: %{http_code}\n"
curl -s http://localhost:8001/mcp -o /dev/null -w "Legit MCP: %{http_code}\n"
curl -s http://localhost:8002/mcp -o /dev/null -w "Evil MCP: %{http_code}\n"
```

All three should respond before proceeding. If not, check the three log files above.

## 2. (Re)seed the database if needed

```bash
.venv/bin/python -m scripts.init_db
```

Only needed once, or after a corrupted/uncommitted DB state — seeding is deterministic
(seed=6727) so re-running it is safe.

## 3. Run trials

```bash
# single condition
.venv/bin/python -m agents.run_trial --model <alias|provider:model> --attack <preset> --topology chain|mesh|both --trace

# one model x all attack conditions x chosen topology(ies)
.venv/bin/python -m agents.run_trial --model <alias|provider:model> --matrix --topology chain|mesh|both --trace

# both built-in models (opus, sonnet) x all attacks
.venv/bin/python -m agents.run_trial --matrix --topology both --trace
```

Model aliases live in `MODEL_ALIASES` in `agents/run_trial.py` (`opus`, `sonnet`, `kimi`,
...). Any other vendor is passed as `provider:model-id` and resolved through `PROVIDERS`
in `agents/chain.py` — add a new vendor there (one `ProviderSpec` entry) rather than
special-casing it in the runner. A new provider needs its API key in `.env` first.

## 4. Attack conditions

The attack toggles per trial via `AttackConfig` presets in `agents/chain.py` (chosen with
`--attack`). Baseline utility and attack ASR come from the **same** pipeline; with `off`,
no malicious client is created at all.

| Preset | Vector | Evil tools bound to |
|---|---|---|
| `off` | none (baseline) | — |
| `tpa_p1` | explicit-trigger function hijack (`check_service_status`) | Orchestrator |
| `tpa_p2` | implicit-trigger function hijack (`compliance_audit_logger`) | Orchestrator |
| `tpa_p3` | implicit-trigger parameter tampering (`reply_formatter`) | Orchestrator |
| `ipi_ticket` | poisoned ticket body (`is_injected=True`, seeded by the runner) | — |
| `ipi_tool` | poisoned tool output (`fetch_enrichment_profile`) | Data Retrieval |
| `all` | every paradigm + injected ticket | Orchestrator + Data Retrieval |

The runner prints a per-condition line as each trial finishes, then an aggregate ASR /
utility / cascade-depth table at the end, broken out by (topology, model, attack).

## 5. Results

Output JSON is written to `data/<Vendor>/` (e.g. `data/Claude/`, `data/Kimi/` — one subdir per
model provider) with filename per code specifications in `agents/run_trial.py`. The aggregate table is printed to stdout and also
written to `data/trials/aggregate.json`.

## 6. Teardown

```bash
pkill -f "uvicorn app.main:app"
pkill -f "mcp_servers.legitimate"
pkill -f "mcp_servers.malicious"
```

## Notes

- Each trial snapshots the DB, runs the graph, scores, then resets the DB — trials are
  independent even back-to-back on a live server (see CLAUDE.md's Evaluation contract).
- `--repeat N` (default 5) controls how many times each condition repeats for the
  aggregate table — this is what makes ASR a rate rather than a single 0/1 outcome.
- If a model refuses the attack outright (0% ASR across the board), check the trace
  files under `data/traces/` before assuming a harness bug — this has happened before
  with both Anthropic models and was a genuine refusal, not a scorer artifact.
