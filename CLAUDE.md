# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**selectinf** — Automated asset collection and vulnerability scanning framework integrating OneForAll, amass, massdns, ksubdomain, subfinder, and JSFinder into a unified four-stage pipeline for subdomain enumeration, fingerprinting, vulnerability scanning, and AI-powered analysis.

## Architecture

Four-stage pipeline: **Collect → Fingerprint → VulnScan → AI Analysis**

The framework uses a **Strangler Pattern**: new pipeline code lives in `selectinf/pipeline/` and `selectinf/stages/`, while `run.py` (legacy entry point) remains intact during migration.

```
selectinf/
├── core/              ─ Infrastructure (config.py, tool_runner.py)
├── stages/            ─ Pipeline stages (collect.py, fingerprint.py, vulnscan.py, ai_analysis.py)
├── pipeline/          ─ Orchestration (orchestrator.py, task_fsm.py)
├── models/            ─ Data classes (entities.py)
├── collect/           ─ Existing data collection layer
├── process/           ─ Existing data processing (dedup, filter, URL convert)
└── output/            ─ Data output (sqlite_manager.py, arl_exporter.py, mysql_exporter.py)
```

**Key modules:**
- `selectinf/core/tool_runner.py` — Unified tool execution via `run_tool()` (single command) and `run_pipe_tool()` (piped commands like massdns)
- `selectinf/pipeline/orchestrator.py` — `PipelineOrchestrator.run()` creates task, runs stages sequentially, cleans up `work/{task_id}/`
- `selectinf/stages/collect.py` — `CollectStage.execute()` runs all collection tools into `work/{task_id}/`, extracts/deduplicates domains, iterates with JSFinder
- `selectinf/output/sqlite_manager.py` — SQLite schema + CRUD helpers. WAL mode + busy_timeout enabled
- `selectinf/pipeline/task_fsm.py` — TaskFSM with DB-persisted status transitions

## Commands

```bash
# Legacy interactive entry point (prompts for domain)
python run.py

# Programmatic pipeline usage
python -c "from selectinf.pipeline.orchestrator import PipelineOrchestrator; PipelineOrchestrator().run('example.com')"

# Phase 1 regression (standalone, no pytest needed)
python tests/test_phase1.py

# Full test suite (requires pytest)
pytest tests/ -v

# OneForAll standalone
python engines/OneForAll/oneforall.py --target example.com run

# Install OneForAll dependencies
pip install -r engines/OneForAll/requirements.txt
```

**Test organization:**
- `tests/test_phase1.py` — Infrastructure QA (imports, config, schema, tool runner, FSM stubs)
- `tests/test_collect_stage.py` — CollectStage integration tests (6 tests, mocks tools)
- `tests/test_orchestrator.py` — Orchestrator integration tests (6 tests, mocks tools)
- `tests/test_pipe_tool.py` — Standalone `run_pipe_tool` verification

## Development Patterns

- **All external tools** must go through `run_tool()` or `run_pipe_tool()` — never call `subprocess` directly
- **Intermediate files** belong in `work/{task_id}/`, never the project root
- **SQLite** — use helpers in `sqlite_manager.py`, never raw SQL in stages. Each thread gets its own `get_db()` connection
- **Pipeline stages** implement `PipelineStage` ABC with `execute(task_id, input_path) -> StageResult`
- **Configuration** — read from `pipeline_config.yaml` via `load_config()`. Access tool settings through `config.collect["subfinder"].timeout` etc.
- **Threading** — use `threading.Thread` for parallel tool groups (amass+OneForAll, massdns+ksubdomain). Use `ThreadPoolExecutor` for future parallelism
- **Windows-first** — all subprocess calls include `CREATE_NO_WINDOW` flag; use `os.path.join` for paths

## Phase Status

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Infrastructure (config, tool_runner, SQLite schema, entities, ABC stubs) | **Complete** |
| Phase 2 | Collect Stage + Orchestrator (work_dir isolation, auto-cleanup) | **Complete** |
| Phase 3 | Fingerprint Stage (httpx integration) | Stub (skipped) |
| Phase 4 | VulnScan Stage (nuclei integration) | Stub (skipped) |
| Phase 5 | AI Analysis Stage (LLM client + prompts) | Stub (skipped) |
| Phase 6 | run.py thin wrapper + end-to-end validation | Pending |

## Important Notes

- **Platform:** Windows 10/11. External binaries at `tools/`: subfinder.exe, amass.exe, ksubdomain.exe, massdns
- **OneForAll:** Large framework under `engines/OneForAll/`, requires its own `requirements.txt`
- **Strangler Pattern:** `run.py` must not be deleted; new pipeline code gradually replaces it
- **Do not modify** third-party code in `tools/` or `engines/`
- **API keys** for OneForAll and ARL are configured separately — check `config/` and `application/`
