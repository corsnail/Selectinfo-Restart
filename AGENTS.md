# PROJECT KNOWLEDGE BASE

**Generated:** 2026-05-17
**Commit:** development
**Branch:** development

## OVERVIEW

**selectinf** - Automated asset collection and vulnerability scanning framework integrating OneForAll, amass, massdns, ksubdomain, subfinder, and JSFinder into a unified four-stage pipeline for subdomain enumeration, fingerprinting, vulnerability scanning, and AI-powered analysis.

## STRUCTURE

```
.
├── run.py                          # Legacy entry point (backward compat)
├── pipeline_config.yaml            # Pipeline configuration
├── selectinf/                      # Core Python package
│   ├── __init__.py
│   ├── __main__.py                 # python -m selectinf (future entry)
│   ├── core/                       # Infrastructure
│   │   ├── config.py               # PipelineConfig + YAML loader
│   │   └── tool_runner.py          # Unified tool execution (run_tool, run_pipe_tool)
│   ├── models/
│   │   └── entities.py             # Asset, Fingerprint, Vulnerability dataclasses
│   ├── stages/                     # Pipeline stages
│   │   ├── base.py                 # PipelineStage ABC + StageResult
│   │   ├── collect.py              # Stage 1: Asset collection (subfinder, amass, OneForAll, massdns, ksubdomain, JSFinder)
│   │   ├── fingerprint.py          # Stage 2: Service/technology detection (stub)
│   │   ├── vulnscan.py             # Stage 3: Nuclei vulnerability scanning (stub)
│   │   └── ai_analysis.py          # Stage 4: LLM-powered report generation (stub)
│   ├── pipeline/                   # Orchestration
│   │   ├── orchestrator.py         # PipelineOrchestrator: stage scheduling + task lifecycle
│   │   └── task_fsm.py             # TaskFSM + DB status persistence
│   ├── collect/                    # Data collection layer (existing)
│   │   ├── extract_domains.py      # Parse results from tools (now accepts work_dir)
│   │   └── dnsgrep.py              # DNS record processing (now accepts work_dir)
│   ├── process/                    # Data processing layer (existing)
│   │   ├── deduplicate.py          # Domain/URL deduplication
│   │   ├── filter_wildcard.py      # Filter wildcard DNS
│   │   └── url_converter.py        # Domain-to-URL conversion
│   ├── ai/                         # AI integration (planned Phase 5)
│   │   ├── client.py               # LLM client interface + OpenAI/Ollama implementations
│   │   └── prompts.py              # Prompt templates for report generation and FP validation
│   └── output/                     # Data output layer
│       ├── sqlite_manager.py       # SQLite schema + CRUD (assets, fingerprints, vulnerabilities, ai_analysis)
│       ├── arl_exporter.py         # ARL platform integration
│       └── mysql_exporter.py       # CSV to MySQL import
├── config/                         # Configuration files
│   └── database.conf               # MySQL connection settings
├── output/                         # Runtime output directory
│   └── xlsx/                       # ARL export files
├── engines/                        # Large frameworks
│   └── OneForAll/                  # Integrated subdomain collection framework
├── tools/                          # External binaries and scripts
│   ├── amass/                      # amass binary + configs
│   ├── massdns/                    # massdns scripts + binaries
│   ├── ksubdomain/                 # ksubdomain executable
│   ├── subfinder/                  # subfinder executable
│   ├── subDomainsBrute/            # Alternative brute-force tool
│   └── jsfinder/                   # JS-based URL/domain extraction
├── tests/                          # Test suite
│   ├── test_phase1.py              # Phase 1 infrastructure QA
│   ├── test_collect_stage.py       # Phase 2 CollectStage integration tests (6 tests)
│   └── test_orchestrator.py        # Phase 2 Orchestrator integration tests (6 tests)
└── application/                    # Task configs (add.json, task.json)
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Start asset collection | `run.py` / `PipelineOrchestrator.run()` | Legacy `run.py` preserved; new code uses orchestrator |
| Pipeline configuration | `pipeline_config.yaml` | All tool timeouts, paths, and stage toggles |
| Core Python modules | `selectinf/` | All utility scripts packaged here |
| Pipeline orchestration | `selectinf/pipeline/orchestrator.py` | Stage scheduling, FSM transitions, work_dir lifecycle |
| Task state machine | `selectinf/pipeline/task_fsm.py` | DB-persisted status transitions |
| Stage base class | `selectinf/stages/base.py` | `PipelineStage` ABC + `StageResult` dataclass |
| Collect stage | `selectinf/stages/collect.py` | Encapsulates `run.py` scan logic with `work_dir` isolation |
| Config loading | `selectinf/core/config.py` | `PipelineConfig`, `ToolConfig`, `load_config()` |
| Tool execution | `selectinf/core/tool_runner.py` | `run_tool()`, `run_pipe_tool()` with retries + logging |
| Data collection layer | `selectinf/collect/` | Domain extraction, DNS discovery |
| Data processing layer | `selectinf/process/` | Dedup, filter, URL conversion |
| Data output layer | `selectinf/output/` | ARL export, MySQL storage, SQLite persistence |
| OneForAll framework | `engines/OneForAll/` | Complex subdomain enumeration tool |
| External binaries | `tools/` | amass, subfinder, massdns, ksubdomain, jsfinder |
| Entity models | `selectinf/models/entities.py` | `Asset`, `Fingerprint`, `Vulnerability` dataclasses |
| Database config | `config/database.conf` | MySQL connection settings |
| Configs | `application/` | Task and asset configurations |

## CONVENTIONS

- **Entry point**: `python run.py` (legacy) or `python -m selectinf` (future)
- **Tool calls**: Use `run_tool()` / `run_pipe_tool()` from `selectinf.core.tool_runner`
- **Threading**: Parallel execution via `threading.Thread` (see scan_thread1/2)
- **Output format**: Text files (.txt) for intermediate, CSV for final results
- **Intermediate isolation**: All tool outputs go to `work/{task_id}/`; orchestrator cleans up after completion
- **Naming**: `<target>.txt` for URLs, `domain_<target>.txt` for domains
- **Database**: SQLite3 via `selectinf.output.sqlite_manager`; WAL mode + busy_timeout enabled
- **Package**: Core modules in `selectinf/`, external tools at root level
- **Strangler Pattern**: New pipeline code lives in `selectinf/pipeline/` and `selectinf/stages/`; `run.py` remains untouched during Phase 2

## ANTI-PATTERNS

- **DO NOT** run tools directly; always use `run.py` orchestration or `PipelineOrchestrator`
- **DO NOT** modify `OneForAll/config/api.py` without backing up API keys
- **NEVER** commit API keys to version control
- **AVOID** running without proper authorization (legal compliance required)
- **NEVER** write intermediate `.txt` files to project root; always use `work/{task_id}/`
- **NEVER** suppress type errors with `as any`, `@ts-ignore`, `@ts-expect-error`

## COMMANDS

```bash
# Main asset collection (interactive, legacy)
python run.py

# Phase 2+ pipeline (programmatic)
python -c "from selectinf.pipeline.orchestrator import PipelineOrchestrator; PipelineOrchestrator().run('example.com')"

# OneForAll standalone
python OneForAll/oneforall.py --target example.com run

# Run test suite
pytest tests/ -v

# Phase 1 regression (standalone)
python tests/test_phase1.py

# Database setup (if needed)
pip install -r OneForAll/requirements.txt
```

## PHASE STATUS

| Phase | Description | Status | Tests |
|-------|-------------|--------|-------|
| Phase 1 | Infrastructure (config, tool_runner, SQLite schema, entities, ABC stubs) | **Complete** | `test_phase1.py` 0 failures |
| Phase 2 | Collect Stage + Orchestrator | **Complete** | `test_collect_stage.py` 6/6 pass, `test_orchestrator.py` 6/6 pass |
| Phase 3 | Fingerprint Stage (httpx integration) | Stub | Skipped |
| Phase 4 | VulnScan Stage (nuclei integration) | Stub | Skipped |
| Phase 5 | AI Analysis Stage (LLM client, prompts, report generation) | Stub | Skipped |
| Phase 6 | run.py thin wrapper + end-to-end validation | Pending | — |

## NOTES

- Windows-focused: Paths use backslashes, includes `.exe` binaries
- OneForAll requires Python 3.8+ and dependencies from `requirements.txt`
- External binaries must exist: `subfinder.exe`, `amass.exe`, `ksubdomain.exe`, `massdns`
- New pipeline stores intermediate results in `work/{task_id}/`; root directory stays clean
- Orchestrator auto-cleans `work/{task_id}/` after task completion
- Do not modify the internal code of third-party modules (`/tools`, `/engines`)
