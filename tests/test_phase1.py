#!/usr/bin/env python3
"""Phase 1 integration QA script."""
import sys
import os

# Ensure project root is on path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def _run_checks():
    """Execute all Phase 1 QA checks and return error list."""
    errors = []

    def check(name, fn):
        try:
            fn()
            print(f"  PASS: {name}")
        except Exception as e:
            print(f"  FAIL: {name} -> {e}")
            errors.append((name, e))

    # ── 1. Import checks ──
    print("=== Import Checks ===")
    check("import selectinf", lambda: __import__("selectinf"))
    check("import selectinf.core.config", lambda: __import__("selectinf.core.config"))
    check("import selectinf.core.tool_runner", lambda: __import__("selectinf.core.tool_runner"))
    check("import selectinf.models.entities", lambda: __import__("selectinf.models.entities"))
    check("import selectinf.stages.base", lambda: __import__("selectinf.stages.base"))
    check("import selectinf.pipeline.orchestrator", lambda: __import__("selectinf.pipeline.orchestrator"))
    check("import selectinf.pipeline.task_fsm", lambda: __import__("selectinf.pipeline.task_fsm"))

    # ── 2. Entity models ──
    print("\n=== Entity Models ===")
    from selectinf.models.entities import Severity, Asset, Fingerprint, Vulnerability

    check("Severity enum", lambda: (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO))
    check("Asset dataclass", lambda: Asset(task_id=1, domain="example.com"))
    check("Fingerprint dataclass", lambda: Fingerprint(task_id=1, url="https://example.com"))
    check("Vulnerability dataclass", lambda: Vulnerability(task_id=1, vuln_id="CVE-2024-1234", url="https://ex.com", template="test", severity=Severity.HIGH))

    # ── 3. Config loading ──
    print("\n=== Config Loading ===")
    from selectinf.core.config import load_config, PipelineConfig
    check("load_config()", lambda: load_config())
    cfg = load_config()
    check("config type", lambda: isinstance(cfg, PipelineConfig))
    check("concurrency", lambda: cfg.concurrency == 4)
    check("collect tools count", lambda: len(cfg.collect) == 6)
    check("fingerprint tools count", lambda: len(cfg.fingerprint) == 2)
    check("vulnscan tools count", lambda: len(cfg.vulnscan) == 1)
    check("ai provider", lambda: cfg.ai.get("provider") == "openai")
    check("subfinder enabled", lambda: cfg.collect["subfinder"].enabled is True)
    check("httpx extra fields", lambda: "ports" in cfg.fingerprint["httpx"].extra)
    check("nuclei severity_filter", lambda: cfg.vulnscan["nuclei"].extra.get("severity_filter") == ["critical", "high", "medium"])

    # ── 4. SQLite schema (idempotent init) ──
    print("\n=== SQLite Schema ===")
    from selectinf.output.sqlite_manager import init_db, get_db
    import sqlite3

    check("init_db idempotent #1", lambda: init_db())
    check("init_db idempotent #2", lambda: init_db())  # must not crash on second call
    conn = get_db()
    cursor = conn.cursor()
    check("WAL mode enabled", lambda: cursor.execute("PRAGMA journal_mode").fetchone()[0] == "wal")
    check("busy_timeout=5000", lambda: cursor.execute("PRAGMA busy_timeout").fetchone()[0] == 5000)
    conn.close()

    # ── 5. Tool runner ──
    print("\n=== Tool Runner ===")
    from selectinf.core.tool_runner import run_tool, ToolResult
    check("run_tool echo", lambda: isinstance(run_tool(["python", "-c", "print(1)"], "echo test", timeout=10), ToolResult))
    res = run_tool(["python", "-c", "print('hello')"], "echo", timeout=10)
    check("ToolResult success", lambda: res.success and res.stdout.strip() == "hello")

    # ── 6. PipelineStage ABC ──
    print("\n=== PipelineStage ABC ===")
    from selectinf.stages.base import StageResult
    check("StageResult create", lambda: StageResult("success", 1, 1, [], "/tmp"))

    # ── 7. Orchestrator + FSM stubs ──
    print("\n=== Orchestrator + FSM Stubs ===")
    from selectinf.pipeline.orchestrator import PipelineOrchestrator
    check("orchestrator init", lambda: PipelineOrchestrator("pipeline_config.yaml"))
    from selectinf.pipeline.task_fsm import TaskFSM
    check("TaskFSM init", lambda: TaskFSM(1).get_status() == "created")

    # ── Summary ──
    print(f"\n=== SUMMARY: {len(errors)} failures ===")
    for name, e in errors:
        print(f"  - {name}: {e}")

    return errors


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    errs = _run_checks()
    sys.exit(1 if errs else 0)
