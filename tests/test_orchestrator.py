#!/usr/bin/env python3
"""Integration tests for PipelineOrchestrator (Phase 2 C8)."""

import os
import sys
import sqlite3
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from selectinf.pipeline.orchestrator import PipelineOrchestrator
from selectinf.output.sqlite_manager import init_db, get_db
from selectinf.core.config import PipelineConfig, ToolConfig


@pytest.fixture
def temp_dirs(tmp_path):
    """Provide isolated work and output directories."""
    work_dir = tmp_path / "work"
    output_dir = tmp_path / "output"
    work_dir.mkdir()
    output_dir.mkdir()
    return str(work_dir), str(output_dir)


@pytest.fixture
def clean_db(tmp_path):
    """Use a temporary SQLite DB for isolation."""
    db_path = tmp_path / "test_orchestrator.db"
    import selectinf.output.sqlite_manager as sm
    orig_db_path = sm.DB_PATH
    sm.DB_PATH = str(db_path)
    init_db()
    yield db_path
    sm.DB_PATH = orig_db_path


@pytest.fixture
def mock_config(temp_dirs):
    """Build a minimal PipelineConfig with isolated directories."""
    work_dir, output_dir = temp_dirs
    return PipelineConfig(
        collect={
            "subfinder": ToolConfig(enabled=True, timeout=5, retries=0),
            "amass": ToolConfig(enabled=True, timeout=5, retries=0),
            "oneforall": ToolConfig(enabled=True, timeout=5, retries=0),
            "massdns": ToolConfig(enabled=True, timeout=5, retries=0),
            "ksubdomain": ToolConfig(enabled=True, timeout=5, retries=0),
            "jsfinder": ToolConfig(enabled=True, timeout=5, retries=0, extra={"max_iterations": 1}),
        },
        fingerprint={},
        vulnscan={},
        ai={},
        concurrency=2,
        work_dir=work_dir,
        output_dir=output_dir,
    )


class TestOrchestratorIntegration:
    """C8: End-to-end orchestrator acceptance tests."""

    def _mock_tool(self, cmd, description, timeout=10, cwd=None, env=None, retries=0):
        """Helper to simulate tool output for run_tool."""
        from selectinf.core.tool_runner import ToolResult
        try:
            out_idx = cmd.index("-o") + 1
            out_path = cmd[out_idx]
            with open(out_path, "w") as f:
                f.write("sub1.example.com\nsub2.example.com\n")
        except ValueError:
            pass
        return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

    def _mock_pipe_tool(self, cmd1, cmd2, description, timeout=10, cwd=None, env=None):
        """Helper to simulate tool output for run_pipe_tool."""
        from selectinf.core.tool_runner import ToolResult
        # massdns uses -w, not -o
        try:
            w_idx = cmd2.index("-w") + 1
            out_path = cmd2[w_idx]
            with open(out_path, "w") as f:
                f.write("sub3.example.com\n")
        except ValueError:
            pass
        return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

    def test_run_returns_summary_dict(self, clean_db, mock_config):
        """Orchestrator.run() must return a dict with task_id, status, and results."""
        with patch("selectinf.pipeline.orchestrator.load_config", return_value=mock_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool):
            orch = PipelineOrchestrator("dummy_config.yaml")
            result = orch.run("example.com")

        assert isinstance(result, dict)
        assert "task_id" in result
        assert "target" in result
        assert "status" in result
        assert "results" in result
        assert "summary" in result
        assert result["target"] == "example.com"

    def test_task_created_in_db(self, clean_db, mock_config):
        """A task row must be created in the task table before execution."""
        with patch("selectinf.pipeline.orchestrator.load_config", return_value=mock_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool):
            orch = PipelineOrchestrator()
            result = orch.run("example.com")

        task_id = result["task_id"]
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM task WHERE id = ?", (task_id,))
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        assert row["target_domain"] == "example.com"

    def test_all_stage_results_present(self, clean_db, mock_config):
        """Results dict must contain entries for all four stages."""
        with patch("selectinf.pipeline.orchestrator.load_config", return_value=mock_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool):
            orch = PipelineOrchestrator()
            result = orch.run("example.com")

        stages = ["collect", "fingerprint", "vulnscan", "ai_analysis"]
        for stage in stages:
            assert stage in result["results"], f"Missing stage result: {stage}"
            assert "status" in result["results"][stage]

    def test_fsm_status_transitions_in_db(self, clean_db, mock_config):
        """Task status must progress through collecting → collecting_done → completed."""
        with patch("selectinf.pipeline.orchestrator.load_config", return_value=mock_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool):
            orch = PipelineOrchestrator()
            result = orch.run("example.com")

        task_id = result["task_id"]
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM task WHERE id = ?", (task_id,))
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        assert row["status"] == "completed"

    def test_work_dir_cleaned_up(self, clean_db, mock_config):
        """Intermediate work directory for the task must be removed after completion."""
        work_dir = mock_config.work_dir
        with patch("selectinf.pipeline.orchestrator.load_config", return_value=mock_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool):
            orch = PipelineOrchestrator()
            result = orch.run("example.com")

        task_id = result["task_id"]
        task_work_dir = os.path.join(work_dir, str(task_id))
        assert not os.path.exists(task_work_dir), f"Work dir not cleaned up: {task_work_dir}"

    def test_output_dir_populated(self, clean_db, mock_config):
        """Final output files must land in output_dir."""
        with patch("selectinf.pipeline.orchestrator.load_config", return_value=mock_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool):
            orch = PipelineOrchestrator()
            result = orch.run("example.com")

        output_dir = mock_config.output_dir
        expected_domain = os.path.join(output_dir, "domain_example.com.txt")
        assert os.path.exists(expected_domain), f"Expected output file missing: {expected_domain}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
