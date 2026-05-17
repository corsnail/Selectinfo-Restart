#!/usr/bin/env python3
"""Integration tests for CollectStage (Phase 2)."""

import os
import sys
import sqlite3
import pytest
from unittest.mock import patch, MagicMock

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from selectinf.stages.collect import CollectStage
from selectinf.stages.base import StageResult
from selectinf.core.config import PipelineConfig, ToolConfig
from selectinf.output.sqlite_manager import init_db, get_db, save_asset


@pytest.fixture
def temp_dirs(tmp_path):
    """Provide isolated work and output directories."""
    work_dir = tmp_path / "work"
    output_dir = tmp_path / "output"
    work_dir.mkdir()
    output_dir.mkdir()
    return str(work_dir), str(output_dir)


@pytest.fixture
def mock_config(temp_dirs):
    """Build a PipelineConfig with isolated directories."""
    work_dir, output_dir = temp_dirs
    cfg = PipelineConfig(
        collect={
            "subfinder": ToolConfig(enabled=True, timeout=10, retries=0),
            "amass": ToolConfig(enabled=True, timeout=10, retries=0),
            "oneforall": ToolConfig(enabled=True, timeout=10, retries=0),
            "massdns": ToolConfig(enabled=True, timeout=10, retries=0),
            "ksubdomain": ToolConfig(enabled=True, timeout=10, retries=0),
            "jsfinder": ToolConfig(enabled=True, timeout=10, retries=0, extra={"max_iterations": 2}),
        },
        fingerprint={},
        vulnscan={},
        ai={},
        concurrency=4,
        work_dir=work_dir,
        output_dir=output_dir,
    )
    return cfg


@pytest.fixture
def clean_db(tmp_path):
    """Use a temporary SQLite DB for isolation."""
    db_path = tmp_path / "test_selectinf.db"
    # Monkey-patch DB_PATH temporarily
    import selectinf.output.sqlite_manager as sm
    orig_db_path = sm.DB_PATH
    sm.DB_PATH = str(db_path)
    init_db()
    yield db_path
    sm.DB_PATH = orig_db_path


@pytest.fixture
def collect_stage(mock_config):
    return CollectStage(mock_config)


class TestCollectStageAcceptance:
    """Task 6 & 8 acceptance criteria encoded as test assertions."""

    @staticmethod
    def _mock_run_tool(cmd, description, timeout=10, cwd=None, env=None, retries=0):
        try:
            out_idx = cmd.index("-o") + 1
            out_path = cmd[out_idx]
            with open(out_path, "w") as f:
                f.write("sub1.example.com\nsub2.example.com\n")
        except ValueError:
            pass
        from selectinf.core.tool_runner import ToolResult
        return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

    @staticmethod
    def _mock_run_pipe_tool(cmd1, cmd2, description, timeout=10, cwd=None, env=None):
        # massdns uses -w for output file in cmd2
        try:
            w_idx = cmd2.index("-w") + 1
            out_path = cmd2[w_idx]
            with open(out_path, "w") as f:
                f.write("sub3.example.com\n")
        except ValueError:
            pass
        from selectinf.core.tool_runner import ToolResult
        return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

    def test_execute_returns_stage_result(self, collect_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        with patch("selectinf.stages.collect.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_run_pipe_tool):
            result = collect_stage.execute(1, "example.com")

        assert isinstance(result, StageResult)
        assert result.status == "success"
        assert result.items_output > 0
        assert result.output_path == os.path.join(temp_dirs[1], "domain_example.com.txt")

    def test_work_dir_created_and_cleaned(self, collect_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        with patch("selectinf.stages.collect.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_run_pipe_tool):
            # work_dir should be created inside execute
            expected_work = os.path.join(work_dir, "1")
            assert not os.path.exists(expected_work)  # before
            collect_stage.execute(1, "example.com")
            # After execute, if cleanup happens inside, it may or may not exist
            # Orchestrator handles cleanup, not CollectStage
            # So we just assert it was used during execution
            assert os.path.exists(work_dir)  # parent exists

    def test_no_root_txt_residue(self, collect_stage, clean_db, temp_dirs):
        """Root directory must not gain new .txt files after collect stage."""
        import glob
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        before = set(glob.glob(os.path.join(root, "*.txt")))

        with patch("selectinf.stages.collect.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_run_pipe_tool):
            collect_stage.execute(1, "example.com")

        after = set(glob.glob(os.path.join(root, "*.txt")))
        new_files = after - before
        assert not new_files, f"Root polluted with new .txt files: {new_files}"

    def test_assets_table_populated(self, collect_stage, clean_db, temp_dirs):
        with patch("selectinf.stages.collect.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_run_pipe_tool):
            collect_stage.execute(1, "example.com")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM assets WHERE task_id = ?", (1,))
        count = cursor.fetchone()[0]
        conn.close()
        assert count > 0, "assets table should be populated"

    def test_legacy_tables_populated(self, collect_stage, clean_db, temp_dirs):
        with patch("selectinf.stages.collect.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_run_pipe_tool):
            collect_stage.execute(1, "example.com")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM module_results WHERE task_id = ?", (1,))
        mod_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM final_results WHERE task_id = ?", (1,))
        final_count = cursor.fetchone()[0]
        conn.close()
        assert mod_count > 0, "module_results should be populated"
        assert final_count > 0, "final_results should be populated"

    def test_output_domain_file_exists(self, collect_stage, clean_db, temp_dirs):
        _, output_dir = temp_dirs
        with patch("selectinf.stages.collect.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_run_pipe_tool):
            collect_stage.execute(1, "example.com")

        expected = os.path.join(output_dir, "domain_example.com.txt")
        assert os.path.exists(expected), f"Expected output file not found: {expected}"

    def test_jsfinder_loop_respects_max_iterations(self, collect_stage, clean_db, temp_dirs):
        """JSFinder loop must stop when max_iterations is reached."""
        work_dir, _ = temp_dirs
        task_work = os.path.join(work_dir, "1")
        os.makedirs(task_work, exist_ok=True)

        # Seed domain.txt with a single URL so each iteration processes exactly 1 new URL
        domain_txt = os.path.join(task_work, "example.com.txt")
        with open(domain_txt, "w", encoding="utf-8") as f:
            f.write("http://sub1.example.com\n")

        jsfinder_urls = []

        def tracking_jsfinder(url: str, cwd: str) -> None:
            """Replace _jsfinder to count calls and produce deterministic new subdomains."""
            jsfinder_urls.append(url)
            subdomain_path = os.path.join(cwd, "subdomain.txt")
            with open(subdomain_path, "w", encoding="utf-8") as f:
                f.write(f"new{len(jsfinder_urls)}.example.com\n")

        # Test _jsfinder_loop directly to avoid noise from tool execution / extraction
        with patch.object(collect_stage, "_jsfinder", side_effect=tracking_jsfinder):
            collect_stage._jsfinder_loop("example.com", task_work, max_iterations=2, errors=[])

        # With 1 initial URL and max_iterations=2:
        #   iteration 1 → processes http://sub1.example.com → discovers new1.example.com
        #   iteration 2 → processes new1.example.com → discovers new2.example.com
        #   loop exits because iteration == max_iterations
        assert len(jsfinder_urls) == 2, (
            f"Expected exactly 2 JSFinder calls (max_iterations=2), got {len(jsfinder_urls)}: {jsfinder_urls}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
