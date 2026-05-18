#!/usr/bin/env python3
"""End-to-end integration test for the full four-stage pipeline (Phase 6)."""

import json
import os
import sys
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
    db_path = tmp_path / "test_e2e.db"
    import selectinf.output.sqlite_manager as sm
    orig_db_path = sm.DB_PATH
    sm.DB_PATH = str(db_path)
    init_db()
    yield db_path
    sm.DB_PATH = orig_db_path


@pytest.fixture
def full_config(temp_dirs):
    """Build a PipelineConfig with all four stages enabled."""
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
        fingerprint={
            "httpx": ToolConfig(
                enabled=True, timeout=10, retries=0,
                extra={"ports": [80, 443], "threads": 20, "tech_detect": True, "follow_redirects": True}
            )
        },
        vulnscan={
            "nuclei": ToolConfig(
                enabled=True, timeout=10, retries=0,
                extra={
                    "severity_filter": ["critical", "high", "medium"],
                    "rate_limit": 50,
                    "threads": 10,
                    "bulk_size": 100,
                }
            )
        },
        ai={
            "provider": "openai",
            "base_url": "",
            "api_key_env": "OPENAI_API_KEY",
            "model": "gpt-4o",
            "temperature": 0.3,
            "max_tokens": 4096,
            "timeout": 30,
            "fp_validation": {"enabled": True, "threshold": 0.7},
            "report": {"format": "markdown", "include_remediation": True, "language": "zh-CN"},
        },
        concurrency=2,
        work_dir=work_dir,
        output_dir=output_dir,
        stages={
            "collect": True,
            "fingerprint": True,
            "vulnscan": True,
            "ai_analysis": True,
        },
        keep_work_dir=True,
    )


class TestEndToEndPipeline:
    """Phase 6: Full four-stage pipeline end-to-end tests."""

    # ------------------------------------------------------------------
    # Mock helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _mock_collect_tool(cmd, description, timeout=10, cwd=None, env=None, retries=0):
        """Simulate collect-stage tool output."""
        from selectinf.core.tool_runner import ToolResult
        try:
            out_idx = cmd.index("-o") + 1
            out_path = cmd[out_idx]
            with open(out_path, "w") as f:
                f.write("sub1.example.com\nsub2.example.com\n")
        except ValueError:
            pass
        return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

    @staticmethod
    def _mock_pipe_tool(cmd1, cmd2, description, timeout=10, cwd=None, env=None):
        """Simulate massdns pipe output."""
        from selectinf.core.tool_runner import ToolResult
        try:
            w_idx = cmd2.index("-w") + 1
            out_path = cmd2[w_idx]
            with open(out_path, "w") as f:
                f.write("sub3.example.com\n")
        except ValueError:
            pass
        return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

    @staticmethod
    def _mock_httpx(cmd, description, timeout=10, cwd=None, env=None, retries=0):
        """Simulate httpx JSON Lines output."""
        from selectinf.core.tool_runner import ToolResult
        try:
            out_idx = cmd.index("-o") + 1
            out_path = cmd[out_idx]
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            fake = {
                "url": "http://sub1.example.com",
                "status_code": 200,
                "webserver": "nginx",
                "tech": ["nginx"],
                "port": "80",
                "ip": "1.2.3.4",
                "title": "Example",
                "content_type": "text/html",
                "time": "150ms",
            }
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(fake) + "\n")
        except ValueError:
            pass
        return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

    @staticmethod
    def _mock_nuclei(cmd, description, timeout=10, cwd=None, env=None, retries=0):
        """Simulate nuclei JSON Lines output."""
        from selectinf.core.tool_runner import ToolResult
        try:
            out_idx = cmd.index("-o") + 1
            out_path = cmd[out_idx]
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            fake = {
                "template-id": "CVE-2024-TEST",
                "template-path": "http/cves/2024/CVE-2024-TEST.yaml",
                "info": {
                    "name": "Test Vuln",
                    "severity": "high",
                    "description": "Test vulnerability",
                    "classification": {"cvss-score": 8.5},
                },
                "host": "http://sub1.example.com",
                "matched-at": "http://sub1.example.com/path",
                "extracted-results": ["secret123"],
            }
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(fake) + "\n")
        except ValueError:
            pass
        return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

    @staticmethod
    def _mock_ai_client():
        """Create a mock AIClient with deterministic responses."""
        mock_client = MagicMock()
        mock_client.model = "gpt-4o"
        mock_client.total_prompt_tokens = 100
        mock_client.total_completion_tokens = 200
        mock_client.total_cost_usd = 0.005

        mock_client.generate_report.return_value = {
            "report": "# 安全评估报告\n\n测试报告内容。",
            "prompt_tokens": 100,
            "completion_tokens": 200,
            "cost_usd": 0.005,
        }
        mock_client.validate_fp.return_value = {
            "is_vuln": True,
            "confidence": 0.95,
            "reason": "Confirmed real vulnerability",
            "prompt_tokens": 50,
            "completion_tokens": 30,
            "cost_usd": 0.001,
        }
        mock_client.get_usage_summary.return_value = {
            "total_prompt_tokens": 100,
            "total_completion_tokens": 200,
            "total_cost_usd": 0.005,
            "provider": "openai",
            "model": "gpt-4o",
        }
        return mock_client

    # ------------------------------------------------------------------
    # 1. Full four-stage pipeline success
    # ------------------------------------------------------------------

    def test_full_pipeline_all_stages_success(self, clean_db, full_config, temp_dirs):
        """All four stages should execute successfully end-to-end."""
        work_dir, output_dir = temp_dirs

        with patch("selectinf.pipeline.orchestrator.load_config", return_value=full_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_collect_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool), \
             patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_httpx), \
             patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_nuclei), \
             patch("selectinf.stages.ai_analysis.AIClient", return_value=self._mock_ai_client()):
            orch = PipelineOrchestrator("dummy_config.yaml")
            result = orch.run("example.com")

        # Overall result structure
        assert isinstance(result, dict)
        assert "task_id" in result
        assert result["target"] == "example.com"
        assert result["status"] == "success"

        # All four stages present
        stages = ["collect", "fingerprint", "vulnscan", "ai_analysis"]
        for stage in stages:
            assert stage in result["results"], f"Missing stage: {stage}"
            stage_result = result["results"][stage]
            assert stage_result["status"] in ("success", "skipped"), \
                f"Stage {stage} failed: {stage_result.get('errors', [])}"

    # ------------------------------------------------------------------
    # 2. Database tables populated
    # ------------------------------------------------------------------

    def test_database_tables_populated(self, clean_db, full_config, temp_dirs):
        """All relevant tables should have data after pipeline completion."""
        with patch("selectinf.pipeline.orchestrator.load_config", return_value=full_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_collect_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool), \
             patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_httpx), \
             patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_nuclei), \
             patch("selectinf.stages.ai_analysis.AIClient", return_value=self._mock_ai_client()):
            orch = PipelineOrchestrator("dummy_config.yaml")
            result = orch.run("example.com")

        task_id = result["task_id"]
        conn = get_db()
        cursor = conn.cursor()

        # task table
        cursor.execute("SELECT * FROM task WHERE id = ?", (task_id,))
        task_row = cursor.fetchone()
        assert task_row is not None
        assert task_row["status"] == "completed"

        # assets table
        cursor.execute("SELECT COUNT(*) FROM assets WHERE task_id = ?", (task_id,))
        assert cursor.fetchone()[0] > 0

        # fingerprints table
        cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE task_id = ?", (task_id,))
        assert cursor.fetchone()[0] > 0

        # vulnerabilities table
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE task_id = ?", (task_id,))
        assert cursor.fetchone()[0] > 0

        # ai_analysis table
        cursor.execute("SELECT COUNT(*) FROM ai_analysis WHERE task_id = ?", (task_id,))
        assert cursor.fetchone()[0] >= 2  # report + usage_summary

        conn.close()

    # ------------------------------------------------------------------
    # 3. Report file generated
    # ------------------------------------------------------------------

    def test_report_md_generated(self, clean_db, full_config, temp_dirs):
        """AI Analysis stage should produce report.md in work/{task_id}/."""
        work_dir, output_dir = temp_dirs

        with patch("selectinf.pipeline.orchestrator.load_config", return_value=full_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_collect_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool), \
             patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_httpx), \
             patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_nuclei), \
             patch("selectinf.stages.ai_analysis.AIClient", return_value=self._mock_ai_client()):
            orch = PipelineOrchestrator("dummy_config.yaml")
            result = orch.run("example.com")

        task_id = result["task_id"]
        report_path = os.path.join(work_dir, str(task_id), "report.md")
        assert os.path.exists(report_path), f"report.md not found at {report_path}"

        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert len(content) > 0

    # ------------------------------------------------------------------
    # 4. Stage chaining — output paths flow correctly
    # ------------------------------------------------------------------

    def test_stage_output_path_chaining(self, clean_db, full_config, temp_dirs):
        """Each stage's output_path should be passed as next stage's input_path."""
        with patch("selectinf.pipeline.orchestrator.load_config", return_value=full_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_collect_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool), \
             patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_httpx), \
             patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_nuclei), \
             patch("selectinf.stages.ai_analysis.AIClient", return_value=self._mock_ai_client()):
            orch = PipelineOrchestrator("dummy_config.yaml")
            result = orch.run("example.com")

        collect_out = result["results"]["collect"]["output_path"]
        fingerprint_out = result["results"]["fingerprint"]["output_path"]
        vulnscan_out = result["results"]["vulnscan"]["output_path"]
        ai_out = result["results"]["ai_analysis"]["output_path"]

        # Each stage should have produced an output path
        assert collect_out is not None
        assert fingerprint_out is not None
        assert vulnscan_out is not None
        assert ai_out is not None

        # VulnScan output should be a .json file
        assert vulnscan_out.endswith("vulnerabilities.json")
        # AI output should be report.md
        assert ai_out.endswith("report.md")

    # ------------------------------------------------------------------
    # 5. Partial failure tolerance
    # ------------------------------------------------------------------

    def test_pipeline_continues_on_fingerprint_partial(self, clean_db, full_config, temp_dirs):
        """Pipeline should continue even if fingerprint stage returns partial."""
        def failing_httpx(cmd, description, timeout=10, cwd=None, env=None, retries=0):
            from selectinf.core.tool_runner import ToolResult
            return ToolResult(success=False, stdout="", stderr="timeout", exit_code=-1, elapsed=10.0)

        with patch("selectinf.pipeline.orchestrator.load_config", return_value=full_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_collect_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool), \
             patch("selectinf.stages.fingerprint.run_tool", side_effect=failing_httpx), \
             patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_nuclei), \
             patch("selectinf.stages.ai_analysis.AIClient", return_value=self._mock_ai_client()):
            orch = PipelineOrchestrator("dummy_config.yaml")
            result = orch.run("example.com")

        # Overall status should be partial (not failed)
        assert result["status"] in ("partial", "success")
        # Later stages should still execute
        assert "vulnscan" in result["results"]
        assert "ai_analysis" in result["results"]

    # ------------------------------------------------------------------
    # 6. Disabled stage skipping
    # ------------------------------------------------------------------

    def test_disabled_stage_skipped(self, clean_db, temp_dirs):
        """When a stage is disabled, it should be skipped without error."""
        work_dir, output_dir = temp_dirs
        cfg = PipelineConfig(
            collect={
                "subfinder": ToolConfig(enabled=True, timeout=5, retries=0),
                "amass": ToolConfig(enabled=True, timeout=5, retries=0),
                "oneforall": ToolConfig(enabled=True, timeout=5, retries=0),
                "massdns": ToolConfig(enabled=True, timeout=5, retries=0),
                "ksubdomain": ToolConfig(enabled=True, timeout=5, retries=0),
                "jsfinder": ToolConfig(enabled=True, timeout=5, retries=0, extra={"max_iterations": 1}),
            },
            fingerprint={
                "httpx": ToolConfig(enabled=True, timeout=10, retries=0, extra={"ports": [80, 443]})
            },
            vulnscan={},
            ai={},
            concurrency=2,
            work_dir=work_dir,
            output_dir=output_dir,
            stages={
                "collect": True,
                "fingerprint": True,
                "vulnscan": False,   # disabled
                "ai_analysis": False,  # disabled
            },
        )

        with patch("selectinf.pipeline.orchestrator.load_config", return_value=cfg), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_collect_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool), \
             patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_httpx):
            orch = PipelineOrchestrator("dummy_config.yaml")
            result = orch.run("example.com")

        assert result["results"]["vulnscan"]["status"] == "skipped"
        assert result["results"]["ai_analysis"]["status"] == "skipped"
        assert result["status"] == "success"

    # ------------------------------------------------------------------
    # 7. Task FSM final state
    # ------------------------------------------------------------------

    def test_task_fsm_final_state_completed(self, clean_db, full_config, temp_dirs):
        """Task status in DB should be 'completed' after pipeline finishes."""
        with patch("selectinf.pipeline.orchestrator.load_config", return_value=full_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_collect_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool), \
             patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_httpx), \
             patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_nuclei), \
             patch("selectinf.stages.ai_analysis.AIClient", return_value=self._mock_ai_client()):
            orch = PipelineOrchestrator("dummy_config.yaml")
            result = orch.run("example.com")

        task_id = result["task_id"]
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT status, total_subdomains, total_fingerprints, total_vulns FROM task WHERE id = ?", (task_id,))
        row = cursor.fetchone()
        conn.close()

        assert row["status"] == "completed"
        assert row["total_subdomains"] > 0
        assert row["total_fingerprints"] > 0
        assert row["total_vulns"] > 0

    # ------------------------------------------------------------------
    # 8. No root directory pollution
    # ------------------------------------------------------------------

    def test_no_root_pollution(self, clean_db, full_config, temp_dirs):
        """Pipeline should not create files in project root."""
        import glob
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        before_txt = set(glob.glob(os.path.join(root, "*.txt")))
        before_json = set(glob.glob(os.path.join(root, "*.json")))
        before_md = set(glob.glob(os.path.join(root, "*.md")))

        with patch("selectinf.pipeline.orchestrator.load_config", return_value=full_config), \
             patch("selectinf.stages.collect.run_tool", side_effect=self._mock_collect_tool), \
             patch("selectinf.stages.collect.run_pipe_tool", side_effect=self._mock_pipe_tool), \
             patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_httpx), \
             patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_nuclei), \
             patch("selectinf.stages.ai_analysis.AIClient", return_value=self._mock_ai_client()):
            orch = PipelineOrchestrator("dummy_config.yaml")
            orch.run("example.com")

        after_txt = set(glob.glob(os.path.join(root, "*.txt")))
        after_json = set(glob.glob(os.path.join(root, "*.json")))
        after_md = set(glob.glob(os.path.join(root, "*.md")))

        assert not (after_txt - before_txt), f"Root polluted with .txt: {after_txt - before_txt}"
        assert not (after_json - before_json), f"Root polluted with .json: {after_json - before_json}"
        assert not (after_md - before_md), f"Root polluted with .md: {after_md - before_md}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
