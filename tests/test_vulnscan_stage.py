#!/usr/bin/env python3
"""TDD test suite for VulnScanStage (Phase 4)."""

import os
import sys
import json
import pytest
from unittest.mock import patch

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from selectinf.stages.vulnscan import VulnScanStage
from selectinf.stages.base import StageResult
from selectinf.core.config import PipelineConfig, ToolConfig
from selectinf.core.tool_runner import ToolResult
from selectinf.output.sqlite_manager import init_db, get_db, save_vulnerability


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
    db_path = tmp_path / "test_selectinf.db"
    import selectinf.output.sqlite_manager as sm
    orig_db_path = sm.DB_PATH
    sm.DB_PATH = str(db_path)
    init_db()
    yield db_path
    sm.DB_PATH = orig_db_path


@pytest.fixture
def mock_config(temp_dirs):
    """Build a PipelineConfig with vulnscan nuclei settings."""
    work_dir, output_dir = temp_dirs
    cfg = PipelineConfig(
        collect={},
        fingerprint={},
        vulnscan={
            "nuclei": ToolConfig(
                enabled=True,
                timeout=1800,
                retries=1,
                extra={
                    "binary_path": "tools/nuclei/nuclei",
                    "templates_dir": "nuclei-templates",
                    "severity_filter": ["critical", "high", "medium"],
                    "rate_limit": 50,
                    "threads": 10,
                    "bulk_size": 100,
                },
            )
        },
        ai={},
        concurrency=4,
        work_dir=work_dir,
        output_dir=output_dir,
    )
    return cfg


@pytest.fixture
def vulnscan_stage(mock_config):
    return VulnScanStage(mock_config)


class TestVulnScanStage:
    """TDD acceptance criteria for Phase 4 vulnerability scanning stage."""

    @staticmethod
    def _mock_run_tool(cmd, description, timeout=1800, cwd=None, env=None, retries=0):
        try:
            out_idx = cmd.index("-o") + 1
            out_path = cmd[out_idx]
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            fake = {
                "template-id": "CVE-2024-1234",
                "template-path": "http/cves/2024/CVE-2024-1234.yaml",
                "info": {
                    "name": "Test Vulnerability",
                    "severity": "high",
                    "description": "A test vulnerability for unit testing",
                    "classification": {"cvss-score": 8.5},
                },
                "host": "https://example.com",
                "matched-at": "https://example.com/vulnerable",
                "extracted-results": ["secret123"],
                "ip": "1.2.3.4",
            }
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(fake) + "\n")
        except ValueError:
            pass
        return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

    # ------------------------------------------------------------------
    # 1. Basic success
    # ------------------------------------------------------------------

    def test_execute_returns_stage_result_success(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.vulnscan.save_vulnerability"):
            result = vulnscan_stage.execute(1, input_path)

        assert isinstance(result, StageResult)
        assert result.status == "success"
        assert result.items_processed > 0
        assert result.items_output > 0
        assert result.output_path is not None

    # ------------------------------------------------------------------
    # 2. Command generation
    # ------------------------------------------------------------------

    def test_nuclei_command_generation(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        captured_cmd = []

        def capture_cmd(cmd, description, timeout=1800, cwd=None, env=None, retries=0):
            captured_cmd.extend(cmd)
            return self._mock_run_tool(cmd, description, timeout, cwd, env, retries)

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=capture_cmd), \
             patch("selectinf.stages.vulnscan.save_vulnerability"):
            vulnscan_stage.execute(1, input_path)

        assert any("nuclei" in str(arg).lower() for arg in captured_cmd)
        assert "-l" in captured_cmd
        assert "-o" in captured_cmd
        assert "-jsonl" in captured_cmd
        assert "-severity" in captured_cmd
        assert "-rl" in captured_cmd
        assert "-c" in captured_cmd
        assert "-bs" in captured_cmd
        assert "-silent" in captured_cmd
        assert "-t" in captured_cmd  # templates_dir is set

    # ------------------------------------------------------------------
    # 3. JSON parsing and DB mapping
    # ------------------------------------------------------------------

    def test_json_lines_parsed_and_mapped(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.vulnscan.save_vulnerability") as mock_save:
            vulnscan_stage.execute(1, input_path)

        assert mock_save.called
        call_kwargs = mock_save.call_args[1]
        assert call_kwargs.get("vuln_id") == "CVE-2024-1234"
        assert call_kwargs.get("url") == "https://example.com"
        assert call_kwargs.get("severity") == "high"
        assert call_kwargs.get("template") == "http/cves/2024/CVE-2024-1234.yaml"

    # ------------------------------------------------------------------
    # 4. Severity filtering
    # ------------------------------------------------------------------

    def test_severity_filtering_excludes_low_info(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        def mock_with_mixed_severity(cmd, description, timeout=1800, cwd=None, env=None, retries=0):
            try:
                out_idx = cmd.index("-o") + 1
                out_path = cmd[out_idx]
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                entries = [
                    {"template-id": "CVE-1", "info": {"severity": "critical"}, "host": "https://a.com"},
                    {"template-id": "CVE-2", "info": {"severity": "high"}, "host": "https://b.com"},
                    {"template-id": "CVE-3", "info": {"severity": "medium"}, "host": "https://c.com"},
                    {"template-id": "CVE-4", "info": {"severity": "low"}, "host": "https://d.com"},
                    {"template-id": "CVE-5", "info": {"severity": "info"}, "host": "https://e.com"},
                ]
                with open(out_path, "w", encoding="utf-8") as f:
                    for e in entries:
                        f.write(json.dumps(e) + "\n")
            except ValueError:
                pass
            return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=mock_with_mixed_severity), \
             patch("selectinf.stages.vulnscan.save_vulnerability") as mock_save:
            result = vulnscan_stage.execute(1, input_path)

        assert result.status == "success"
        assert result.items_output == 3  # critical + high + medium only
        assert mock_save.call_count == 3

    # ------------------------------------------------------------------
    # 5. CVSS extraction
    # ------------------------------------------------------------------

    def test_cvss_score_extracted_from_classification(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.vulnscan.save_vulnerability") as mock_save:
            vulnscan_stage.execute(1, input_path)

        assert mock_save.called
        assert mock_save.call_args[1].get("cvss_score") == 8.5

    # ------------------------------------------------------------------
    # 6. vulnerabilities.json output
    # ------------------------------------------------------------------

    def test_vulnerabilities_json_output(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.vulnscan.save_vulnerability"):
            result = vulnscan_stage.execute(1, input_path)

        vuln_json = os.path.join(work_dir, "1", "vulnerabilities.json")
        assert os.path.exists(vuln_json)
        with open(vuln_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) > 0
        assert data[0]["vuln_id"] == "CVE-2024-1234"

    # ------------------------------------------------------------------
    # 7. Missing binary
    # ------------------------------------------------------------------

    def test_missing_nuclei_binary_returns_partial(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        with patch.object(
            vulnscan_stage, "_resolve_binary", return_value=("", "tools/nuclei/nuclei")
        ), patch("selectinf.stages.vulnscan.save_vulnerability") as mock_save:
            result = vulnscan_stage.execute(1, input_path)

        assert isinstance(result, StageResult)
        assert result.status == "partial"
        assert len(result.errors) > 0
        assert "未找到" in result.errors[0]
        assert not mock_save.called

    # ------------------------------------------------------------------
    # 8. Empty target file
    # ------------------------------------------------------------------

    def test_empty_target_file_returns_success_zero_items(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            pass  # empty file

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.vulnscan.save_vulnerability") as mock_save:
            result = vulnscan_stage.execute(1, input_path)

        assert isinstance(result, StageResult)
        assert result.status == "success"
        assert result.items_processed == 0
        assert result.items_output == 0
        assert not mock_save.called

    # ------------------------------------------------------------------
    # 9. Missing input file
    # ------------------------------------------------------------------

    def test_missing_input_file_returns_success_zero(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        # No nuclei_targets.txt created

        result = vulnscan_stage.execute(1, input_path)
        assert isinstance(result, StageResult)
        assert result.status == "success"
        assert result.items_processed == 0
        assert result.items_output == 0

    # ------------------------------------------------------------------
    # 10. Malformed JSON lines
    # ------------------------------------------------------------------

    def test_malformed_json_line_skipped(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        def mock_with_bad_json(cmd, description, timeout=1800, cwd=None, env=None, retries=0):
            try:
                out_idx = cmd.index("-o") + 1
                out_path = cmd[out_idx]
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write("not valid json\n")
                    f.write(json.dumps({"template-id": "CVE-OK", "info": {"severity": "high"}, "host": "https://ok.com"}) + "\n")
                    f.write("{ broken\n")
            except ValueError:
                pass
            return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=mock_with_bad_json), \
             patch("selectinf.stages.vulnscan.save_vulnerability") as mock_save:
            result = vulnscan_stage.execute(1, input_path)

        assert result.status == "success"
        assert result.items_output == 1
        assert mock_save.call_count == 1

    # ------------------------------------------------------------------
    # 11. Real DB write
    # ------------------------------------------------------------------

    def test_vulnerabilities_table_populated(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        # Only mock run_tool; let save_vulnerability hit the real DB
        with patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_run_tool):
            result = vulnscan_stage.execute(1, input_path)

        assert result.status == "success"
        assert result.items_output > 0

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE task_id = ?", (1,))
        count = cursor.fetchone()[0]
        conn.close()
        assert count > 0, "vulnerabilities table should be populated with real data"

    # ------------------------------------------------------------------
    # 12. Disabled stage
    # ------------------------------------------------------------------

    def test_nuclei_disabled_returns_skipped(self, mock_config, temp_dirs):
        work_dir, output_dir = temp_dirs
        cfg = PipelineConfig(
            collect={},
            fingerprint={},
            vulnscan={
                "nuclei": ToolConfig(
                    enabled=False,
                    timeout=1800,
                    retries=1,
                    extra={
                        "severity_filter": ["critical"],
                        "rate_limit": 50,
                        "threads": 10,
                        "bulk_size": 100,
                    },
                )
            },
            ai={},
            concurrency=4,
            work_dir=work_dir,
            output_dir=output_dir,
        )
        stage = VulnScanStage(cfg)
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        result = stage.execute(1, input_path)
        assert isinstance(result, StageResult)
        assert result.status == "skipped"
        assert result.items_processed == 1
        assert result.items_output == 0

    # ------------------------------------------------------------------
    # 13. No root pollution
    # ------------------------------------------------------------------

    def test_no_root_txt_pollution(self, vulnscan_stage, clean_db, temp_dirs):
        import glob
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        before_txt = set(glob.glob(os.path.join(root, "*.txt")))
        before_json = set(glob.glob(os.path.join(root, "*.json")))

        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.vulnscan.save_vulnerability"):
            result = vulnscan_stage.execute(1, input_path)

        after_txt = set(glob.glob(os.path.join(root, "*.txt")))
        after_json = set(glob.glob(os.path.join(root, "*.json")))
        new_txt = after_txt - before_txt
        new_json = after_json - before_json
        assert not new_txt, f"Root polluted with new .txt files: {new_txt}"
        assert not new_json, f"Root polluted with new .json files: {new_json}"
        assert "vulnerabilities.json" in result.output_path

    # ------------------------------------------------------------------
    # 14. Timeout exit_code -1
    # ------------------------------------------------------------------

    def test_timeout_exit_code_minus_one(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        timeout_result = ToolResult(
            success=False, stdout="", stderr="TimeoutExpired",
            exit_code=-1, elapsed=1800.0
        )

        with patch("selectinf.stages.vulnscan.run_tool", return_value=timeout_result), \
             patch("selectinf.stages.vulnscan.save_vulnerability") as mock_save:
            result = vulnscan_stage.execute(1, input_path)

        assert isinstance(result, StageResult)
        assert result.status == "partial"
        assert len(result.errors) > 0
        assert "超时" in result.errors[0]
        assert not mock_save.called

    # ------------------------------------------------------------------
    # 15. run_tool None returns partial
    # ------------------------------------------------------------------

    def test_run_tool_none_returns_partial(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        with patch("selectinf.stages.vulnscan.run_tool", return_value=None), \
             patch("selectinf.stages.vulnscan.save_vulnerability") as mock_save:
            result = vulnscan_stage.execute(1, input_path)

        assert isinstance(result, StageResult)
        assert result.status == "partial"
        assert len(result.errors) > 0
        assert not mock_save.called

    # ------------------------------------------------------------------
    # 16. Severity filter respects config
    # ------------------------------------------------------------------

    def test_severity_filter_respects_config(self, mock_config, temp_dirs):
        work_dir, _ = temp_dirs
        cfg = PipelineConfig(
            collect={},
            fingerprint={},
            vulnscan={
                "nuclei": ToolConfig(
                    enabled=True,
                    timeout=1800,
                    retries=1,
                    extra={
                        "severity_filter": ["critical"],
                        "rate_limit": 50,
                        "threads": 10,
                        "bulk_size": 100,
                    },
                )
            },
            ai={},
            concurrency=4,
            work_dir=work_dir,
            output_dir="output",
        )
        stage = VulnScanStage(cfg)
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        def mock_with_critical_and_high(cmd, description, timeout=1800, cwd=None, env=None, retries=0):
            try:
                out_idx = cmd.index("-o") + 1
                out_path = cmd[out_idx]
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                entries = [
                    {"template-id": "CVE-CRIT", "info": {"severity": "critical"}, "host": "https://a.com"},
                    {"template-id": "CVE-HIGH", "info": {"severity": "high"}, "host": "https://b.com"},
                ]
                with open(out_path, "w", encoding="utf-8") as f:
                    for e in entries:
                        f.write(json.dumps(e) + "\n")
            except ValueError:
                pass
            return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=mock_with_critical_and_high), \
             patch("selectinf.stages.vulnscan.save_vulnerability") as mock_save:
            result = stage.execute(1, input_path)

        assert result.status == "success"
        assert result.items_output == 1  # Only critical
        assert mock_save.call_count == 1

    # ------------------------------------------------------------------
    # 17. Templates dir empty omits -t flag
    # ------------------------------------------------------------------

    def test_templates_dir_empty_omits_t_flag(self, mock_config, temp_dirs):
        work_dir, _ = temp_dirs
        cfg = PipelineConfig(
            collect={},
            fingerprint={},
            vulnscan={
                "nuclei": ToolConfig(
                    enabled=True,
                    timeout=1800,
                    retries=1,
                    extra={
                        "templates_dir": "",  # Empty
                        "severity_filter": ["critical"],
                        "rate_limit": 50,
                        "threads": 10,
                        "bulk_size": 100,
                    },
                )
            },
            ai={},
            concurrency=4,
            work_dir=work_dir,
            output_dir="output",
        )
        stage = VulnScanStage(cfg)
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        captured_cmd = []

        def capture_cmd(cmd, description, timeout=1800, cwd=None, env=None, retries=0):
            captured_cmd.extend(cmd)
            return self._mock_run_tool(cmd, description, timeout, cwd, env, retries)

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=capture_cmd), \
             patch("selectinf.stages.vulnscan.save_vulnerability"):
            stage.execute(1, input_path)

        assert "-t" not in captured_cmd

    # ------------------------------------------------------------------
    # 18. Extracted results joined as string
    # ------------------------------------------------------------------

    def test_extracted_results_joined_as_string(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.vulnscan.save_vulnerability") as mock_save:
            vulnscan_stage.execute(1, input_path)

        assert mock_save.called
        extracted = mock_save.call_args[1].get("extracted_results")
        assert extracted == "secret123"

    # ------------------------------------------------------------------
    # 19. Missing CVSS defaults to None
    # ------------------------------------------------------------------

    def test_missing_cvss_score_defaults_to_none(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        def mock_without_cvss(cmd, description, timeout=1800, cwd=None, env=None, retries=0):
            try:
                out_idx = cmd.index("-o") + 1
                out_path = cmd[out_idx]
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                fake = {
                    "template-id": "CVE-9999",
                    "template-path": "test.yaml",
                    "info": {"severity": "high", "name": "No CVSS"},
                    "host": "https://example.com",
                }
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(json.dumps(fake) + "\n")
            except ValueError:
                pass
            return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=mock_without_cvss), \
             patch("selectinf.stages.vulnscan.save_vulnerability") as mock_save:
            vulnscan_stage.execute(1, input_path)

        assert mock_save.called
        assert mock_save.call_args[1].get("cvss_score") is None

    # ------------------------------------------------------------------
    # 20. Missing info fields handled gracefully
    # ------------------------------------------------------------------

    def test_missing_info_fields_handled_gracefully(self, vulnscan_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "fingerprints.json")
        target_file = os.path.join(work_dir, "1", "nuclei_targets.txt")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("https://example.com\n")

        def mock_partial(cmd, description, timeout=1800, cwd=None, env=None, retries=0):
            try:
                out_idx = cmd.index("-o") + 1
                out_path = cmd[out_idx]
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                fake = {
                    "template-id": "CVE-PARTIAL",
                    "info": {"severity": "medium"},  # missing description, name
                    "host": "https://example.com",
                }
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(json.dumps(fake) + "\n")
            except ValueError:
                pass
            return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

        with patch("selectinf.stages.vulnscan.run_tool", side_effect=mock_partial), \
             patch("selectinf.stages.vulnscan.save_vulnerability") as mock_save:
            result = vulnscan_stage.execute(1, input_path)

        assert result.status == "success"
        assert result.items_output == 1
        assert mock_save.call_count == 1
        call_kwargs = mock_save.call_args[1]
        assert call_kwargs.get("vuln_id") == "CVE-PARTIAL"
        assert call_kwargs.get("severity") == "medium"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
