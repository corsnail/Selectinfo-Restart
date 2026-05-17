#!/usr/bin/env python3
"""TDD test suite for FingerprintStage (Phase 3)."""

import os
import sys
import json
import pytest
from unittest.mock import patch

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from selectinf.stages.fingerprint import FingerprintStage
from selectinf.stages.base import StageResult
from selectinf.core.config import PipelineConfig, ToolConfig
from selectinf.core.tool_runner import ToolResult
from selectinf.output.sqlite_manager import init_db, get_db, save_fingerprint


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
    """Build a PipelineConfig with fingerprint httpx settings."""
    work_dir, output_dir = temp_dirs
    cfg = PipelineConfig(
        collect={},
        fingerprint={
            "httpx": ToolConfig(
                enabled=True,
                timeout=10,
                retries=0,
                extra={
                    "ports": [80, 443, 8080, 8443],
                    "tech_detect": True,
                    "follow_redirects": True,
                    "threads": 20,
                },
            )
        },
        vulnscan={},
        ai={},
        concurrency=4,
        work_dir=work_dir,
        output_dir=output_dir,
    )
    return cfg


@pytest.fixture
def fingerprint_stage(mock_config):
    return FingerprintStage(mock_config)


class TestFingerprintStage:
    """TDD acceptance criteria for Phase 3 fingerprinting stage."""

    @staticmethod
    def _mock_run_tool(cmd, description, timeout=10, cwd=None, env=None, retries=0):
        try:
            out_idx = cmd.index("-o") + 1
            out_path = cmd[out_idx]
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            fake_data = [
                {
                    "url": "http://example.com",
                    "host": "example.com",
                    "port": 80,
                    "status_code": 200,
                    "title": "Example",
                    "content_type": "text/html",
                    "webserver": "nginx",
                    "tech": ["nginx", "php"],
                    "waf": "cloudflare",
                    "time": "1.23s",
                }
            ]
            with open(out_path, "w", encoding="utf-8") as f:
                for item in fake_data:
                    f.write(json.dumps(item) + "\n")
        except ValueError:
            pass
        return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

    def test_execute_returns_stage_result_success(self, fingerprint_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("example.com\n")

        with patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.fingerprint.save_fingerprint"):
            result = fingerprint_stage.execute(1, input_path)

        assert isinstance(result, StageResult)
        assert result.status == "success"
        assert result.items_processed > 0
        assert result.items_output > 0
        assert result.output_path is not None
        assert os.path.exists(result.output_path)

    def test_httpx_command_generation(self, fingerprint_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("example.com\n")

        captured_cmd = []

        def capture_cmd(cmd, description, timeout=10, cwd=None, env=None, retries=0):
            captured_cmd.extend(cmd)
            return self._mock_run_tool(cmd, description, timeout, cwd, env, retries)

        with patch("selectinf.stages.fingerprint.run_tool", side_effect=capture_cmd), \
             patch("selectinf.stages.fingerprint.save_fingerprint"):
            fingerprint_stage.execute(1, input_path)

        assert any("httpx" in str(arg).lower() for arg in captured_cmd)
        assert "-l" in captured_cmd
        assert "-ports" in captured_cmd
        assert "-o" in captured_cmd
        assert "-json" in captured_cmd
        assert "-threads" in captured_cmd
        assert "-tech-detect" in captured_cmd
        assert "-follow-redirects" in captured_cmd
        assert "-timeout" in captured_cmd
        assert "-no-color" in captured_cmd

    def test_json_lines_parsed_and_mapped(self, fingerprint_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("example.com\n")

        with patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.fingerprint.save_fingerprint") as mock_save:
            fingerprint_stage.execute(1, input_path)

        assert mock_save.called
        call_kwargs = mock_save.call_args[1]
        assert call_kwargs.get("url") == "http://example.com"
        assert call_kwargs.get("status_code") == 200
        assert call_kwargs.get("title") == "Example"
        assert call_kwargs.get("content_type") == "text/html"
        assert call_kwargs.get("server_header") == "nginx"
        assert call_kwargs.get("waf_detected") == "cloudflare"

    def test_tech_stack_stored_as_json_string(self, fingerprint_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("example.com\n")

        with patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.fingerprint.save_fingerprint") as mock_save:
            fingerprint_stage.execute(1, input_path)

        assert mock_save.called
        tech_stack = mock_save.call_args[1].get("tech_stack")
        assert isinstance(tech_stack, str)
        parsed = json.loads(tech_stack)
        assert parsed == ["nginx", "php"]

    def test_response_time_ms_conversion(self, fingerprint_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("example.com\n")

        with patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.fingerprint.save_fingerprint") as mock_save:
            fingerprint_stage.execute(1, input_path)

        assert mock_save.called
        response_time_ms = mock_save.call_args[1].get("response_time_ms")
        assert response_time_ms == 1230
        assert isinstance(response_time_ms, int)

    def test_fingerprints_json_output(self, fingerprint_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("example.com\n")

        with patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.fingerprint.save_fingerprint"):
            result = fingerprint_stage.execute(1, input_path)

        fingerprints_json = os.path.join(work_dir, "1", "fingerprints.json")
        assert os.path.exists(fingerprints_json)
        with open(fingerprints_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) > 0
        assert data[0]["url"] == "http://example.com"
        assert data[0]["status_code"] == 200

    def test_missing_httpx_binary_returns_partial(self, fingerprint_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("example.com\n")

        with patch("selectinf.stages.fingerprint.run_tool", return_value=None), \
             patch("selectinf.stages.fingerprint.save_fingerprint") as mock_save:
            result = fingerprint_stage.execute(1, input_path)

        assert isinstance(result, StageResult)
        assert result.status == "partial"
        assert len(result.errors) > 0
        assert not mock_save.called

    def test_empty_domain_file_returns_success_zero_items(self, fingerprint_stage, clean_db, temp_dirs):
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            pass  # empty file

        with patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.fingerprint.save_fingerprint") as mock_save:
            result = fingerprint_stage.execute(1, input_path)

        assert isinstance(result, StageResult)
        assert result.status == "success"
        assert result.items_processed == 0
        assert result.items_output == 0
        assert not mock_save.called

    def test_url_target_generation_with_ports(self, fingerprint_stage):
        domains = ["example.com", "sub.example.com"]
        ports = [80, 443, 8080, 8443]
        targets = fingerprint_stage._build_targets(domains, ports)

        assert isinstance(targets, list)
        assert len(targets) == 8
        assert "http://example.com" in targets
        assert "https://example.com" in targets
        assert "http://example.com:8080" in targets
        assert "https://example.com:8443" in targets
        assert "http://sub.example.com" in targets
        assert "https://sub.example.com" in targets
        assert "http://sub.example.com:8080" in targets
        assert "https://sub.example.com:8443" in targets

    def test_no_root_txt_pollution(self, fingerprint_stage, clean_db, temp_dirs):
        import glob
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        before_txt = set(glob.glob(os.path.join(root, "*.txt")))
        before_json = set(glob.glob(os.path.join(root, "*.json")))

        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("example.com\n")

        with patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.fingerprint.save_fingerprint"):
            result = fingerprint_stage.execute(1, input_path)

        after_txt = set(glob.glob(os.path.join(root, "*.txt")))
        after_json = set(glob.glob(os.path.join(root, "*.json")))
        new_txt = after_txt - before_txt
        new_json = after_json - before_json
        assert not new_txt, f"Root polluted with new .txt files: {new_txt}"
        assert not new_json, f"Root polluted with new .json files: {new_json}"
        assert "fingerprints.json" in result.output_path

    def test_httpx_disabled_returns_skipped(self, mock_config, temp_dirs):
        """When httpx is disabled, stage should return skipped status."""
        work_dir, output_dir = temp_dirs
        # Override config to disable httpx
        cfg = PipelineConfig(
            collect={},
            fingerprint={
                "httpx": ToolConfig(
                    enabled=False,
                    timeout=10,
                    retries=0,
                    extra={"ports": [80, 443], "threads": 20},
                )
            },
            vulnscan={},
            ai={},
            concurrency=4,
            work_dir=work_dir,
            output_dir=output_dir,
        )
        stage = FingerprintStage(cfg)
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("example.com\n")

        result = stage.execute(1, input_path)
        assert isinstance(result, StageResult)
        assert result.status == "skipped"
        assert result.items_processed == 1
        assert result.items_output == 0

    def test_missing_input_file_returns_success_zero(self, fingerprint_stage, clean_db, temp_dirs):
        """When input file does not exist, stage should return success with 0 items."""
        work_dir, _ = temp_dirs
        missing_path = os.path.join(work_dir, "nonexistent.txt")

        result = fingerprint_stage.execute(1, missing_path)
        assert isinstance(result, StageResult)
        assert result.status == "success"
        assert result.items_processed == 0
        assert result.items_output == 0

    def test_malformed_json_line_skipped(self, fingerprint_stage, clean_db, temp_dirs):
        """Malformed JSON Lines in httpx output should be skipped gracefully."""
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("example.com\n")

        def mock_with_bad_json(cmd, description, timeout=10, cwd=None, env=None, retries=0):
            try:
                out_idx = cmd.index("-o") + 1
                out_path = cmd[out_idx]
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write("not valid json\n")
                    f.write(json.dumps({"url": "http://example.com", "status_code": 200}) + "\n")
                    f.write("{ broken\n")
            except ValueError:
                pass
            return ToolResult(success=True, stdout="", stderr="", exit_code=0, elapsed=0.1)

        with patch("selectinf.stages.fingerprint.run_tool", side_effect=mock_with_bad_json), \
             patch("selectinf.stages.fingerprint.save_fingerprint") as mock_save:
            result = fingerprint_stage.execute(1, input_path)

        assert result.status == "success"
        assert result.items_output == 1  # Only the valid JSON line
        assert mock_save.call_count == 1

    def test_nuclei_targets_txt_generated(self, fingerprint_stage, clean_db, temp_dirs):
        """nuclei_targets.txt should be written with discovered URLs."""
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("example.com\n")

        with patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_run_tool), \
             patch("selectinf.stages.fingerprint.save_fingerprint"):
            result = fingerprint_stage.execute(1, input_path)

        nuclei_path = os.path.join(work_dir, "1", "nuclei_targets.txt")
        assert os.path.exists(nuclei_path), f"nuclei_targets.txt not found at {nuclei_path}"
        with open(nuclei_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        assert "http://example.com" in lines

    def test_fingerprints_table_populated(self, fingerprint_stage, clean_db, temp_dirs):
        """Verify that fingerprints are actually persisted to SQLite (no mock)."""
        work_dir, _ = temp_dirs
        input_path = os.path.join(work_dir, "domain_example.com.txt")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("example.com\n")

        # Only mock run_tool; let save_fingerprint hit the real DB
        with patch("selectinf.stages.fingerprint.run_tool", side_effect=self._mock_run_tool):
            result = fingerprint_stage.execute(1, input_path)

        assert result.status == "success"
        assert result.items_output > 0

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE task_id = ?", (1,))
        count = cursor.fetchone()[0]
        conn.close()
        assert count > 0, "fingerprints table should be populated with real data"

    def test_read_domains_strips_url_scheme(self, fingerprint_stage):
        """_read_domains should extract hostname from URL lines."""
        # Simulate a file that contains URLs (legacy output from url_converter.py)
        work_dir = os.path.dirname(os.path.abspath(__file__))
        test_file = os.path.join(work_dir, "_test_urls.txt")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("http://example.com\n")
            f.write("https://sub.example.com:8443/path\n")
            f.write("example.com\n")
        try:
            domains = fingerprint_stage._read_domains(test_file)
            assert "example.com" in domains
            assert "sub.example.com" in domains
            assert "http://example.com" not in domains
            assert len(domains) == 3
        finally:
            os.remove(test_file)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
