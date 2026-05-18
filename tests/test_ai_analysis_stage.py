#!/usr/bin/env python3
"""TDD test suite for AIAnalysisStage (Phase 5)."""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from selectinf.stages.ai_analysis import AIAnalysisStage
from selectinf.stages.base import StageResult
from selectinf.core.config import PipelineConfig
from selectinf.output.sqlite_manager import (
    init_db, get_db, save_vulnerability, save_fingerprint, save_ai_analysis,
)


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
    """Build a PipelineConfig with AI settings."""
    work_dir, output_dir = temp_dirs
    cfg = PipelineConfig(
        collect={},
        fingerprint={},
        vulnscan={},
        ai={
            "provider": "openai",
            "base_url": "",
            "api_key_env": "OPENAI_API_KEY",
            "model": "gpt-4o",
            "temperature": 0.3,
            "max_tokens": 4096,
            "timeout": 30,
            "fp_validation": {
                "enabled": True,
                "threshold": 0.7,
            },
            "report": {
                "format": "markdown",
                "include_remediation": True,
                "language": "zh-CN",
            },
        },
        concurrency=4,
        work_dir=work_dir,
        output_dir=output_dir,
        stages={
            "collect": True,
            "fingerprint": True,
            "vulnscan": True,
            "ai_analysis": True,
        },
    )
    return cfg


@pytest.fixture
def ai_stage(mock_config):
    return AIAnalysisStage(mock_config)


# -- Mock helpers --

def _make_mock_client(
    report_text="# Test Report\n\nThis is a test.",
    fp_result=None,
    raise_on_report=None,
):
    """Create a mock AIClient with configurable behavior."""
    if fp_result is None:
        fp_result = {"is_vuln": True, "confidence": 0.9, "reason": "Test validation"}

    mock_client = MagicMock()
    mock_client.model = "gpt-4o"
    mock_client.total_prompt_tokens = 100
    mock_client.total_completion_tokens = 200
    mock_client.total_cost_usd = 0.005

    mock_client.generate_report.return_value = {
        "report": report_text,
        "prompt_tokens": 100,
        "completion_tokens": 200,
        "cost_usd": 0.005,
    }

    mock_client.validate_fp.return_value = {
        **fp_result,
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

    if raise_on_report:
        mock_client.generate_report.side_effect = raise_on_report

    return mock_client


class TestAIAnalysisStage:
    """TDD acceptance criteria for Phase 5 AI analysis stage."""

    # 1. Basic success with data
    def test_execute_returns_success_with_data(self, ai_stage, clean_db, temp_dirs):
        """When vulnerabilities and fingerprints exist, stage should succeed."""
        work_dir, _ = temp_dirs
        task_id = 1
        save_vulnerability(task_id, "CVE-001", "https://example.com", "cve-test",
                           "high", 8.5, "Test vuln", "https://example.com/vuln")
        save_fingerprint(task_id, "https://example.com", "1.2.3.4", 443, 200,
                         "Example", "text/html", "nginx", '["nginx"]')

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            result = ai_stage.execute(task_id, input_path)

        assert isinstance(result, StageResult)
        assert result.status == "success"
        assert result.items_processed > 0
        assert result.items_output == 2  # 1 FP validation + 1 report
        assert result.output_path.endswith("report.md")

    # 2. Empty data handling
    def test_empty_data_generates_placeholder_report(self, ai_stage, clean_db, temp_dirs):
        """When no vulnerabilities or fingerprints, stage should generate a placeholder report."""
        work_dir, _ = temp_dirs
        task_id = 1
        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            result = ai_stage.execute(task_id, input_path)

        assert result.status == "success"
        assert os.path.exists(result.output_path)
        with open(result.output_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "未发现" in content or "test" in content.lower()

    # 3. FP validation enabled
    def test_fp_validation_enabled_calls_validate_fp(self, ai_stage, clean_db, temp_dirs):
        """When fp_validation.enabled=True, validate_fp should be called for each vuln."""
        work_dir, _ = temp_dirs
        task_id = 1
        save_vulnerability(task_id, "CVE-001", "https://a.com", "t1", "high", 8.0)
        save_vulnerability(task_id, "CVE-002", "https://b.com", "t2", "medium", 5.0)

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            mock_client = _make_mock_client()
            MockClient.return_value = mock_client
            ai_stage.execute(task_id, input_path)

        assert mock_client.validate_fp.call_count == 2

    # 4. FP validation disabled
    def test_fp_validation_disabled_skips_validate_fp(self, mock_config, temp_dirs, clean_db):
        """When fp_validation.enabled=False, validate_fp should not be called."""
        mock_config.ai["fp_validation"]["enabled"] = False
        stage = AIAnalysisStage(mock_config)

        work_dir, _ = temp_dirs
        task_id = 1
        save_vulnerability(task_id, "CVE-001", "https://a.com", "t1", "high", 8.0)

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            mock_client = _make_mock_client()
            MockClient.return_value = mock_client
            stage.execute(task_id, input_path)

        mock_client.validate_fp.assert_not_called()

    # 5. Report written to file
    def test_report_md_written_to_work_dir(self, ai_stage, clean_db, temp_dirs):
        """report.md should be written to work/{task_id}/."""
        work_dir, _ = temp_dirs
        task_id = 1
        save_vulnerability(task_id, "CVE-001", "https://a.com", "t1", "high", 8.0)
        save_fingerprint(task_id, "https://a.com", "1.2.3.4", 443, 200, "Test")

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            MockClient.return_value = _make_mock_client(report_text="# Custom Report")
            result = ai_stage.execute(task_id, input_path)

        report_path = os.path.join(work_dir, str(task_id), "report.md")
        assert os.path.exists(report_path)
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "# Custom Report" in content

    # 6. AI analysis saved to SQLite
    def test_ai_analysis_saved_to_sqlite(self, ai_stage, clean_db, temp_dirs):
        """Report and usage records should be saved to ai_analysis table."""
        work_dir, _ = temp_dirs
        task_id = 1
        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            ai_stage.execute(task_id, input_path)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ai_analysis WHERE task_id = ?", (task_id,))
        count = cursor.fetchone()[0]
        conn.close()
        assert count >= 2

    # 7. API timeout handling
    def test_api_timeout_generates_fallback_report(self, ai_stage, clean_db, temp_dirs):
        """When LLM times out, stage should return partial with fallback report."""
        work_dir, _ = temp_dirs
        task_id = 1
        save_vulnerability(task_id, "CVE-001", "https://a.com", "t1", "high", 8.0)
        save_fingerprint(task_id, "https://a.com", "1.2.3.4", 443, 200, "Test")

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            mock_client = _make_mock_client(raise_on_report=TimeoutError("LLM timeout"))
            MockClient.return_value = mock_client
            result = ai_stage.execute(task_id, input_path)

        assert result.status == "partial"
        assert len(result.errors) > 0
        assert "timeout" in result.errors[0].lower() or "超时" in result.errors[0]
        assert os.path.exists(result.output_path)

    # 8. AIClient initialization failure
    def test_client_init_failure_returns_failed(self, ai_stage, clean_db, temp_dirs):
        """When AIClient fails to initialize, stage should return failed."""
        work_dir, _ = temp_dirs
        task_id = 1
        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient", side_effect=Exception("Init failed")):
            result = ai_stage.execute(task_id, input_path)

        assert result.status == "failed"
        assert len(result.errors) > 0
        assert "初始化失败" in result.errors[0]

    # 9. Stage disabled
    def test_stage_disabled_returns_skipped(self, mock_config, temp_dirs, clean_db):
        """When ai_analysis stage is disabled, should return skipped."""
        mock_config.stages["ai_analysis"] = False
        stage = AIAnalysisStage(mock_config)

        work_dir, _ = temp_dirs
        task_id = 1
        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)

        result = stage.execute(task_id, input_path)
        assert result.status == "skipped"

    # 10. AI config empty
    def test_empty_ai_config_returns_skipped(self, mock_config, temp_dirs, clean_db):
        """When ai config is empty, should return skipped."""
        mock_config.ai = {}
        stage = AIAnalysisStage(mock_config)

        work_dir, _ = temp_dirs
        task_id = 1
        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")

        result = stage.execute(task_id, input_path)
        assert result.status == "skipped"

    # 11. FP validation result saved to DB
    def test_fp_validation_result_saved_to_db(self, ai_stage, clean_db, temp_dirs):
        """FP validation results should be saved to ai_analysis table."""
        work_dir, _ = temp_dirs
        task_id = 1
        save_vulnerability(task_id, "CVE-001", "https://a.com", "t1", "high", 8.0)

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            ai_stage.execute(task_id, input_path)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM ai_analysis WHERE task_id = ? AND analysis_type = ?",
            (task_id, "fp_validation")
        )
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 1

    # 12. Vulnerability ai_validated updated
    def test_vulnerability_ai_validated_updated(self, ai_stage, clean_db, temp_dirs):
        """vulnerabilities.ai_validated should be updated after FP validation."""
        work_dir, _ = temp_dirs
        task_id = 1
        save_vulnerability(task_id, "CVE-001", "https://a.com", "t1", "high", 8.0)

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            MockClient.return_value = _make_mock_client(
                fp_result={"is_vuln": True, "confidence": 0.95, "reason": "Confirmed"}
            )
            ai_stage.execute(task_id, input_path)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ai_validated, ai_confidence FROM vulnerabilities WHERE task_id = ? AND vuln_id = ?",
            (task_id, "CVE-001")
        )
        row = cursor.fetchone()
        conn.close()
        assert row["ai_validated"] == 1
        assert row["ai_confidence"] == 0.95

    # 13. Low confidence marks as suspected FP
    def test_low_confidence_marks_as_suspected_fp(self, ai_stage, clean_db, temp_dirs):
        """When confidence < threshold, ai_validated should be 0."""
        work_dir, _ = temp_dirs
        task_id = 1
        save_vulnerability(task_id, "CVE-001", "https://a.com", "t1", "high", 8.0)

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            MockClient.return_value = _make_mock_client(
                fp_result={"is_vuln": False, "confidence": 0.3, "reason": "Likely FP"}
            )
            ai_stage.execute(task_id, input_path)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ai_validated, ai_confidence FROM vulnerabilities WHERE task_id = ? AND vuln_id = ?",
            (task_id, "CVE-001")
        )
        row = cursor.fetchone()
        conn.close()
        assert row["ai_validated"] == 0
        assert row["ai_confidence"] == 0.3

    # 14. No root pollution
    def test_no_root_pollution(self, ai_stage, clean_db, temp_dirs):
        """Stage should not create files in project root."""
        import glob
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        before_txt = set(glob.glob(os.path.join(root, "*.txt")))
        before_md = set(glob.glob(os.path.join(root, "*.md")))

        work_dir, _ = temp_dirs
        task_id = 1
        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            ai_stage.execute(task_id, input_path)

        after_txt = set(glob.glob(os.path.join(root, "*.txt")))
        after_md = set(glob.glob(os.path.join(root, "*.md")))
        assert not (after_txt - before_txt), f"Root polluted with .txt: {after_txt - before_txt}"
        assert not (after_md - before_md), f"Root polluted with .md: {after_md - before_md}"

    # 15. Multiple vulnerabilities processed
    def test_multiple_vulnerabilities_all_validated(self, ai_stage, clean_db, temp_dirs):
        """All vulnerabilities should be validated when FP validation is enabled."""
        work_dir, _ = temp_dirs
        task_id = 1
        for i in range(5):
            save_vulnerability(task_id, f"CVE-{i:03d}", f"https://a{i}.com", f"t{i}",
                               "high", 8.0)

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            mock_client = _make_mock_client()
            MockClient.return_value = mock_client
            ai_stage.execute(task_id, input_path)

        assert mock_client.validate_fp.call_count == 5

    # -- Acceptance report additions (item 5) --

    # 15a. ConnectionError fallback in generate_report
    def test_connection_error_generates_fallback_report(self, ai_stage, clean_db, temp_dirs):
        """When LLM ConnectionError occurs, stage should fallback with partial status."""
        work_dir, _ = temp_dirs
        task_id = 1
        save_vulnerability(task_id, "CVE-001", "https://a.com", "t1", "high", 8.0)
        save_fingerprint(task_id, "https://a.com", "1.2.3.4", 443, 200, "Test")

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            mock_client = _make_mock_client(raise_on_report=ConnectionError("DNS failure"))
            MockClient.return_value = mock_client
            result = ai_stage.execute(task_id, input_path)

        assert result.status == "partial"
        assert len(result.errors) > 0
        assert "connection" in result.errors[0].lower() or "连接" in result.errors[0] or "失败" in result.errors[0]

    # 15b. FP validation fallback on timeout: conservative is_vuln=True
    def test_fp_validation_timeout_fallback(self, ai_stage, clean_db, temp_dirs):
        """When validate_fp raises TimeoutError, result should be conservative (is_vuln=True)."""
        work_dir, _ = temp_dirs
        task_id = 1
        save_vulnerability(task_id, "CVE-001", "https://a.com", "t1", "high", 8.0)

        # Lower threshold so conservative fallback (confidence=0.5) is treated as real
        ai_stage.config.ai["fp_validation"]["threshold"] = 0.5

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        def mock_validate_fp(*args, **kwargs):
            raise TimeoutError("LLM timeout")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            mock_client = _make_mock_client()
            mock_client.validate_fp.side_effect = mock_validate_fp
            MockClient.return_value = mock_client
            result = ai_stage.execute(task_id, input_path)

        assert result.status == "success"
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ai_validated, ai_confidence FROM vulnerabilities WHERE task_id = ? AND vuln_id = ?",
            (task_id, "CVE-001")
        )
        row = cursor.fetchone()
        conn.close()
        assert row["ai_validated"] == 1  # Conservative: assume real on failure
        assert row["ai_confidence"] == 0.5

    # 15c. FP validation fallback on generic exception
    def test_fp_validation_exception_fallback(self, ai_stage, clean_db, temp_dirs):
        """When validate_fp raises generic Exception, result should be conservative."""
        work_dir, _ = temp_dirs
        task_id = 1
        save_vulnerability(task_id, "CVE-001", "https://a.com", "t1", "high", 8.0)

        # Lower threshold so conservative fallback (confidence=0.5) is treated as real
        ai_stage.config.ai["fp_validation"]["threshold"] = 0.5

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        def mock_validate_fp(*args, **kwargs):
            raise RuntimeError("Unexpected error")

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            mock_client = _make_mock_client()
            mock_client.validate_fp.side_effect = mock_validate_fp
            MockClient.return_value = mock_client
            result = ai_stage.execute(task_id, input_path)

        assert result.status == "success"
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ai_validated, ai_confidence FROM vulnerabilities WHERE task_id = ? AND vuln_id = ?",
            (task_id, "CVE-001")
        )
        row = cursor.fetchone()
        conn.close()
        assert row["ai_validated"] == 1
        assert row["ai_confidence"] == 0.5

    # 15d. Same vuln_id on multiple URLs: _update_vuln_ai_result should only update matching URL
    def test_update_vuln_ai_result_respects_url(self, ai_stage, clean_db, temp_dirs):
        """When same vuln_id exists on different URLs, only the matching URL should be updated."""
        work_dir, _ = temp_dirs
        task_id = 1
        # Same CVE on two different endpoints
        save_vulnerability(task_id, "CVE-001", "https://a.com/login", "t1", "high", 8.0)
        save_vulnerability(task_id, "CVE-001", "https://a.com/admin", "t1", "high", 8.0)

        input_path = os.path.join(work_dir, str(task_id), "fingerprints.json")
        os.makedirs(os.path.dirname(input_path), exist_ok=True)
        with open(input_path, "w") as f:
            f.write("[]")

        # Mock validate_fp to return different confidence per URL
        call_count = [0]

        def mock_validate_fp(vuln, fp_context, language):
            call_count[0] += 1
            url = vuln.get("url", "")
            if "login" in url:
                return {"is_vuln": True, "confidence": 0.95, "reason": "Confirmed", "prompt_tokens": 10, "completion_tokens": 5, "cost_usd": 0.001}
            else:
                return {"is_vuln": False, "confidence": 0.3, "reason": "FP", "prompt_tokens": 10, "completion_tokens": 5, "cost_usd": 0.001}

        with patch("selectinf.stages.ai_analysis.AIClient") as MockClient:
            mock_client = _make_mock_client()
            mock_client.validate_fp.side_effect = mock_validate_fp
            MockClient.return_value = mock_client
            ai_stage.execute(task_id, input_path)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT url, ai_validated, ai_confidence FROM vulnerabilities WHERE task_id = ? AND vuln_id = ? ORDER BY url",
            (task_id, "CVE-001")
        )
        rows = cursor.fetchall()
        conn.close()

        assert len(rows) == 2
        # First row (login) should be validated=1, confidence=0.95
        # Second row (admin) should be validated=0, confidence=0.3
        row_map = {row["url"]: row for row in rows}
        assert row_map["https://a.com/login"]["ai_validated"] == 1
        assert row_map["https://a.com/login"]["ai_confidence"] == 0.95
        assert row_map["https://a.com/admin"]["ai_validated"] == 0
        assert row_map["https://a.com/admin"]["ai_confidence"] == 0.3


class TestAIClient:
    """Unit tests for AIClient class."""

    # 16. Provider config resolution
    def test_openai_provider_defaults(self):
        """OpenAI provider should use default base_url and model."""
        from selectinf.ai.client import AIClient
        config = {"provider": "openai", "api_key_env": "TEST_KEY"}
        with patch.dict(os.environ, {"TEST_KEY": "sk-test123"}):
            client = AIClient(config)
        assert client.provider == "openai"
        assert client.model == "gpt-4o"
        assert client.base_url is None

    def test_ollama_provider_defaults(self):
        """Ollama provider should use localhost base_url."""
        from selectinf.ai.client import AIClient
        config = {"provider": "ollama"}
        client = AIClient(config)
        assert client.provider == "ollama"
        assert "localhost:11434" in client.base_url
        assert client.model == "llama3"

    def test_bailian_provider_defaults(self):
        """Bailian provider should use dashscope base_url."""
        from selectinf.ai.client import AIClient
        config = {"provider": "bailian", "api_key_env": "DASHSCOPE_API_KEY"}
        with patch.dict(os.environ, {"DASHSCOPE_API_KEY": "sk-ali123"}):
            client = AIClient(config)
        assert client.provider == "bailian"
        assert "dashscope.aliyuncs.com" in client.base_url
        assert client.model == "qwen-plus"

    # 17. JSON extraction
    def test_extract_json_pure_json(self):
        """Should parse pure JSON."""
        from selectinf.ai.client import AIClient
        raw = '{"is_vuln": true, "confidence": 0.9, "reason": "test"}'
        result = AIClient._extract_json(raw)
        assert result["is_vuln"] is True
        assert result["confidence"] == 0.9

    def test_extract_json_markdown_block(self):
        """Should extract JSON from markdown code block."""
        from selectinf.ai.client import AIClient
        raw = '```json\n{"is_vuln": false, "confidence": 0.3}\n```'
        result = AIClient._extract_json(raw)
        assert result["is_vuln"] is False

    def test_extract_json_markdown_block_no_lang(self):
        """Should extract JSON from ``` block without language tag."""
        from selectinf.ai.client import AIClient
        raw = '```\n{"is_vuln": true}\n```'
        result = AIClient._extract_json(raw)
        assert result["is_vuln"] is True

    def test_extract_json_embedded_in_text(self):
        """Should extract JSON embedded in surrounding text."""
        from selectinf.ai.client import AIClient
        raw = 'Here is the result: {"is_vuln": true, "confidence": 0.8}. Hope this helps!'
        result = AIClient._extract_json(raw)
        assert result["is_vuln"] is True

    def test_extract_json_empty_returns_empty_dict(self):
        """Should return empty dict for empty input."""
        from selectinf.ai.client import AIClient
        result = AIClient._extract_json("")
        assert result == {}

    def test_extract_json_invalid_returns_empty_dict(self):
        """Should return empty dict for unparseable input."""
        from selectinf.ai.client import AIClient
        result = AIClient._extract_json("not json at all {{{")
        assert result == {}

    # 18. Cost estimation
    def test_cost_estimation_gpt4o(self):
        """Should estimate cost correctly for gpt-4o."""
        from selectinf.ai.client import AIClient
        config = {"provider": "openai", "model": "gpt-4o", "api_key_env": "TEST_KEY"}
        with patch.dict(os.environ, {"TEST_KEY": "sk-test"}):
            client = AIClient(config)
        cost = client._estimate_cost(1000, 500)
        expected = (1000 / 1_000_000) * 2.50 + (500 / 1_000_000) * 10.00
        assert abs(cost - expected) < 0.0001

    def test_cost_estimation_ollama_is_free(self):
        """Ollama models should have zero cost."""
        from selectinf.ai.client import AIClient
        config = {"provider": "ollama", "model": "llama3"}
        client = AIClient(config)
        cost = client._estimate_cost(10000, 5000)
        assert cost == 0.0

    def test_cost_estimation_unknown_model_is_free(self):
        """Unknown models should default to zero cost."""
        from selectinf.ai.client import AIClient
        config = {"provider": "openai", "model": "unknown-model", "api_key_env": "TEST_KEY"}
        with patch.dict(os.environ, {"TEST_KEY": "sk-test"}):
            client = AIClient(config)
        cost = client._estimate_cost(1000, 500)
        assert cost == 0.0

    # 19. Ollama timeout auto-extension
    def test_ollama_timeout_extended_for_cold_start(self):
        """Ollama provider should auto-extend timeout to 120s."""
        from selectinf.ai.client import AIClient
        config = {"provider": "ollama", "timeout": 30}
        client = AIClient(config)
        assert client.timeout == 120

    # 20. Usage summary tracking
    def test_usage_summary_tracks_totals(self):
        """Usage summary should track cumulative tokens and cost."""
        from selectinf.ai.client import AIClient
        config = {"provider": "openai", "api_key_env": "TEST_KEY"}
        with patch.dict(os.environ, {"TEST_KEY": "sk-test"}):
            client = AIClient(config)
        client.total_prompt_tokens = 500
        client.total_completion_tokens = 1000
        client.total_cost_usd = 0.012

        summary = client.get_usage_summary()
        assert summary["total_prompt_tokens"] == 500
        assert summary["total_completion_tokens"] == 1000
        assert summary["total_cost_usd"] == 0.012
        assert summary["provider"] == "openai"
        assert summary["model"] == "gpt-4o"

    # -- Acceptance report additions (item 5) --

    # 20a. validate_fp with empty JSON response defaults to is_vuln=True
    def test_validate_fp_empty_json_defaults_to_true(self):
        """When _extract_json returns empty dict, validate_fp should default is_vuln=True."""
        from selectinf.ai.client import AIClient
        config = {"provider": "openai", "api_key_env": "TEST_KEY"}
        with patch.dict(os.environ, {"TEST_KEY": "sk-test"}):
            client = AIClient(config)

        # Mock _chat to return unparseable text
        with patch.object(client, "_chat", return_value={
            "content": "not json at all",
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "cost_usd": 0.001,
        }):
            vuln = {
                "template": "test.yaml",
                "severity": "high",
                "url": "https://example.com",
                "matched_at": "/path",
                "extracted_results": None,
                "cvss_score": 8.0,
                "description": "Test",
            }
            result = client.validate_fp(vuln, None, "zh-CN")

        assert result["is_vuln"] is True
        assert result["confidence"] == 0.5
        assert "无法解析" in result["reason"] or "无法" in result["reason"]

    # 20b. Bailian provider end-to-end validate_fp mock
    def test_bailian_provider_end_to_end_validate_fp(self):
        """Bailian provider should work end-to-end with mocked _chat."""
        from selectinf.ai.client import AIClient
        config = {"provider": "bailian", "api_key_env": "DASHSCOPE_API_KEY"}
        with patch.dict(os.environ, {"DASHSCOPE_API_KEY": "sk-bailian-test"}):
            client = AIClient(config)

        assert client.provider == "bailian"
        assert client.model == "qwen-plus"
        assert "dashscope.aliyuncs.com" in client.base_url

        with patch.object(client, "_chat", return_value={
            "content": '{"is_vuln": false, "confidence": 0.2, "reason": "False positive"}',
            "prompt_tokens": 20,
            "completion_tokens": 10,
            "cost_usd": 0.002,
        }):
            vuln = {
                "template": "test.yaml",
                "severity": "low",
                "url": "https://example.com",
                "matched_at": "/path",
                "extracted_results": None,
                "cvss_score": 3.0,
                "description": "Test",
            }
            result = client.validate_fp(vuln, None, "zh-CN")

        assert result["is_vuln"] is False
        assert result["confidence"] == 0.2
        assert "False positive" in result["reason"]

    # 20c. Ollama api_key_env warning
    def test_ollama_api_key_env_warning(self, caplog):
        """Ollama provider should emit warning when api_key_env is configured."""
        import logging
        from selectinf.ai.client import AIClient
        config = {"provider": "ollama", "api_key_env": "OPENAI_API_KEY"}
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with caplog.at_level(logging.WARNING):
                client = AIClient(config)
        assert client.provider == "ollama"
        assert "不需要" in caplog.text or "ignored" in caplog.text.lower() or "require" in caplog.text.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
