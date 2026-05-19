#!/usr/bin/env python3
"""Tests for CLI argument parsing in run.py."""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from run import _build_parser
from selectinf.pipeline.orchestrator import PipelineOrchestrator


class TestCLIArgs:
    """TDD acceptance for CLI argument parsing."""

    # 1. Quick mode with domain
    def test_cli_parser_quick_mode(self):
        p = _build_parser()
        args = p.parse_args(["-d", "example.com", "-m", "quick"])
        assert args.domain == "example.com"
        assert args.mode == "quick"

    # 2. Default mode is quick
    def test_cli_parser_default_mode_is_quick(self):
        p = _build_parser()
        args = p.parse_args(["-d", "example.com"])
        assert args.mode == "quick"

    # 3. Full mode
    def test_cli_parser_full_mode(self):
        p = _build_parser()
        args = p.parse_args(["-d", "example.com", "-m", "full"])
        assert args.mode == "full"

    # 4. Passive mode
    def test_cli_parser_passive_mode(self):
        p = _build_parser()
        args = p.parse_args(["-d", "example.com", "-m", "passive"])
        assert args.mode == "passive"

    # 5. Custom mode
    def test_cli_parser_custom_mode(self):
        p = _build_parser()
        args = p.parse_args(["-d", "example.com", "-m", "custom"])
        assert args.mode == "custom"

    # 6. Legacy flag
    def test_cli_parser_legacy_flag(self):
        p = _build_parser()
        args = p.parse_args(["-d", "example.com", "--legacy"])
        assert args.legacy is True

    # 7. No args defaults to None domain
    def test_cli_parser_no_args_domain_none(self):
        p = _build_parser()
        args = p.parse_args([])
        assert args.domain is None
        assert args.mode == "quick"

    # 8. Invalid mode rejected
    def test_cli_parser_invalid_mode_rejected(self):
        p = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "example.com", "-m", "invalid"])


class TestOrchestratorMode:
    """Integration tests for orchestrator accepting mode."""

    # 9. Orchestrator accepts quick mode
    def test_orchestrator_accepts_quick_mode(self):
        orch = PipelineOrchestrator(mode="quick")
        assert orch.config.collect["subfinder"].enabled is False
        assert orch.config.collect["amass"].enabled is True

    # 10. Orchestrator accepts full mode
    def test_orchestrator_accepts_full_mode(self):
        orch = PipelineOrchestrator(mode="full")
        assert orch.config.collect["subfinder"].enabled is True
        assert orch.config.collect["oneforall"].enabled is True

    # 11. Orchestrator accepts passive mode
    def test_orchestrator_accepts_passive_mode(self):
        orch = PipelineOrchestrator(mode="passive")
        assert orch.config.collect["amass"].enabled is True
        assert "-brute" not in orch.config.collect["amass"].extra_args
        assert orch.config.collect["massdns"].enabled is False

    # 12. Orchestrator default mode respects YAML
    def test_orchestrator_default_respects_yaml(self):
        orch = PipelineOrchestrator()
        assert orch.config.collect["subfinder"].enabled is False
        assert orch.config.collect["amass"].enabled is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
