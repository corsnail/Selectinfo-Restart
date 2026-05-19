#!/usr/bin/env python3
"""Tests for ModePreset configuration overrides."""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from selectinf.core.config import (
    load_config, ModePreset, apply_mode_preset, PipelineConfig, ToolConfig
)


@pytest.fixture
def base_config():
    """Build a minimal PipelineConfig with all 6 collect tools."""
    return PipelineConfig(
        collect={
            "subfinder": ToolConfig(enabled=True),
            "amass": ToolConfig(enabled=True, extra_args=["-v", "-brute", "-active"]),
            "oneforall": ToolConfig(enabled=True),
            "massdns": ToolConfig(enabled=True),
            "ksubdomain": ToolConfig(enabled=True),
            "jsfinder": ToolConfig(enabled=True, extra={"max_iterations": 5}),
        },
        fingerprint={},
        vulnscan={},
        ai={},
    )


class TestModePreset:
    """TDD acceptance for mode preset tool enable/disable logic."""

    # 1. Quick mode disables overlap
    def test_quick_mode_disables_overlap(self, base_config):
        apply_mode_preset(base_config, ModePreset.QUICK)
        assert base_config.collect["amass"].enabled is True
        assert base_config.collect["massdns"].enabled is True
        assert base_config.collect["jsfinder"].enabled is True
        assert base_config.collect["subfinder"].enabled is False
        assert base_config.collect["oneforall"].enabled is False
        assert base_config.collect["ksubdomain"].enabled is False

    # 2. Full mode enables everything
    def test_full_mode_enables_everything(self, base_config):
        # Start with some disabled
        base_config.collect["subfinder"].enabled = False
        apply_mode_preset(base_config, ModePreset.FULL)
        assert all(t.enabled for t in base_config.collect.values())

    # 3. Passive mode strips brute-force flags
    def test_passive_mode_strips_brute_args(self, base_config):
        apply_mode_preset(base_config, ModePreset.PASSIVE)
        assert base_config.collect["amass"].enabled is True
        assert "-brute" not in base_config.collect["amass"].extra_args
        assert "-active" not in base_config.collect["amass"].extra_args
        assert base_config.collect["massdns"].enabled is False
        assert base_config.collect["subfinder"].enabled is False
        assert base_config.collect["jsfinder"].enabled is True

    # 4. Custom mode leaves config untouched
    def test_custom_mode_no_op(self, base_config):
        before = {name: cfg.enabled for name, cfg in base_config.collect.items()}
        apply_mode_preset(base_config, ModePreset.CUSTOM)
        after = {name: cfg.enabled for name, cfg in base_config.collect.items()}
        assert before == after

    # 5. Quick mode preserves amass extra_args
    def test_quick_mode_preserves_amass_args(self, base_config):
        original = list(base_config.collect["amass"].extra_args)
        apply_mode_preset(base_config, ModePreset.QUICK)
        assert base_config.collect["amass"].extra_args == original


class TestLoadConfigWithMode:
    """Integration tests for load_config() accepting mode parameter."""

    # 6. load_config accepts quick mode
    def test_load_config_quick_mode(self):
        cfg = load_config(mode="quick")
        assert cfg.collect["amass"].enabled is True
        assert cfg.collect["subfinder"].enabled is False

    # 7. load_config accepts full mode
    def test_load_config_full_mode(self):
        cfg = load_config(mode="full")
        assert cfg.collect["subfinder"].enabled is True
        assert cfg.collect["oneforall"].enabled is True

    # 8. load_config accepts passive mode
    def test_load_config_passive_mode(self):
        cfg = load_config(mode="passive")
        assert cfg.collect["amass"].enabled is True
        assert "-brute" not in cfg.collect["amass"].extra_args
        assert cfg.collect["massdns"].enabled is False

    # 9. load_config accepts custom mode
    def test_load_config_custom_mode(self):
        cfg = load_config(mode="custom")
        # Should respect YAML defaults (subfinder/oneforall/ksubdomain disabled)
        assert cfg.collect["subfinder"].enabled is False

    # 10. load_config rejects invalid mode
    def test_load_config_invalid_mode_raises(self):
        with pytest.raises(ValueError) as exc_info:
            load_config(mode="invalid")
        assert "Invalid mode" in str(exc_info.value)

    # 11. load_config without mode uses YAML defaults
    def test_load_config_no_mode_uses_yaml_defaults(self):
        cfg = load_config()
        assert cfg.collect["subfinder"].enabled is False
        assert cfg.collect["amass"].enabled is True

    # 12. ModePreset enum values
    def test_mode_preset_enum_values(self):
        assert ModePreset.QUICK.value == "quick"
        assert ModePreset.FULL.value == "full"
        assert ModePreset.PASSIVE.value == "passive"
        assert ModePreset.CUSTOM.value == "custom"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
