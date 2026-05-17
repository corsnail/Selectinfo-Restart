# selectinf/core/config.py
# Pipeline configuration dataclasses and YAML loader

from dataclasses import dataclass, field
from typing import Dict, List, Any
import os
import yaml

from selectinf import get_logger

logger = get_logger("core.config")


@dataclass
class ToolConfig:
    """Configuration for a single tool. Supports arbitrary extra fields via kwargs."""
    enabled: bool = True
    timeout: int = 300
    retries: int = 1
    extra_args: List[str] = field(default_factory=list)
    # Capture any additional tool-specific fields (names_file, resolvers_file,
    # ports, tech_detect, threads, severity_filter, rate_limit, bulk_size, etc.)
    extra: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ToolConfig":
        """Build ToolConfig from a dict, separating known fields from extras."""
        known = {
            "enabled": d.get("enabled", True),
            "timeout": d.get("timeout", 300),
            "retries": d.get("retries", 1),
            "extra_args": d.get("extra_args", []),
        }
        extra = {k: v for k, v in d.items()
                 if k not in ("enabled", "timeout", "retries", "extra_args")}
        return ToolConfig(**known, extra=extra)


@dataclass
class PipelineConfig:
    """Top-level pipeline configuration."""
    collect: Dict[str, ToolConfig] = field(default_factory=dict)
    fingerprint: Dict[str, ToolConfig] = field(default_factory=dict)
    vulnscan: Dict[str, ToolConfig] = field(default_factory=dict)
    ai: Dict[str, Any] = field(default_factory=dict)
    concurrency: int = 4
    output_dir: str = "output"
    work_dir: str = "work"


def _load_stage_tools(stage_data: Any) -> Dict[str, ToolConfig]:
    """
    Convert a stage dict (like collect, fingerprint, vulnscan) into
    a dict of tool_name -> ToolConfig.

    Handles two layouts seen in pipeline_config.yaml:
      1. { "tools": { "subfinder": {...}, ... } }   <- collect
      2. { "httpx": {...}, "port_scan": {...} }     <- fingerprint, vulnscan
    """
    if isinstance(stage_data, dict):
        # Layout 1: explicit "tools" wrapper
        if "tools" in stage_data:
            raw = stage_data["tools"]
        else:
            raw = stage_data
        return {name: ToolConfig.from_dict(cfg) for name, cfg in raw.items()}
    return {}


def load_config(path: str = "pipeline_config.yaml") -> PipelineConfig:
    """
    Load and deserialize pipeline_config.yaml into a PipelineConfig object.

    Args:
        path: Path to the YAML config file (default: pipeline_config.yaml in cwd).

    Returns:
        PipelineConfig instance.

    Raises:
        FileNotFoundError: if the config file does not exist.
    """
    # Resolve to absolute path if relative
    if not os.path.isabs(path):
        # Resolve relative to project root (two levels up from selectinf/core/)
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        path = os.path.join(project_root, path)

    if not os.path.exists(path):
        logger.error(f"Config file not found: {path}")
        raise FileNotFoundError(f"Pipeline config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not raw:
        raise ValueError(f"Empty or invalid YAML config: {path}")

    # Top-level "pipeline" section
    pipe = raw.get("pipeline", {})
    concurrency = pipe.get("concurrency", 4)
    output_dir = pipe.get("output_dir", "output")
    work_dir = pipe.get("work_dir", "work")

    collect = _load_stage_tools(raw.get("collect", {}))
    fingerprint = _load_stage_tools(raw.get("fingerprint", {}))
    vulnscan = _load_stage_tools(raw.get("vulnscan", {}))

    # AI section is free-form; store as plain dict
    ai = raw.get("ai", {})

    logger.info(
        f"Loaded config: concurrency={concurrency}, "
        f"collect={len(collect)} tools, "
        f"fingerprint={len(fingerprint)} tools, "
        f"vulnscan={len(vulnscan)} tools"
    )

    return PipelineConfig(
        collect=collect,
        fingerprint=fingerprint,
        vulnscan=vulnscan,
        ai=ai,
        concurrency=concurrency,
        output_dir=output_dir,
        work_dir=work_dir,
    )