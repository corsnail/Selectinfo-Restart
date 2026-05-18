"""Unified LLM client supporting OpenAI, Ollama, and Alibaba Bailian."""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from openai import OpenAI, APIError, APITimeoutError, APIConnectionError

from selectinf import get_logger
from selectinf.ai.prompts import REPORT_PROMPT, FP_VALIDATION_PROMPT

logger = get_logger("ai.client")

# ── Provider defaults ─────────────────────────────────────────────

_PROVIDER_CONFIG = {
    "openai": {
        "base_url": None,  # SDK default: https://api.openai.com/v1
        "api_key_env": "OPENAI_API_KEY",
        "model": "gpt-4o",
    },
    "ollama": {
        "base_url": "http://localhost:11434/v1",
        "api_key_env": "",  # Ollama doesn't require API key
        "model": "llama3",
    },
    "bailian": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "api_key_env": "DASHSCOPE_API_KEY",
        "model": "qwen-plus",
    },
}

# Cost per 1M tokens (USD) — approximate pricing for estimation
_COST_PER_1M = {
    # OpenAI
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-3.5-turbo": (0.50, 1.50),
    # Bailian / Qwen
    "qwen-plus": (0.06, 0.24),
    "qwen3.6-plus": (0.06, 0.24),
    "qwen-turbo": (0.01, 0.03),
    "qwen-max": (0.28, 0.84),
    # Ollama (free)
    "llama3": (0.0, 0.0),
    "llama3.1": (0.0, 0.0),
    "qwen2.5": (0.0, 0.0),
}


class AIClient:
    """Unified LLM client for report generation and false-positive validation.

    Supports three providers via the OpenAI-compatible API protocol:
    - OpenAI (default base_url)
    - Ollama (http://localhost:11434/v1)
    - Alibaba Bailian (https://dashscope.aliyuncs.com/compatible-mode/v1)

    Usage:
        client = AIClient(config.ai)
        report = client.generate_report(vulns, fingerprints)
        result = client.validate_fp(vuln, fingerprint_context)
    """

    def __init__(self, ai_config: Dict[str, Any]):
        """Initialize the LLM client from pipeline_config.yaml ai section.

        Args:
            ai_config: The "ai" dict from PipelineConfig.ai
        """
        self.provider = ai_config.get("provider", "openai").lower()
        provider_defaults = _PROVIDER_CONFIG.get(self.provider, _PROVIDER_CONFIG["openai"])

        # Resolve base_url: config > provider default > SDK default
        self.base_url = ai_config.get("base_url") or provider_defaults.get("base_url")

        # Resolve API key
        api_key_env = ai_config.get("api_key_env") or provider_defaults.get("api_key_env", "")
        if self.provider == "ollama" and api_key_env:
            logger.warning(
                "Ollama provider does not require an API key; configured api_key_env '%s' will be ignored",
                api_key_env,
            )
        self.api_key = os.environ.get(api_key_env, "") if api_key_env else ""

        # Resolve model
        self.model = ai_config.get("model") or provider_defaults.get("model", "gpt-4o")

        # Other settings
        self.temperature = ai_config.get("temperature", 0.3)
        self.max_tokens = ai_config.get("max_tokens", 4096)
        self.timeout = ai_config.get("timeout", 120)  # seconds; Ollama cold start needs more

        # Ollama-specific: extend timeout for cold start
        if self.provider == "ollama" and self.timeout < 120:
            self.timeout = 120
            logger.info("Ollama provider: 连接超时自动延长至 120s (冷启动兼容)")

        # Token tracking
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_cost_usd = 0.0

        # Initialize OpenAI SDK client
        self._client = self._init_client()

        logger.info(
            "AIClient 初始化: provider=%s, model=%s, base_url=%s",
            self.provider, self.model, self.base_url or "(default)"
        )

    def _init_client(self) -> OpenAI:
        """Create the underlying OpenAI SDK client."""
        kwargs: Dict[str, Any] = {
            "timeout": self.timeout,
        }
        if self.base_url:
            kwargs["base_url"] = self.base_url
        if self.api_key:
            kwargs["api_key"] = self.api_key
        else:
            # Ollama doesn't need a key; OpenAI SDK requires a non-empty string
            kwargs["api_key"] = "ollama"

        try:
            return OpenAI(**kwargs)
        except Exception as e:
            logger.error("OpenAI SDK 客户端初始化失败: %s", e)
            raise

    # ── Core chat method ──────────────────────────────────────────

    def _chat(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = False,
    ) -> Dict[str, Any]:
        """Send a chat completion request and return the raw response dict.

        Args:
            messages: OpenAI-format message list [{"role": "...", "content": "..."}]
            json_mode: If True, request JSON output via response_format

        Returns:
            Dict with keys: content, prompt_tokens, completion_tokens, cost_usd

        Raises:
            APIError on API failures
            TimeoutError on connection timeouts
        """
        request_kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        if json_mode:
            request_kwargs["response_format"] = {"type": "json_object"}

        try:
            response = self._client.chat.completions.create(**request_kwargs)
        except APITimeoutError:
            logger.error("LLM 请求超时 (>%ds, provider=%s)", self.timeout, self.provider)
            raise TimeoutError(f"LLM 请求超时 (>{self.timeout}s)")
        except APIConnectionError as e:
            logger.error("LLM 连接失败 (provider=%s): %s", self.provider, e)
            raise ConnectionError(f"LLM 连接失败: {e}")
        except APIError as e:
            logger.error("LLM API 错误 (provider=%s): %s", self.provider, e)
            raise

        # Extract usage
        usage = response.usage
        prompt_tokens = usage.prompt_tokens if usage else 0
        completion_tokens = usage.completion_tokens if usage else 0
        content = response.choices[0].message.content if response.choices else ""

        # Calculate cost
        cost = self._estimate_cost(prompt_tokens, completion_tokens)

        # Update totals
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_cost_usd += cost

        logger.debug(
            "LLM 调用: prompt_tokens=%d, completion_tokens=%d, cost=$%.4f",
            prompt_tokens, completion_tokens, cost
        )

        return {
            "content": content,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "cost_usd": round(cost, 6),
        }

    # ── Public: Report generation ─────────────────────────────────

    def generate_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        fingerprints: List[Dict[str, Any]],
        language: str = "zh-CN",
        include_remediation: bool = True,
    ) -> Dict[str, Any]:
        """Generate a Markdown security report from vulnerabilities and fingerprints.

        Args:
            vulnerabilities: List of vulnerability dicts from SQLite
            fingerprints: List of fingerprint dicts from SQLite
            language: Report language (default: zh-CN)
            include_remediation: Whether to include remediation advice

        Returns:
            Dict with keys: report (str), prompt_tokens, completion_tokens, cost_usd
        """
        # Build summaries
        fp_summary = self._build_fingerprint_summary(fingerprints)
        vuln_summary = self._build_vulnerability_summary(vulnerabilities)

        # Fill prompt template
        remediation_section = "修复建议 (具体步骤和优先级)" if include_remediation else "无"
        prompt = REPORT_PROMPT.format(
            language=language,
            include_remediation="是" if include_remediation else "否",
            fingerprints_summary=fp_summary,
            vulnerabilities_summary=vuln_summary,
            remediation_section=remediation_section,
        )

        messages = [
            {"role": "system", "content": "你是一名资深网络安全分析师，擅长编写专业的安全评估报告。"},
            {"role": "user", "content": prompt},
        ]

        result = self._chat(messages, json_mode=False)

        return {
            "report": result["content"],
            "prompt_tokens": result["prompt_tokens"],
            "completion_tokens": result["completion_tokens"],
            "cost_usd": result["cost_usd"],
        }

    # ── Public: False-positive validation ─────────────────────────

    def validate_fp(
        self,
        vuln: Dict[str, Any],
        fingerprint_context: Optional[Dict[str, Any]] = None,
        language: str = "zh-CN",
    ) -> Dict[str, Any]:
        """Validate whether a single vulnerability is a false positive.

        Args:
            vuln: Vulnerability dict from SQLite
            fingerprint_context: Optional fingerprint dict for the same URL
            language: Response language (default: zh-CN)

        Returns:
            Dict with keys: is_vuln (bool), confidence (float), reason (str),
                           prompt_tokens, completion_tokens, cost_usd
        """
        fp = fingerprint_context or {}

        prompt = FP_VALIDATION_PROMPT.format(
            template=vuln.get("template", "unknown"),
            severity=vuln.get("severity", "unknown"),
            url=vuln.get("url", "unknown"),
            matched_at=vuln.get("matched_at", "N/A"),
            extracted_results=vuln.get("extracted_results", "无"),
            cvss_score=vuln.get("cvss_score", "N/A"),
            description=vuln.get("description", "无描述"),
            server_header=fp.get("server_header", "未知"),
            tech_stack=fp.get("tech_stack", "未知"),
            waf_detected=fp.get("waf_detected", "未检测"),
            status_code=fp.get("status_code", "未知"),
            language=language,
        )

        messages = [
            {"role": "system", "content": "你是一名安全漏洞验证专家，擅长识别误报。请严格输出 JSON 格式。"},
            {"role": "user", "content": prompt},
        ]

        result = self._chat(messages, json_mode=True)

        # Parse JSON response
        parsed = self._extract_json(result["content"])

        return {
            "is_vuln": parsed.get("is_vuln", True),
            "confidence": float(parsed.get("confidence", 0.5)),
            "reason": parsed.get("reason", "无法解析响应"),
            "prompt_tokens": result["prompt_tokens"],
            "completion_tokens": result["completion_tokens"],
            "cost_usd": result["cost_usd"],
        }

    # ── JSON extraction fallback ──────────────────────────────────

    @staticmethod
    def _extract_json(raw: str) -> Dict[str, Any]:
        """Extract JSON from LLM response with fallback strategies.

        Handles:
        1. Pure JSON
        2. Markdown code block: ```json {...} ```
        3. Markdown code block: ``` {...} ```
        4. JSON embedded in text

        Args:
            raw: Raw LLM response string

        Returns:
            Parsed dict, or empty dict on failure
        """
        if not raw:
            return {}

        # Strategy 1: Try direct parse
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # Strategy 2: Extract from markdown code block (```json or ```)
        code_block_pattern = r"```(?:json)?\s*\n?([\s\S]*?)\n?```"
        match = re.search(code_block_pattern, raw)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Strategy 3: Find first { and last } in the text
        first_brace = raw.find("{")
        last_brace = raw.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            try:
                return json.loads(raw[first_brace:last_brace + 1])
            except json.JSONDecodeError:
                pass

        logger.warning("无法从 LLM 响应中提取 JSON: %s", raw[:200])
        return {}

    # ── Cost estimation ───────────────────────────────────────────

    def _estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate API cost based on token usage and model pricing.

        Args:
            prompt_tokens: Number of input tokens
            completion_tokens: Number of output tokens

        Returns:
            Estimated cost in USD
        """
        pricing = _COST_PER_1M.get(self.model)
        if pricing is None:
            # Unknown model: assume $0 (Ollama-like)
            return 0.0

        input_rate, output_rate = pricing
        cost = (prompt_tokens / 1_000_000) * input_rate + \
               (completion_tokens / 1_000_000) * output_rate
        return round(cost, 6)

    # ── Summary builders ──────────────────────────────────────────

    @staticmethod
    def _build_fingerprint_summary(fingerprints: List[Dict[str, Any]]) -> str:
        """Build a concise text summary of fingerprints for the prompt."""
        if not fingerprints:
            return "无指纹数据"

        lines = [f"共扫描 {len(fingerprints)} 个服务端点:\n"]

        # Tech stack distribution
        tech_counts: Dict[str, int] = {}
        status_counts: Dict[int, int] = {}
        for fp in fingerprints:
            tech = fp.get("tech_stack")
            if tech:
                try:
                    techs = json.loads(tech) if isinstance(tech, str) else tech
                    for t in techs:
                        tech_counts[t] = tech_counts.get(t, 0) + 1
                except (json.JSONDecodeError, TypeError):
                    tech_counts[str(tech)] = tech_counts.get(str(tech), 0) + 1

            sc = fp.get("status_code")
            if sc:
                status_counts[sc] = status_counts.get(sc, 0) + 1

        lines.append("技术栈分布:")
        for tech, count in sorted(tech_counts.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"  - {tech}: {count} 次")

        lines.append("\n状态码分布:")
        for sc, count in sorted(status_counts.items()):
            lines.append(f"  - HTTP {sc}: {count} 次")

        # Sample entries (limit to avoid token overflow)
        lines.append("\n部分端点示例 (最多 20 条):")
        for fp in fingerprints[:20]:
            url = fp.get("url", "unknown")
            title = fp.get("title", "")
            tech = fp.get("tech_stack", "")
            lines.append(f"  - {url} | title={title} | tech={tech}")

        return "\n".join(lines)

    @staticmethod
    def _build_vulnerability_summary(vulnerabilities: List[Dict[str, Any]]) -> str:
        """Build a concise text summary of vulnerabilities for the prompt."""
        if not vulnerabilities:
            return "未发现中危及以上漏洞"

        # Group by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        by_severity: Dict[str, List[Dict]] = {}
        for v in vulnerabilities:
            sev = v.get("severity", "info").lower()
            by_severity.setdefault(sev, []).append(v)

        lines = [f"共发现 {len(vulnerabilities)} 个漏洞:\n"]

        for sev in severity_order:
            vulns = by_severity.get(sev, [])
            if not vulns:
                continue
            lines.append(f"### {sev.upper()} ({len(vulns)} 个)")
            for v in vulns[:15]:  # Limit per severity to control tokens
                template = v.get("template", "unknown")
                url = v.get("url", "unknown")
                desc = (v.get("description") or "无描述")[:150]
                cvss = v.get("cvss_score", "N/A")
                lines.append(f"  - [{template}] {url} (CVSS: {cvss})")
                lines.append(f"    描述: {desc}")

        return "\n".join(lines)

    # ── Token usage summary ───────────────────────────────────────

    def get_usage_summary(self) -> Dict[str, Any]:
        """Return cumulative token usage and cost for this session."""
        return {
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "provider": self.provider,
            "model": self.model,
        }
