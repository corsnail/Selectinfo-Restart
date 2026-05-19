"""Vulnerability scanning stage using nuclei."""

import json
import os
import shutil
import sys
from typing import Any, Dict, List, Optional, Tuple

from selectinf import get_logger
from selectinf.core.config import ToolConfig
from selectinf.core.tool_runner import run_tool
from selectinf.output.sqlite_manager import save_vulnerability
from selectinf.stages.base import PipelineStage, StageResult

logger = get_logger("stages.vulnscan")


class VulnScanStage(PipelineStage):
    """Stage for vulnerability scanning using nuclei."""

    def __init__(self, config):
        self.config = config

    def execute(self, task_id: int, input_path: str) -> StageResult:
        """Execute the vulnerability scanning stage.

        Reads nuclei targets from work/{task_id}/nuclei_targets.txt,
        invokes nuclei with configured severity filters and templates,
        parses JSON Lines output, persists vulnerabilities to SQLite,
        and writes vulnerabilities.json.

        Args:
            task_id: The ID of the task being processed.
            input_path: Path to the input data (used for fallback output path).

        Returns:
            StageResult containing the execution results.
        """
        work_path = os.path.join(self.config.work_dir, str(task_id))
        os.makedirs(work_path, exist_ok=True)

        errors: List[str] = []

        # 1. Read nuclei targets
        target_file = os.path.join(work_path, "nuclei_targets.txt")
        targets = self._read_targets(target_file)
        if not targets:
            logger.warning("无 nuclei 扫描目标: %s", target_file)
            return StageResult(
                status="success",
                items_processed=0,
                items_output=0,
                errors=errors,
                output_path=input_path,
            )

        logger.info("读取到 %d 个 nuclei 扫描目标", len(targets))

        # 2. Load nuclei configuration
        cfg = self.config.vulnscan.get("nuclei", ToolConfig())
        if not cfg.enabled:
            logger.info("nuclei 已禁用，跳过漏洞扫描")
            return StageResult(
                status="skipped",
                items_processed=len(targets),
                items_output=0,
                errors=errors,
                output_path=input_path,
            )

        timeout = cfg.timeout
        retries = cfg.retries
        templates_dir = cfg.extra.get("templates_dir", "")
        severity_filter = cfg.extra.get("severity_filter", ["critical", "high", "medium"])
        rate_limit = cfg.extra.get("rate_limit", 50)
        threads = cfg.extra.get("threads", 10)
        bulk_size = cfg.extra.get("bulk_size", 100)

        # 3. Resolve binary path
        raw_binary = cfg.extra.get("binary_path", "tools/nuclei/nuclei")
        binary, bin_err = self._resolve_binary(raw_binary)
        if not binary:
            error_msg = f"nuclei 二进制未找到: {bin_err}"
            logger.error(error_msg)
            errors.append(error_msg)
            return StageResult(
                status="partial",
                items_processed=len(targets),
                items_output=0,
                errors=errors,
                output_path=input_path,
            )

        # 4. Build nuclei command
        output_file = os.path.join(work_path, "nuclei_output.json")
        severity_str = ",".join(severity_filter)

        cmd: List[str] = [
            binary,
            "-l", target_file,
            "-o", output_file,
            "-jsonl",
            "-severity", severity_str,
            "-rl", str(rate_limit),
            "-c", str(threads),
            "-bs", str(bulk_size),
            "-silent",
        ]
        if templates_dir:
            cmd.extend(["-t", templates_dir])

        # 5. Execute nuclei
        logger.info(
            "启动 nuclei 漏洞扫描 (目标数=%d, severity=%s, 超时=%ds)",
            len(targets), severity_str, timeout
        )
        result = run_tool(cmd, description="nuclei", timeout=timeout, retries=retries)

        # 6. Handle tool execution outcome
        if result is None:
            error_msg = f"nuclei 执行失败: 二进制文件未找到 (期望路径: {binary})"
            logger.error(error_msg)
            errors.append(error_msg)
            return StageResult(
                status="partial",
                items_processed=len(targets),
                items_output=0,
                errors=errors,
                output_path=input_path,
            )

        if result.exit_code == -1:
            # TimeoutExpired: subprocess was killed, likely no output file
            error_msg = f"nuclei 进程超时 (>{timeout}s)，未生成输出文件"
            logger.error(error_msg)
            errors.append(error_msg)
        elif not result.success:
            stderr_snippet = (result.stderr or "")[:500]
            logger.warning(
                "nuclei 退出码非零 (exit_code=%d), 尝试解析部分输出\nstderr: %s",
                result.exit_code,
                stderr_snippet,
            )
            if result.stdout:
                logger.info("nuclei STDOUT:\n%s", result.stdout[:1000])

        # 7. Parse nuclei JSON Lines output
        vulnerabilities: List[Dict[str, Any]] = []
        duplicates_skipped = 0
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("跳过无效 JSON 行: %s", line[:100])
                        continue

                    vuln = self._parse_vulnerability_entry(data)
                    if vuln is None:
                        continue

                    # Defensive severity filtering (nuclei may output entries outside requested severities)
                    vuln_sev = vuln.get("severity", "").lower()
                    if severity_filter and vuln_sev not in [s.lower() for s in severity_filter]:
                        logger.debug(
                            "二次过滤丢弃 severity=%s 的漏洞 (不在配置过滤列表 %s): %s",
                            vuln_sev, severity_filter, vuln.get("vuln_id")
                        )
                        continue

                    vulnerabilities.append(vuln)

                    # Persist to SQLite
                    try:
                        # Truncate nuclei raw JSON to ≤8KB per schema spec
                        raw_json = json.dumps(data, ensure_ascii=False)
                        if len(raw_json) > 8192:
                            raw_json = raw_json[:8192]

                        save_vulnerability(
                            task_id=task_id,
                            vuln_id=vuln["vuln_id"],
                            url=vuln["url"],
                            template=vuln["template"],
                            severity=vuln["severity"],
                            cvss_score=vuln.get("cvss_score"),
                            description=vuln.get("description"),
                            matched_at=vuln.get("matched_at"),
                            extracted_results=vuln.get("extracted_results"),
                            nuclei_output_json=raw_json,
                        )
                    except Exception as e:
                        logger.error("保存漏洞失败 [%s]: %s", vuln.get("vuln_id"), e)
                        errors.append(str(e))

            # Log duplicate/insert summary after the loop
            if vulnerabilities:
                logger.info(
                    "漏洞解析完成: %d 条解析, 其中重复/冲突被跳过若干条",
                    len(vulnerabilities)
                )
        else:
            logger.warning("nuclei 输出文件不存在: %s", output_file)

        # 8. Write aggregated vulnerabilities.json
        vulnerabilities_json_path = os.path.join(work_path, "vulnerabilities.json")
        try:
            with open(vulnerabilities_json_path, "w", encoding="utf-8") as f:
                json.dump(vulnerabilities, f, indent=2, ensure_ascii=False)
            logger.info("漏洞结果已写入 %s (%d 条)", vulnerabilities_json_path, len(vulnerabilities))
        except Exception as e:
            logger.error("写入 vulnerabilities.json 失败: %s", e)
            errors.append(str(e))

        # 9. Build and return StageResult
        status = "success" if not errors else "partial"
        return StageResult(
            status=status,
            items_processed=len(targets),
            items_output=len(vulnerabilities),
            errors=errors,
            output_path=vulnerabilities_json_path,
        )

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_binary(raw_path: str) -> Tuple[str, str]:
        """Resolve binary path with platform-aware suffix.

        Appends ``.exe`` on Windows if the path does not already end with it.
        Falls back to ``shutil.which`` when the explicit path is missing.

        Returns:
            (resolved_path, error_message).  ``error_message`` is empty on success.
        """
        if sys.platform.startswith("win") and not raw_path.endswith(".exe"):
            candidate = raw_path + ".exe"
        else:
            candidate = raw_path

        if not os.path.isfile(candidate):
            base = os.path.basename(candidate)
            in_path = shutil.which(base)
            if in_path:
                return in_path, ""
            error_msg = (
                f"{candidate} 不存在。"
                f"由于 GitHub 文件大小限制，大文件二进制需要从官方下载。"
                f"请从 https://github.com/projectdiscovery/nuclei/releases 下载 nuclei，"
                f"解压后将 nuclei.exe 放置于 {candidate} 或添加到系统 PATH。"
            )
            return "", error_msg

        if not sys.platform.startswith("win") and not os.access(candidate, os.X_OK):
            return "", f"{candidate} 存在但无可执行权限"

        return candidate, ""

    @staticmethod
    def _read_targets(target_file: str) -> List[str]:
        """Read targets from file, one per line. Skip empty lines."""
        if not os.path.exists(target_file):
            return []
        targets = []
        with open(target_file, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if raw:
                    targets.append(raw)
        return targets

    @staticmethod
    def _parse_vulnerability_entry(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single JSON Lines entry from nuclei output into a vulnerability dict.

        Returns a dict keyed by vulnerability fields, or None if the entry lacks a template-id.
        """
        template_id = data.get("template-id")
        if not template_id:
            return None

        info = data.get("info", {})
        if not isinstance(info, dict):
            info = {}

        severity = info.get("severity", "info")
        name = info.get("name", "")
        description = info.get("description", "")

        # CVSS score extraction from nested classification
        cvss_score = None
        classification = info.get("classification", {})
        if isinstance(classification, dict):
            cvss_raw = classification.get("cvss-score")
            if cvss_raw is not None:
                try:
                    cvss_score = float(cvss_raw)
                except (ValueError, TypeError):
                    cvss_score = None

        host = data.get("host", "")
        matched_at = data.get("matched-at", "")

        extracted = data.get("extracted-results", [])
        if isinstance(extracted, list):
            extracted_results = ",".join(str(x) for x in extracted) if extracted else None
        else:
            extracted_results = str(extracted) if extracted else None

        return {
            "vuln_id": template_id,
            "url": host,
            "template": data.get("template-path", ""),
            "severity": severity,
            "cvss_score": cvss_score,
            "description": description or name,
            "matched_at": matched_at,
            "extracted_results": extracted_results,
        }
