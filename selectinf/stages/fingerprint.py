"""Fingerprint stage for service and technology detection using httpx."""

import json
import os
from typing import Any, Dict, List, Optional

from selectinf import get_logger
from selectinf.core.config import ToolConfig
from selectinf.core.tool_runner import run_tool

from selectinf.output.sqlite_manager import save_fingerprint
from selectinf.stages.base import PipelineStage, StageResult

logger = get_logger("stages.fingerprint")


class FingerprintStage(PipelineStage):
    """Stage for fingerprinting services and technologies using httpx."""

    def __init__(self, config):
        self.config = config

    def execute(self, task_id: int, input_path: str) -> StageResult:
        """Execute the fingerprinting stage.

        Reads domains from input_path, generates URL targets, invokes httpx,
        parses JSON Lines output, persists fingerprints to SQLite, and writes
        fingerprints.json.

        Args:
            task_id: The ID of the task being processed.
            input_path: Path to the input data (one domain per line).

        Returns:
            StageResult containing the execution results.
        """
        work_path = os.path.join(self.config.work_dir, str(task_id))
        os.makedirs(work_path, exist_ok=True)

        errors: List[str] = []

        # 1. Read domains from input file
        domains = self._read_domains(input_path)
        if not domains:
            logger.warning("输入文件无有效域名: %s", input_path)
            return StageResult(
                status="success",
                items_processed=0,
                items_output=0,
                errors=errors,
                output_path=input_path,
            )

        logger.info("读取到 %d 个域名", len(domains))

        # 2. Load httpx configuration
        cfg = self.config.fingerprint.get("httpx", ToolConfig())

        if not cfg.enabled:
            logger.info("httpx 已禁用，跳过指纹识别")
            return StageResult(
                status="skipped",
                items_processed=len(domains),
                items_output=0,
                errors=errors,
                output_path=input_path,
            )

        timeout = cfg.timeout
        retries = cfg.retries
        ports = list(set(cfg.extra.get("ports", [80, 443])))
        threads = cfg.extra.get("threads", 20)
        tech_detect = cfg.extra.get("tech_detect", True)
        follow_redirects = cfg.extra.get("follow_redirects", True)

        # 3. Write bare domains for httpx (httpx handles ports via -ports flag)
        target_file = os.path.join(work_path, "httpx_input.txt")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("\n".join(domains))
        logger.info("生成 %d 个探测目标 → %s", len(domains), target_file)

        # 4. Build httpx command
        output_file = os.path.join(work_path, "httpx_output.json")
        port_csv = ",".join(str(p) for p in ports)
        binary = os.path.join("tools", "httpx", "httpx.exe")

        cmd: List[str] = [
            binary,
            "-l", target_file,
            "-ports", port_csv,
            "-o", output_file,
            "-json",
            "-threads", str(threads),
        ]

        if tech_detect:
            cmd.append("-tech-detect")
        if follow_redirects:
            cmd.append("-follow-redirects")

        cmd.extend(["-timeout", str(timeout), "-no-color"])

        # 5. Execute httpx
        logger.info("启动 httpx 指纹识别 (目标数=%d, 端口=%s)", len(domains), port_csv)
        result = run_tool(cmd, description="httpx", timeout=timeout, retries=retries)

        # 6. Handle tool execution outcome
        if result is None:
            error_msg = "httpx 执行失败: 二进制文件未找到"
            logger.error(error_msg)
            errors.append(error_msg)
            return StageResult(
                status="partial",
                items_processed=len(domains),
                items_output=0,
                errors=errors,
                output_path=input_path,
            )

        if not result.success:
            stderr_snippet = (result.stderr or "")[:500]
            logger.warning(
                "httpx 退出码非零 (exit_code=%d), 尝试解析部分输出\nstderr: %s",
                result.exit_code,
                stderr_snippet,
            )
            if result.stdout:
                logger.info("httpx STDOUT:\n%s", result.stdout[:1000])

        # 7. Parse httpx JSON Lines output
        fingerprints: List[Dict[str, Any]] = []
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

                    fp = self._parse_fingerprint_entry(data)
                    if fp is None:
                        continue

                    fingerprints.append(fp)

                    # Persist to SQLite
                    try:
                        save_fingerprint(
                            task_id=task_id,
                            url=fp["url"],
                            ip=fp.get("ip"),
                            port=fp.get("port", 443),
                            status_code=fp.get("status_code"),
                            title=fp.get("title"),
                            content_type=fp.get("content_type"),
                            server_header=fp.get("server_header"),
                            tech_stack=fp.get("tech_stack"),
                            waf_detected=fp.get("waf_detected"),
                            response_time_ms=fp.get("response_time_ms"),
                        )
                    except Exception as e:
                        logger.error("保存指纹失败 [%s]: %s", fp.get("url"), e)
                        errors.append(str(e))
        else:
            logger.warning("httpx 输出文件不存在: %s", output_file)

        # 8. Write aggregated fingerprints.json
        fingerprints_json_path = os.path.join(work_path, "fingerprints.json")
        try:
            with open(fingerprints_json_path, "w", encoding="utf-8") as f:
                json.dump(fingerprints, f, indent=2, ensure_ascii=False)
            logger.info("指纹结果已写入 %s (%d 条)", fingerprints_json_path, len(fingerprints))
        except Exception as e:
            logger.error("写入 fingerprints.json 失败: %s", e)
            errors.append(str(e))

        # 9. Write nuclei_targets.txt for downstream VulnScan stage
        nuclei_targets_path = os.path.join(work_path, "nuclei_targets.txt")
        try:
            if fingerprints:
                urls = [fp["url"] for fp in fingerprints if fp.get("url")]
            else:
                # Fallback: probe all domain+port combinations
                urls = self._build_targets(domains, ports)
            with open(nuclei_targets_path, "w", encoding="utf-8") as f:
                f.write("\n".join(urls))
            logger.info("nuclei 目标列表已写入 %s (%d 条)", nuclei_targets_path, len(urls))
        except Exception as e:
            logger.error("写入 nuclei_targets.txt 失败: %s", e)
            errors.append(str(e))

        # 10. Build and return StageResult
        status = "success" if not errors else "partial"
        return StageResult(
            status=status,
            items_processed=len(domains),
            items_output=len(fingerprints),
            errors=errors,
            output_path=fingerprints_json_path,
        )

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    @staticmethod
    def _read_domains(input_path: str) -> List[str]:
        """Read domains from input file, one per line. Skip empty lines."""
        if not os.path.exists(input_path):
            return []
        domains = []
        with open(input_path, "r", encoding="utf-8") as f:
            for line in f:
                domain = line.strip()
                if domain:
                    domains.append(domain)
        return domains

    @staticmethod
    def _build_targets(domains: List[str], ports: List[int]) -> List[str]:
        """Build URL targets by combining domains with ports.

        Rules:
            port 80   → http://domain
            port 443  → https://domain
            port 8080 → http://domain:8080
            port 8443 → https://domain:8443
            other     → http://domain:port
        """
        targets = []
        for domain in domains:
            for port in ports:
                if port == 443:
                    url = f"https://{domain}"
                elif port == 80:
                    url = f"http://{domain}"
                elif port == 8443:
                    url = f"https://{domain}:8443"
                elif port == 8080:
                    url = f"http://{domain}:8080"
                else:
                    url = f"http://{domain}:{port}"
                targets.append(url)
        return targets

    @staticmethod
    def _parse_fingerprint_entry(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single JSON Lines entry from httpx output into a fingerprint dict.

        Returns a dict keyed by fingerprint fields, or None if the entry lacks a URL.
        """
        url = data.get("url")
        if not url:
            return None

        # Tech stack: list → JSON string, string → as-is, missing → None
        tech_raw = data.get("tech")
        if isinstance(tech_raw, list):
            tech_stack = json.dumps(tech_raw)
        elif isinstance(tech_raw, str):
            tech_stack = tech_raw
        else:
            tech_stack = None

        # WAF
        waf_detected = data.get("waf")

        # Response time: "1.234s" → 1234 ms; missing/invalid → None
        response_time_ms = None
        time_raw = data.get("time")
        if time_raw is not None:
            try:
                if isinstance(time_raw, str) and time_raw.endswith("s"):
                    time_raw = time_raw[:-1]
                    response_time_ms = int(float(time_raw) * 1000)
                elif isinstance(time_raw, (int, float)):
                    response_time_ms = int(float(time_raw) * 1000)
            except (ValueError, TypeError):
                pass

        # Port: default to 443 if missing; cast to int for SQLite INTEGER
        port = data.get("port", 443)
        if port is None:
            port = 443
        try:
            port = int(port)
        except (ValueError, TypeError):
            port = 443

        return {
            "url": url,
            "ip": data.get("host"),
            "port": port,
            "status_code": data.get("status_code"),
            "title": data.get("title"),
            "content_type": data.get("content_type"),
            "server_header": data.get("webserver"),
            "tech_stack": tech_stack,
            "waf_detected": waf_detected,
            "response_time_ms": response_time_ms,
        }
