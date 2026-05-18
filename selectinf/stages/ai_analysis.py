"""AI-powered analysis stage (Phase 5)."""

import json
import os
from typing import Any, Dict, List, Optional

from selectinf import get_logger
from selectinf.ai.client import AIClient
from selectinf.output.sqlite_manager import (
    get_fingerprints,
    get_vulnerabilities,
    save_ai_analysis,
)
from selectinf.stages.base import PipelineStage, StageResult

logger = get_logger("stages.ai_analysis")

# Severity threshold: only include these in report to control token usage
_REPORT_SEVERITIES = {"critical", "high", "medium"}


class AIAnalysisStage(PipelineStage):
    """Stage for AI-based analysis of vulnerabilities and fingerprints.

    Workflow:
    1. Read vulnerabilities + fingerprints from SQLite
    2. If fp_validation.enabled, validate each vulnerability via LLM
    3. Generate Markdown report via LLM
    4. Write results to ai_analysis table + report.md file
    """

    def __init__(self, config):
        self.config = config

    def execute(self, task_id: int, input_path: str) -> StageResult:
        """Execute the AI analysis stage.

        Note: This stage reads data directly from SQLite (get_vulnerabilities,
        get_fingerprints) rather than from the input_path file. The input_path
        parameter is kept for PipelineStage interface compatibility but is not used.

        Args:
            task_id: The ID of the task being processed.
            input_path: Path to the input data (fingerprints.json from previous stage).
                        Not used; data is read from SQLite directly.

        Returns:
            StageResult containing the execution results.
        """
        work_path = os.path.join(self.config.work_dir, str(task_id))
        os.makedirs(work_path, exist_ok=True)

        errors: List[str] = []
        items_processed = 0
        items_output = 0

        # 1. Load AI configuration
        ai_config = self.config.ai
        if not ai_config:
            logger.warning("AI 配置为空，跳过分析")
            return StageResult(
                status="skipped",
                items_processed=0,
                items_output=0,
                errors=["AI 配置为空"],
                output_path=input_path,
            )

        # 2. Check if stage is enabled
        stages = self.config.stages
        if not stages.get("ai_analysis", True):
            logger.info("ai_analysis 阶段已禁用，跳过")
            return StageResult(
                status="skipped",
                items_processed=0,
                items_output=0,
                errors=[],
                output_path=input_path,
            )

        # 3. Initialize LLM client
        try:
            client = AIClient(ai_config)
        except Exception as e:
            error_msg = f"AIClient 初始化失败: {e}"
            logger.error(error_msg)
            return StageResult(
                status="failed",
                items_processed=0,
                items_output=0,
                errors=[error_msg],
                output_path=input_path,
            )

        # 4. Read data from SQLite
        vulnerabilities = get_vulnerabilities(task_id)
        fingerprints = get_fingerprints(task_id)

        # Build fingerprint lookup by URL for FP validation context
        fp_by_url: Dict[str, Dict] = {}
        for fp in fingerprints:
            url = fp.get("url", "")
            if url:
                fp_by_url[url] = fp

        logger.info(
            "读取数据: vulnerabilities=%d, fingerprints=%d",
            len(vulnerabilities), len(fingerprints)
        )

        # 5. Handle empty data
        if not vulnerabilities and not fingerprints:
            logger.info("无漏洞和指纹数据，生成空报告")
            report_result = {
                "report": "# 安全评估报告\n\n本次扫描未发现任何资产或漏洞。",
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "cost_usd": 0.0,
            }
        else:
            # 5a. False-positive validation (if enabled)
            fp_config = ai_config.get("fp_validation", {})
            fp_enabled = fp_config.get("enabled", True)
            fp_threshold = fp_config.get("threshold", 0.7)

            if fp_enabled and vulnerabilities:
                logger.info("开始误报验证 (%d 个漏洞)...", len(vulnerabilities))
                vuln_results = self._validate_vulnerabilities(
                    client, vulnerabilities, fp_by_url, ai_config
                )
                items_processed += len(vuln_results)

        # Update SQLite with AI validation results
                for vr in vuln_results:
                    try:
                        self._update_vuln_ai_result(task_id, vr, fp_threshold)
                        items_output += 1
                    except Exception as e:
                        logger.warning("更新漏洞 AI 结果失败: %s", e)
                        errors.append(f"更新漏洞 AI 结果失败: {e}")

                # Save FP validation records to ai_analysis table
                for vr in vuln_results:
                    try:
                        save_ai_analysis(
                            task_id=task_id,
                            analysis_type="fp_validation",
                            input_data=json.dumps({
                                "vuln_id": vr["vuln_id"],
                                "template": vr["template"],
                            }, ensure_ascii=False),
                            model_used=client.model,
                            prompt_tokens=vr.get("prompt_tokens", 0),
                            completion_tokens=vr.get("completion_tokens", 0),
                            result_text=json.dumps({
                                "is_vuln": vr["is_vuln"],
                                "confidence": vr["confidence"],
                                "reason": vr["reason"],
                            }, ensure_ascii=False),
                            cost_usd=vr.get("cost_usd", 0.0),
                        )
                    except Exception as e:
                        logger.warning("保存 FP 验证记录失败: %s", e)
                        errors.append(f"保存 FP 验证记录失败: {e}")

            # 5b. Generate report
            report_config = ai_config.get("report", {})
            language = report_config.get("language", "zh-CN")
            include_remediation = report_config.get("include_remediation", True)

            # Filter vulnerabilities for report (severity >= medium)
            report_vulns = [
                v for v in vulnerabilities
                if v.get("severity", "").lower() in _REPORT_SEVERITIES
            ]

            logger.info("生成报告 (漏洞数=%d, 指纹数=%d)...", len(report_vulns), len(fingerprints))

            try:
                report_result = client.generate_report(
                    vulnerabilities=report_vulns,
                    fingerprints=fingerprints,
                    language=language,
                    include_remediation=include_remediation,
                )
            except (TimeoutError, ConnectionError) as e:
                error_msg = f"报告生成失败: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
                report_result = {
                    "report": f"# 安全评估报告\n\n**生成失败**: {e}\n\n请检查 LLM 服务连接。",
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "cost_usd": 0.0,
                }
            except Exception as e:
                error_msg = f"报告生成异常: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
                report_result = {
                    "report": f"# 安全评估报告\n\n**生成异常**: {e}",
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "cost_usd": 0.0,
                }

        # 6. Write report to file
        report_path = os.path.join(work_path, "report.md")
        report_text = report_result.get("report", "")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report_text)
            logger.info("报告已写入 %s", report_path)
            items_output += 1
        except Exception as e:
            logger.error("写入报告文件失败: %s", e)
            errors.append(f"写入报告文件失败: {e}")

        # 7. Save report record to ai_analysis table
        try:
            save_ai_analysis(
                task_id=task_id,
                analysis_type="report",
                input_data=json.dumps({
                    "vulnerability_count": len(vulnerabilities),
                    "fingerprint_count": len(fingerprints),
                }, ensure_ascii=False),
                model_used=client.model,
                prompt_tokens=report_result.get("prompt_tokens", 0),
                completion_tokens=report_result.get("completion_tokens", 0),
                result_text=report_text[:16384] if report_text else "",  # Truncate for DB (spec: ≤16KB)
                cost_usd=report_result.get("cost_usd", 0.0),
            )
        except Exception as e:
            logger.warning("保存报告记录到数据库失败: %s", e)
            errors.append(f"保存报告记录失败: {e}")

        # 8. Save total usage summary
        usage = client.get_usage_summary()
        try:
            save_ai_analysis(
                task_id=task_id,
                analysis_type="usage_summary",
                input_data=None,
                model_used=usage["model"],
                prompt_tokens=usage["total_prompt_tokens"],
                completion_tokens=usage["total_completion_tokens"],
                result_text=json.dumps(usage, ensure_ascii=False),
                cost_usd=usage["total_cost_usd"],
            )
        except Exception as e:
            logger.warning("保存用量摘要失败: %s", e)

        # 9. Build result
        status = "success" if not errors else "partial"
        return StageResult(
            status=status,
            items_processed=items_processed or len(vulnerabilities) + len(fingerprints),
            items_output=items_output,
            errors=errors,
            output_path=report_path,
        )

    # ── Helper methods ────────────────────────────────────────────

    def _validate_vulnerabilities(
        self,
        client: AIClient,
        vulnerabilities: List[Dict[str, Any]],
        fp_by_url: Dict[str, Dict],
        ai_config: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Validate each vulnerability for false positives.

        Args:
            client: Initialized AIClient
            vulnerabilities: List of vulnerability dicts
            fp_by_url: Fingerprint lookup by URL
            ai_config: AI configuration dict

        Returns:
            List of validation result dicts
        """
        results = []
        report_config = ai_config.get("report", {})
        language = report_config.get("language", "zh-CN")

        for vuln in vulnerabilities:
            vuln_id = vuln.get("vuln_id", "unknown")
            url = vuln.get("url", "")
            fp_context = fp_by_url.get(url)

            try:
                result = client.validate_fp(vuln, fp_context, language)
                result["vuln_id"] = vuln_id
                result["template"] = vuln.get("template", "")
                result["url"] = url
                results.append(result)

                verdict = "真实漏洞" if result["is_vuln"] else "疑似误报"
                logger.info(
                    "FP 验证 [%s]: %s (置信度=%.2f, 理由=%s)",
                    vuln_id, verdict, result["confidence"], result["reason"][:50]
                )

            except (TimeoutError, ConnectionError) as e:
                logger.warning("FP 验证超时/连接失败 [%s]: %s", vuln_id, e)
                results.append({
                    "vuln_id": vuln_id,
                    "template": vuln.get("template", ""),
                    "url": url,
                    "is_vuln": True,  # Conservative: assume real on failure
                    "confidence": 0.5,
                    "reason": f"验证失败: {e}",
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "cost_usd": 0.0,
                })
            except Exception as e:
                logger.warning("FP 验证异常 [%s]: %s", vuln_id, e)
                results.append({
                    "vuln_id": vuln_id,
                    "template": vuln.get("template", ""),
                    "url": url,
                    "is_vuln": True,
                    "confidence": 0.5,
                    "reason": f"验证异常: {e}",
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "cost_usd": 0.0,
                })

        return results

    @staticmethod
    def _update_vuln_ai_result(
        task_id: int,
        vr: Dict[str, Any],
        threshold: float,
    ) -> None:
        """Update vulnerability record with AI validation result in SQLite.

        Sets ai_validated and ai_confidence fields.
        """
        from selectinf.output.sqlite_manager import get_db

        is_vuln = vr.get("is_vuln", True)
        confidence = vr.get("confidence", 0.5)

        # If confidence below threshold, mark as suspected false positive
        ai_validated = 1 if (is_vuln and confidence >= threshold) else 0

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE vulnerabilities
               SET ai_validated = ?, ai_confidence = ?
               WHERE task_id = ? AND vuln_id = ? AND url = ?""",
            (ai_validated, confidence, task_id, vr["vuln_id"], vr.get("url", ""))
        )
        conn.commit()
        conn.close()
