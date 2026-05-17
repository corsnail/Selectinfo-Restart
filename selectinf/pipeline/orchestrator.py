"""Pipeline orchestrator for coordinating multi-stage asset scanning."""

import os
import shutil

from selectinf import get_logger
from selectinf.core.config import load_config
from selectinf.output.sqlite_manager import create_task, finish_task, get_task_summary
from selectinf.pipeline.task_fsm import TaskFSM, TaskState, update_task_status
from selectinf.stages.ai_analysis import AIAnalysisStage
from selectinf.stages.base import StageResult
from selectinf.stages.collect import CollectStage
from selectinf.stages.fingerprint import FingerprintStage
from selectinf.stages.vulnscan import VulnScanStage

logger = get_logger("pipeline.orchestrator")


class PipelineOrchestrator:
    """Orchestrates the execution of pipeline stages for asset scanning."""

    def __init__(self, config_path: str = "pipeline_config.yaml"):
        """Initialize the orchestrator with configuration.

        Args:
            config_path: Path to the pipeline configuration file.
        """
        self.config = load_config(config_path)
        self.stages = [
            ("collect", CollectStage(self.config)),
            ("fingerprint", FingerprintStage(self.config)),
            ("vulnscan", VulnScanStage(self.config)),
            ("ai_analysis", AIAnalysisStage(self.config)),
        ]
        logger.debug("PipelineOrchestrator initialized with config: %s", config_path)

    def run(self, target: str) -> dict:
        """Run the full pipeline for a given target.

        Args:
            target: The target domain to scan (e.g. "example.com").

        Returns:
            dict: Pipeline summary with task_id, stages results, and totals.
        """
        logger.info("=" * 50)
        logger.info("Pipeline 启动: target=%s", target)
        logger.info("=" * 50)

        # 1. Create task record
        task_id = create_task(target)
        fsm = TaskFSM(task_id)
        fsm.transition(TaskState.COLLECTING.value)
        update_task_status(task_id, fsm.get_status())

        results = {}
        last_output_path = target
        overall_status = "success"

        # 2. Execute stages sequentially
        for stage_name, stage in self.stages:
            logger.info("进入阶段: %s", stage_name)

            # Map stage name → FSM state
            state_map = {
                "collect": TaskState.COLLECTING,
                "fingerprint": TaskState.FINGERPRINTING,
                "vulnscan": TaskState.VULNSCANNING,
                "ai_analysis": TaskState.AI_ANALYZING,
            }
            done_state_map = {
                "collect": TaskState.COLLECTING_DONE,
                "fingerprint": TaskState.FINGERPRINTING_DONE,
                "vulnscan": TaskState.VULNSCANNING_DONE,
                "ai_analysis": TaskState.COMPLETED,
            }

            fsm.transition(state_map[stage_name].value)
            update_task_status(task_id, fsm.get_status())

            try:
                result: StageResult = stage.execute(task_id, last_output_path)
            except Exception as e:
                logger.error("阶段 %s 执行失败: %s", stage_name, e, exc_info=True)
                result = StageResult(
                    status="failed",
                    items_processed=0,
                    items_output=0,
                    errors=[str(e)],
                    output_path=last_output_path,
                )

            # Transition to done state
            fsm.transition(done_state_map[stage_name].value)
            update_task_status(task_id, fsm.get_status())

            results[stage_name] = {
                "status": result.status,
                "items_processed": result.items_processed,
                "items_output": result.items_output,
                "errors": result.errors,
                "output_path": result.output_path,
            }

            if result.status in ("failed",):
                overall_status = "failed"
            elif result.status in ("partial",) and overall_status == "success":
                overall_status = "partial"

            # Chain output to next stage
            last_output_path = result.output_path

        # 3. Finalise task
        summary = get_task_summary(task_id)
        finish_task(
            task_id,
            total_subdomains=summary.get("total_unique_domains", 0),
            note=f"Pipeline finished with status={overall_status}"
        )

        # 4. Clean up work_dir (intermediate files)
        work_path = os.path.join(self.config.work_dir, str(task_id))
        if os.path.exists(work_path):
            try:
                shutil.rmtree(work_path)
                logger.info("已清理工作目录: %s", work_path)
            except Exception as e:
                logger.warning("清理工作目录失败: %s", e)

        logger.info("Pipeline 完成: task_id=%d, status=%s", task_id, overall_status)

        return {
            "task_id": task_id,
            "target": target,
            "status": overall_status,
            "results": results,
            "summary": summary,
        }
