"""Vulnerability scanning stage."""

from selectinf.stages.base import PipelineStage, StageResult


class VulnScanStage(PipelineStage):
    """Stage for vulnerability scanning."""

    def __init__(self, config):
        self.config = config

    def execute(self, task_id: int, input_path: str) -> StageResult:
        """Execute the vulnerability scanning stage.

        Args:
            task_id: The ID of the task being processed.
            input_path: Path to the input data for this stage.

        Returns:
            StageResult containing the execution results.
        """
        return StageResult(
            status="skipped",
            items_processed=0,
            items_output=0,
            errors=[],
            output_path=input_path
        )