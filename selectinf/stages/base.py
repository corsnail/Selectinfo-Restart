"""Base classes for pipeline stages."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List


@dataclass
class StageResult:
    """Result of a pipeline stage execution."""

    status: str  # "success" | "partial" | "failed"
    items_processed: int
    items_output: int
    errors: List[str]
    output_path: str


class PipelineStage(ABC):
    """Abstract base class for all pipeline stages."""

    @abstractmethod
    def execute(self, task_id: int, input_path: str) -> StageResult:
        """Execute the pipeline stage.

        Args:
            task_id: The ID of the task being processed.
            input_path: Path to the input data for this stage.

        Returns:
            StageResult containing the execution results.
        """
        pass