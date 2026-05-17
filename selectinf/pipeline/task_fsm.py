"""Task finite state machine for pipeline status tracking."""

from enum import Enum
from selectinf import get_logger
from selectinf.output.sqlite_manager import get_db

logger = get_logger("pipeline.task_fsm")


class TaskState(Enum):
    """Task state constants."""
    CREATED = "created"
    COLLECTING = "collecting"
    COLLECTING_DONE = "collecting_done"
    FINGERPRINTING = "fingerprinting"
    FINGERPRINTING_DONE = "fingerprinting_done"
    VULNSCANNING = "vulnscanning"
    VULNSCANNING_DONE = "vulnscanning_done"
    AI_ANALYZING = "ai_analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskFSM:
    """Finite state machine for tracking task status transitions."""

    def __init__(self, task_id: int):
        """Initialize the TaskFSM for a given task.

        Args:
            task_id: The ID of the task to track.
        """
        self.task_id = task_id
        self._status = TaskState.CREATED.value
        logger.debug("TaskFSM initialized for task_id=%d", task_id)

    def transition(self, new_status: str) -> None:
        """Transition the task to a new status.

        Args:
            new_status: The new status to transition to.
        """
        logger.info("Task %d transitioning: %s -> %s", self.task_id, self._status, new_status)
        self._status = new_status

    def get_status(self) -> str:
        """Get the current status of the task.

        Returns:
            str: The current task status.
        """
        return self._status


def update_task_status(task_id: int, status: str) -> None:
    """Update the status of a task in the database.

    Args:
        task_id: The ID of the task to update.
        status: The new status for the task.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE task SET status = ? WHERE id = ?", (status, task_id))
    conn.commit()
    conn.close()
    logger.debug("Task %d status updated to: %s", task_id, status)