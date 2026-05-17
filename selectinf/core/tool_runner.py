"""Unified tool execution abstraction with logging, timing, and retries."""

import logging
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Optional

from selectinf import get_logger


@dataclass
class ToolResult:
    """Result of a tool execution.

    Attributes:
        success: Whether the tool exited with code 0.
        stdout: Standard output from the tool.
        stderr: Standard error from the tool.
        exit_code: The exit code returned by the tool.
        elapsed: Time in seconds the tool took to execute.
    """

    success: bool
    stdout: str
    stderr: str
    exit_code: int
    elapsed: float


def run_tool(
    cmd: List[str],
    description: str,
    timeout: int = 300,
    cwd: str = None,
    env: dict = None,
    retries: int = 1,
) -> Optional[ToolResult]:
    """Execute a command-line tool with logging, timing, and retries.

    Args:
        cmd: The command and arguments to execute as a list.
        description: Human-readable description of the tool for logging.
        timeout: Maximum time in seconds to wait for the tool (default 300).
        cwd: Working directory to execute the command in (default: current directory).
        env: Environment variables to pass to the subprocess (default: inherit current env).
        retries: Number of times to retry on failure (default 1, meaning 1 attempt).

    Returns:
        ToolResult object if the tool executes (even on failure after retries),
        or None if the tool could not be run at all (e.g., binary not found).
    """
    logger = get_logger("core.tool_runner")

    # Determine if running on Windows for CREATE_NO_WINDOW flag
    is_windows = sys.platform == "win32" or sys.platform.startswith("win")

    # Build subprocess creation flags
    creation_flags = 0
    if is_windows:
        creation_flags |= subprocess.CREATE_NO_WINDOW

    last_result = None
    total_attempts = retries + 1

    for attempt in range(1, total_attempts + 1):
        attempt_label = f"{description} (attempt {attempt}/{total_attempts})"
        logger.info(f"Executing: {' '.join(cmd)}")
        logger.debug(f"  Working directory: {cwd or 'current'}")
        logger.debug(f"  Timeout: {timeout}s")

        start_time = time.time()

        try:
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                cwd=cwd,
                env=env,
                creationflags=creation_flags,
            )
            elapsed = time.time() - start_time

            stdout = result.stdout or ""
            stderr = result.stderr or ""
            exit_code = result.returncode

            logger.info(f"Completed: {attempt_label} (exit={exit_code}, elapsed={elapsed:.2f}s)")

            if stdout:
                logger.debug(f"  stdout: {stdout[:500]}{'...' if len(stdout) > 500 else ''}")
            if stderr:
                logger.debug(f"  stderr: {stderr[:500]}{'...' if len(stderr) > 500 else ''}")

            last_result = ToolResult(
                success=(exit_code == 0),
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                elapsed=elapsed,
            )

            if exit_code == 0:
                return last_result

            # Non-zero exit code - check for specific error patterns before retrying
            if attempt < total_attempts:
                if _check_error_patterns(stderr, logger):
                    logger.warning(f"Retrying: {description} after non-zero exit ({exit_code})")
                else:
                    # Unknown error pattern - still retry but log it
                    logger.warning(f"Retrying: {description} (exit={exit_code})")
            else:
                logger.error(f"Failed after {total_attempts} attempts: {description} (exit={exit_code})")

        except FileNotFoundError as e:
            elapsed = time.time() - start_time
            error_msg = (
                f"Binary not found for {description}. "
                f"Please ensure the executable exists and is in your PATH. "
                f"Error: {e}"
            )
            logger.error(error_msg)
            return None

        except subprocess.TimeoutExpired as e:
            elapsed = time.time() - start_time
            # Construct a ToolResult for timeout since we don't have stdout/stderr
            timeout_result = ToolResult(
                success=False,
                stdout=getattr(e, "stdout", "") or "",
                stderr=getattr(e, "stderr", "") or "",
                exit_code=-1,
                elapsed=elapsed,
            )
            logger.error(
                f"Timeout expired for {description} after {timeout}s. "
                f"Consider increasing the timeout or checking if the tool is hanging."
            )
            return timeout_result

        except OSError as e:
            elapsed = time.time() - start_time
            error_msg = (
                f"OS error while executing {description}: {e}. "
                f"This may indicate a missing dependency or system resource issue."
            )
            logger.error(error_msg)
            last_result = ToolResult(
                success=False,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                elapsed=elapsed,
            )

    return last_result


def run_pipe_tool(
    cmd1: List[str],
    cmd2: List[str],
    description: str,
    timeout: int = 300,
    cwd: str = None,
    env: dict = None,
) -> Optional[ToolResult]:
    """Run two subprocess commands in a pipe (cmd1 | cmd2) with logging and error handling.

    This is used for tools that require chained subprocess execution, such as
    massdns (subbrute.py | massdns.exe).

    Args:
        cmd1: The first command in the pipe (producer).
        cmd2: The second command in the pipe (consumer).
        description: Human-readable description for logging.
        timeout: Maximum time in seconds to wait for completion.
        cwd: Working directory for both commands.
        env: Environment variables to pass to both subprocesses.

    Returns:
        ToolResult for the second command (cmd2), or None on total failure.
    """
    logger = get_logger("core.tool_runner")

    is_windows = sys.platform == "win32" or sys.platform.startswith("win")
    creation_flags = 0
    if is_windows:
        creation_flags |= subprocess.CREATE_NO_WINDOW

    logger.info(f"Executing pipe: {' '.join(cmd1)} | {' '.join(cmd2)}")
    start_time = time.time()

    proc1 = None
    proc2 = None

    try:
        proc1 = subprocess.Popen(
            cmd1,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            env=env,
            creationflags=creation_flags,
        )
        proc2 = subprocess.Popen(
            cmd2,
            stdin=proc1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            env=env,
            creationflags=creation_flags,
        )
        proc1.stdout.close()  # Allow proc1 to receive a SIGPIPE if proc2 exits

        stdout, stderr = proc2.communicate(timeout=timeout)
        elapsed = time.time() - start_time
        exit_code = proc2.returncode

        logger.info(f"Completed: {description} (exit={exit_code}, elapsed={elapsed:.2f}s)")

        return ToolResult(
            success=(exit_code == 0),
            stdout=stdout or "",
            stderr=stderr or "",
            exit_code=exit_code,
            elapsed=elapsed,
        )

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        if proc1:
            proc1.kill()
        if proc2:
            proc2.kill()
        logger.error(f"Timeout expired for {description} after {timeout}s.")
        return ToolResult(
            success=False,
            stdout="",
            stderr="TimeoutExpired",
            exit_code=-1,
            elapsed=elapsed,
        )

    except FileNotFoundError as e:
        elapsed = time.time() - start_time
        logger.error(f"Binary not found for {description}: {e}")
        return None

    except OSError as e:
        elapsed = time.time() - start_time
        logger.error(f"OS error while executing {description}: {e}")
        return ToolResult(
            success=False,
            stdout="",
            stderr=str(e),
            exit_code=-1,
            elapsed=elapsed,
        )


def _check_error_patterns(stderr: str, logger: logging.Logger) -> bool:
    """Check stderr for known error patterns and log specific guidance.

    Args:
        stderr: The standard error output to check.
        logger: Logger instance for outputting specific guidance.

    Returns:
        True if a known pattern was found, False otherwise.
    """
    stderr_lower = stderr.lower()

    # Check for wpcap.dll / Npcap related errors
    if "wpcap.dll" in stderr or "couldn't load wpcap" in stderr_lower:
        logger.error(
            "Npcap/WinPcap error detected. "
            "This tool requires Npcap to be installed. "
            "Download from: https://npcap.com/#download"
        )
        return True

    # Add more specific error pattern handling here as needed
    # Example patterns could include:
    # - Missing Visual C++ runtime
    # - Permission denied errors
    # - Network-related errors

    return False
