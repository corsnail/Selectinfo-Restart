# selectinf - Automated asset collection and vulnerability scanning framework
#
# Package structure:
#   selectinf.collect  - Data collection layer (extract_domains, dnsgrep)
#   selectinf.process  - Data processing layer (deduplicate, filter, url_converter)
#   selectinf.output   - Data output layer (arl_exporter, mysql_exporter)
#
# Entry points:
#   python run.py          - Main orchestrator
#   python -m selectinf    - Package entry point

import logging
import sys
import os
from datetime import datetime

# ── Logging Configuration ────────────────────────────────────
# Dual output: console (INFO+) + file (DEBUG+, with timestamps)

_LOGGER_INITIALIZED = False
_LOG_FORMAT = "[%(asctime)s] %(levelname)-7s %(name)s | %(message)s"
_LOG_DATE_FORMAT = "%H:%M:%S"

# Console format: colored, no module name
_CONSOLE_FORMATTER = logging.Formatter("[%(levelname)-7s] %(message)s")
_FILE_FORMATTER = logging.Formatter(
    "%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


def _init_logging():
    """Initialize logging once."""
    global _LOGGER_INITIALIZED
    if _LOGGER_INITIALIZED:
        return
    _LOGGER_INITIALIZED = True

    # Ensure output/logs/ directory exists
    _log_dir = os.path.join(os.path.dirname(__file__), "..", "output", "logs")
    os.makedirs(_log_dir, exist_ok=True)

    # Root logger captures everything
    root_logger = logging.getLogger("selectinf")
    root_logger.setLevel(logging.DEBUG)
    root_logger.handlers.clear()

    # Console handler: INFO and above
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(_CONSOLE_FORMATTER)
    root_logger.addHandler(console_handler)

    # File handler: DEBUG and above, rotates daily (implicitly via date in filename)
    log_filename = os.path.join(
        _log_dir, f"selectinf_{datetime.now().strftime('%Y%m%d')}.log"
    )
    file_handler = logging.FileHandler(log_filename, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(_FILE_FORMATTER)
    root_logger.addHandler(file_handler)

    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger for a module. Initializes logging on first call."""
    _init_logging()
    return logging.getLogger(f"selectinf.{name}")
