"""Rich-based logging configuration for PathStrike."""

from __future__ import annotations

import logging
from pathlib import Path

from rich.logging import RichHandler

from pathstrike.utils.security import CredentialScrubFilter

LOGGER_NAME = "pathstrike"

_FILE_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s.%(module)s | %(message)s"
_FILE_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

# Shared credential-scrubbing filter applied to all handlers
_credential_filter = CredentialScrubFilter()


def setup_logging(
    verbose: bool = False,
    log_file: Path | None = None,
    quiet: bool = False,
) -> logging.Logger:
    """Configure and return the pathstrike logger.

    Args:
        verbose: If True, set level to DEBUG; otherwise INFO.
        log_file: Optional path for a persistent log file with structured output.
        quiet: If True, suppress console output (only file logging remains).

    Returns:
        The configured ``pathstrike`` logger instance.
    """
    logger = logging.getLogger(LOGGER_NAME)

    # Prevent duplicate handlers on repeated calls
    if logger.handlers:
        logger.handlers.clear()

    # Clear any existing filters on the logger itself
    for f in logger.filters[:]:
        logger.removeFilter(f)

    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    # Apply credential scrubbing at the logger level so it covers all handlers
    logger.addFilter(_credential_filter)

    # --- Rich console handler (suppressed in quiet mode) ---
    if not quiet:
        console_handler = RichHandler(
            level=level,
            show_time=True,
            show_path=verbose,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=verbose,
        )
        console_handler.setLevel(level)
        console_handler.addFilter(_credential_filter)
        logger.addHandler(console_handler)

    # --- Optional file handler ---
    if log_file is not None:
        log_path = Path(log_file).expanduser().resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(fmt=_FILE_FORMAT, datefmt=_FILE_DATE_FORMAT)
        )
        file_handler.addFilter(_credential_filter)
        logger.addHandler(file_handler)

    # Don't propagate to root logger
    logger.propagate = False

    return logger
