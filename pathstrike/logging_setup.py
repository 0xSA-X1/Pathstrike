"""Rich-based logging configuration for PathStrike.

Default (non-verbose) console output is intentionally quiet: only INFO+
goes to the terminal, and most handled/expected failures are emitted at
DEBUG.  Every run still gets a full DEBUG-level session log file on disk
so warnings and errors that were demoted off-screen are still reviewable
after the fact — :func:`print_log_summary` prints a one-line hint at the
end of each command pointing at the file whenever anything was logged
at WARNING or higher.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

from pathstrike.utils.security import CredentialScrubFilter

LOGGER_NAME = "pathstrike"

_FILE_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s.%(module)s | %(message)s"
_FILE_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

# Shared credential-scrubbing filter applied to all handlers
_credential_filter = CredentialScrubFilter()

# Per-session state set by setup_logging() and read back by the CLI at
# end-of-command to surface a "N warnings occurred" hint.
_session_log_path: Path | None = None
_warning_counter: "_WarningCounter | None" = None


class _WarningCounter(logging.Handler):
    """Handler that counts WARNING+ records (regardless of console level).

    Used by :func:`print_log_summary` to report how many warnings/errors
    were logged during a run even when the console was quiet.  Records are
    not stored to avoid unbounded memory — the session log file on disk is
    the authoritative copy.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.warning_count = 0
        self.error_count = 0

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno >= logging.ERROR:
            self.error_count += 1
        elif record.levelno >= logging.WARNING:
            self.warning_count += 1


def setup_logging(
    verbose: bool = False,
    log_file: Path | None = None,
    quiet: bool = False,
) -> logging.Logger:
    """Configure and return the pathstrike logger.

    Args:
        verbose: If True, set console level to DEBUG; otherwise INFO.
            The session log file always captures DEBUG+ regardless.
        log_file: Optional explicit log-file path.  When omitted, a
            timestamped file is created at
            ``~/.pathstrike/logs/session_<YYYYMMDD_HHMMSS>.log``.
        quiet: If True, suppress console output entirely (file logging
            still active).

    Returns:
        The configured ``pathstrike`` logger instance.
    """
    global _session_log_path, _warning_counter

    logger = logging.getLogger(LOGGER_NAME)

    # Prevent duplicate handlers on repeated calls
    if logger.handlers:
        logger.handlers.clear()

    # Clear any existing filters on the logger itself
    for f in logger.filters[:]:
        logger.removeFilter(f)

    console_level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(logging.DEBUG)  # file handler needs DEBUG; console filters above

    # Apply credential scrubbing at the logger level so it covers all handlers
    logger.addFilter(_credential_filter)

    # --- Rich console handler (suppressed in quiet mode) ---
    if not quiet:
        console_handler = RichHandler(
            level=console_level,
            show_time=True,
            show_path=verbose,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=verbose,
        )
        console_handler.setLevel(console_level)
        console_handler.addFilter(_credential_filter)
        logger.addHandler(console_handler)

    # --- File handler: explicit path or auto-generated session log ---
    if log_file is not None:
        log_path = Path(log_file).expanduser().resolve()
    else:
        default_dir = Path.home() / ".pathstrike" / "logs"
        log_path = default_dir / f"session_{time.strftime('%Y%m%d_%H%M%S')}.log"

    log_path.parent.mkdir(parents=True, exist_ok=True)
    _session_log_path = log_path

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter(fmt=_FILE_FORMAT, datefmt=_FILE_DATE_FORMAT)
    )
    file_handler.addFilter(_credential_filter)
    logger.addHandler(file_handler)

    # --- Warning counter (level-agnostic, doesn't emit to console) ---
    _warning_counter = _WarningCounter()
    _warning_counter.addFilter(_credential_filter)
    logger.addHandler(_warning_counter)

    # Don't propagate to root logger
    logger.propagate = False

    return logger


def get_session_log_path() -> Path | None:
    """Return the current run's session log file path, if configured."""
    return _session_log_path


def get_log_counts() -> tuple[int, int]:
    """Return ``(warning_count, error_count)`` for the current session."""
    if _warning_counter is None:
        return (0, 0)
    return (_warning_counter.warning_count, _warning_counter.error_count)


def print_log_summary(console: Console | None = None) -> None:
    """Print a one-line summary pointing at the session log, if needed.

    No output when nothing was logged at WARNING or higher.  Otherwise
    prints the counts and a ready-to-copy ``cat`` command so the user
    can review details after a quiet run.
    """
    if console is None:
        console = Console()

    warnings, errors = get_log_counts()
    if warnings == 0 and errors == 0:
        return
    if _session_log_path is None:
        return

    parts: list[str] = []
    if errors:
        parts.append(f"[red]{errors} error(s)[/]")
    if warnings:
        parts.append(f"[yellow]{warnings} warning(s)[/]")
    summary = " and ".join(parts)

    console.print(
        f"\n[bold]⚠  {summary} logged during this run.[/]"
    )
    console.print(f"   [dim]cat {_session_log_path}[/]")
