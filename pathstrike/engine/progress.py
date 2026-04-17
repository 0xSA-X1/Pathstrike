"""Rich-based live progress display for attack path execution.

Provides a real-time dashboard showing the status of each step as the
orchestrator works through an attack path.  The display updates in-place
using Rich's Live rendering.

Status indicators:
  ⏳  pending      — step not yet attempted
  🔄  running      — step currently executing
  ✅  success      — step completed successfully
  ❌  failed       — step failed (no more retries)
  🔁  retrying     — step failed, retrying
  ⏭️  skipped      — step skipped (dry-run or user abort)
  🕐  time_sync    — performing automatic time sync
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class _QuietLive:
    """Context manager wrapping Rich's :class:`Live` with log-handler muzzling.

    During in-place Live rendering, stray log messages printed to the
    same console cause the panel to fragment / stack.  On ``__enter__``
    every handler attached to the pathstrike logger has its level
    raised to CRITICAL; on ``__exit__`` prior levels are restored.  The
    session log file keeps receiving records regardless — only
    console-bound output is suppressed during the Live context.

    The wrapper also proxies :meth:`update` so
    :meth:`AttackProgressTracker._refresh` can call ``self._live.update(...)``
    transparently whether the Live is active or not.
    """

    def __init__(self, tracker: "AttackProgressTracker") -> None:
        self._tracker = tracker
        self._live = Live(
            tracker._render(),
            console=tracker.console,
            refresh_per_second=4,
            transient=False,
        )
        self._prev_levels: list[tuple[logging.Handler, int]] = []

    def __enter__(self):
        pathstrike_logger = logging.getLogger("pathstrike")
        for handler in pathstrike_logger.handlers:
            self._prev_levels.append((handler, handler.level))
            handler.setLevel(logging.CRITICAL)
        self._live.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            return self._live.__exit__(exc_type, exc_val, exc_tb)
        finally:
            for handler, level in self._prev_levels:
                handler.setLevel(level)
            self._prev_levels.clear()

    def update(self, *args, **kwargs):
        return self._live.update(*args, **kwargs)

    def __getattr__(self, name: str):
        """Proxy any other attribute (start, stop, refresh, etc.) to the inner Live.

        The orchestrator may call ``.stop()``, ``.start(refresh=True)``,
        ``.refresh()`` or other Rich Live methods that we don't explicitly
        wrap — forward them transparently so the wrapper is a drop-in.
        """
        return getattr(self._live, name)


class StepStatus(StrEnum):
    """Visual status for each step in the progress display."""

    pending = "pending"
    running = "running"
    success = "success"
    failed = "failed"
    retrying = "retrying"
    skipped = "skipped"
    time_sync = "time_sync"
    dry_run = "dry_run"


_STATUS_ICONS: dict[StepStatus, str] = {
    StepStatus.pending: "⏳",
    StepStatus.running: "🔄",
    StepStatus.success: "✅",
    StepStatus.failed: "❌",
    StepStatus.retrying: "🔁",
    StepStatus.skipped: "⏭️ ",
    StepStatus.time_sync: "🕐",
    StepStatus.dry_run: "📝",
}

_STATUS_STYLES: dict[StepStatus, str] = {
    StepStatus.pending: "dim",
    StepStatus.running: "bold cyan",
    StepStatus.success: "bold green",
    StepStatus.failed: "bold red",
    StepStatus.retrying: "bold yellow",
    StepStatus.skipped: "dim yellow",
    StepStatus.time_sync: "bold magenta",
    StepStatus.dry_run: "dim cyan",
}


@dataclass
class StepProgress:
    """Tracks progress for a single attack step."""

    index: int
    edge_type: str
    source: str
    target: str
    status: StepStatus = StepStatus.pending
    message: str = ""
    attempt: int = 0
    max_retries: int = 0
    elapsed_seconds: float = 0.0
    error_category: str = ""
    _start_time: float | None = field(default=None, repr=False)

    def start(self) -> None:
        """Mark step as running and start the timer."""
        self.status = StepStatus.running
        self._start_time = time.monotonic()

    def complete(self, message: str = "") -> None:
        """Mark step as successfully completed."""
        self.status = StepStatus.success
        self.message = message
        self._stop_timer()

    def fail(self, message: str = "", error_category: str = "") -> None:
        """Mark step as failed."""
        self.status = StepStatus.failed
        self.message = message
        self.error_category = error_category
        self._stop_timer()

    def retry(self, attempt: int, message: str = "") -> None:
        """Mark step as retrying."""
        self.status = StepStatus.retrying
        self.attempt = attempt
        self.message = message
        self._start_time = time.monotonic()

    def mark_time_sync(self) -> None:
        """Mark step as performing time sync."""
        self.status = StepStatus.time_sync
        self.message = "Synchronising clock with DC..."

    def skip(self, message: str = "") -> None:
        """Mark step as skipped."""
        self.status = StepStatus.skipped
        self.message = message
        self._stop_timer()

    def mark_dry_run(self, message: str = "") -> None:
        """Mark step as dry-run."""
        self.status = StepStatus.dry_run
        self.message = message
        self._stop_timer()

    def _stop_timer(self) -> None:
        if self._start_time is not None:
            self.elapsed_seconds += time.monotonic() - self._start_time
            self._start_time = None


class AttackProgressTracker:
    """Manages a live Rich display showing attack path progress.

    Usage::

        tracker = AttackProgressTracker(console)
        tracker.add_step(0, "GenericAll", "JSMITH", "DC01")
        tracker.add_step(1, "DCSync", "DC01", "DOMAIN")

        with tracker.live():
            tracker.update_step(0, StepStatus.running)
            # ... do work ...
            tracker.update_step(0, StepStatus.success, "ACL modified")

    The live context renders the progress table in real-time.
    """

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self.steps: list[StepProgress] = []
        self._live: Live | None = None
        self._start_time: float = 0.0
        self._extra_messages: list[tuple[str, str]] = []  # (style, message)

    def add_step(
        self,
        index: int,
        edge_type: str,
        source: str,
        target: str,
        max_retries: int = 0,
    ) -> StepProgress:
        """Register a new step in the tracker."""
        step = StepProgress(
            index=index,
            edge_type=edge_type,
            source=source,
            target=target,
            max_retries=max_retries,
        )
        self.steps.append(step)
        return step

    def get_step(self, index: int) -> StepProgress | None:
        """Retrieve a step by index."""
        for step in self.steps:
            if step.index == index:
                return step
        return None

    def add_message(self, message: str, style: str = "dim") -> None:
        """Add a log message to the progress display."""
        self._extra_messages.append((style, message))
        # Keep only last 8 messages
        if len(self._extra_messages) > 8:
            self._extra_messages = self._extra_messages[-8:]
        self._refresh()

    def live(self) -> _QuietLive:
        """Return a Rich Live context manager for real-time rendering.

        Wraps Rich's :class:`Live` with log-handler muzzling: on
        ``__enter__`` every handler attached to the pathstrike logger is
        raised to CRITICAL; on ``__exit__`` prior levels are restored.
        This prevents stray log messages from emitting to stdout during
        Live's in-place re-render (which was causing the panel to
        stack/duplicate on-screen).  The DEBUG+ session log file keeps
        receiving every record regardless.

        Important: callers must use ``with tracker.live() as display:``.
        The returned wrapper proxies :meth:`update` to the underlying
        Live so :meth:`_refresh` keeps working via ``self._live``.
        """
        self._start_time = time.monotonic()
        self._live = _QuietLive(self)
        return self._live

    def _refresh(self) -> None:
        """Update the live display."""
        if self._live is not None:
            self._live.update(self._render())

    def refresh(self) -> None:
        """Public refresh — call after updating step status."""
        self._refresh()

    def _render(self) -> Panel:
        """Build the full progress panel."""
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="blue",
            expand=True,
            pad_edge=True,
        )
        table.add_column("", width=3, justify="center")  # status icon
        table.add_column("Step", width=5, justify="right", style="dim")
        table.add_column("Edge Type", style="bold", min_width=15)
        table.add_column("Source → Target", min_width=20)
        table.add_column("Status", min_width=12)
        table.add_column("Details", ratio=1)

        for step in self.steps:
            icon = _STATUS_ICONS.get(step.status, "?")
            style = _STATUS_STYLES.get(step.status, "")

            # Status text
            status_text = step.status.value
            if step.status == StepStatus.retrying:
                status_text = f"retry {step.attempt}/{step.max_retries}"

            # Elapsed time
            elapsed = step.elapsed_seconds
            if step._start_time is not None:
                elapsed += time.monotonic() - step._start_time
            time_str = f" ({elapsed:.1f}s)" if elapsed > 0.1 else ""

            # Detail message (truncated)
            detail = step.message[:60] + ("..." if len(step.message) > 60 else "")
            if step.error_category:
                detail = f"[{step.error_category}] {detail}"

            table.add_row(
                icon,
                str(step.index),
                Text(step.edge_type, style=style),
                f"[green]{step.source}[/] → [green]{step.target}[/]",
                Text(f"{status_text}{time_str}", style=style),
                Text(detail, style="dim" if step.status == StepStatus.pending else ""),
            )

        # Build the panel content
        content = table

        # Add log messages below the table
        if self._extra_messages:
            messages_text = Text()
            for msg_style, msg in self._extra_messages[-5:]:
                messages_text.append(f"\n  {msg}", style=msg_style)
            content = Table.grid()
            content.add_row(table)
            content.add_row(messages_text)

        # Summary stats
        total = len(self.steps)
        completed = sum(1 for s in self.steps if s.status == StepStatus.success)
        failed = sum(1 for s in self.steps if s.status == StepStatus.failed)
        elapsed_total = time.monotonic() - self._start_time if self._start_time else 0

        subtitle = (
            f"[dim]{completed}/{total} completed"
            f"{f' · {failed} failed' if failed else ''}"
            f" · {elapsed_total:.1f}s elapsed[/]"
        )

        return Panel(
            content,
            title="[bold]⚔️  PathStrike — Attack Progress[/]",
            subtitle=subtitle,
            border_style="blue",
            expand=True,
        )

    def print_summary(self) -> None:
        """Print a final summary table after execution completes."""
        self.console.print()

        table = Table(
            title="Execution Summary",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Step", width=5, justify="right")
        table.add_column("Edge", style="bold")
        table.add_column("Source → Target")
        table.add_column("Result")
        table.add_column("Attempts", justify="center")
        table.add_column("Time", justify="right")
        table.add_column("Details")

        for step in self.steps:
            icon = _STATUS_ICONS.get(step.status, "?")
            style = _STATUS_STYLES.get(step.status, "")
            attempts = f"{step.attempt + 1}" if step.attempt > 0 else "1"
            elapsed = f"{step.elapsed_seconds:.1f}s" if step.elapsed_seconds > 0.1 else "-"

            table.add_row(
                str(step.index),
                step.edge_type,
                f"{step.source} → {step.target}",
                Text(f"{icon} {step.status.value}", style=style),
                attempts,
                elapsed,
                step.message[:80],
            )

        self.console.print(table)

        # Stats
        total = len(self.steps)
        succeeded = sum(1 for s in self.steps if s.status == StepStatus.success)
        failed = sum(1 for s in self.steps if s.status == StepStatus.failed)
        total_time = sum(s.elapsed_seconds for s in self.steps)

        if failed == 0 and succeeded == total:
            self.console.print(
                f"\n[bold green]✅ All {total} steps completed successfully "
                f"in {total_time:.1f}s[/]"
            )
        elif failed > 0:
            self.console.print(
                f"\n[bold red]❌ {failed}/{total} steps failed. "
                f"{succeeded} succeeded in {total_time:.1f}s[/]"
            )
        else:
            self.console.print(
                f"\n[dim]{succeeded}/{total} steps processed in {total_time:.1f}s[/]"
            )
