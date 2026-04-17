"""Main execution engine that drives the attack path exploitation loop.

This orchestrator provides:
- Live Rich progress display showing per-step status
- Automatic error classification and diagnosis
- Configurable retry logic with exponential backoff
- Automatic Kerberos time-sync detection and remediation
- Detailed verbosity for debugging tool failures
- Checkpoint/resume support for interrupted attack paths
"""

from __future__ import annotations

import asyncio
import logging

from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from pathstrike.config import PathStrikeConfig
from pathstrike.engine.checkpoint import CheckpointManager
from pathstrike.engine.credential_store import CredentialStore
from pathstrike.engine.edge_registry import get_handler
from pathstrike.engine.error_handler import (
    ErrorCategory,
    ErrorDiagnosis,
    Remediation,
    RetryPolicy,
    diagnose_error,
    get_backoff_seconds,
    is_time_skew_error,
    should_retry,
)
from pathstrike.engine.progress import AttackProgressTracker, StepStatus
from pathstrike.engine.rollback import RollbackManager
from pathstrike.engine.time_sync import (
    TimeSyncResult,
    sync_time_with_faketime_fallback,
)
from pathstrike.models import AttackPath, Credential, ExecutionMode, PathStep

# Trigger handler registration by importing the handlers package.
# Concrete handler modules use @register_handler which populates the registry
# at import time.
try:
    import pathstrike.handlers  # noqa: F401
except ImportError:
    pass

logger = logging.getLogger("pathstrike")
console = Console()


class AttackOrchestrator:
    """Orchestrates the step-by-step exploitation of a BloodHound attack path.

    The orchestrator iterates through each edge in an :class:`AttackPath`,
    locates the registered handler for that edge type, and executes the
    exploit (or dry-run).  In interactive mode, the user is prompted before
    each step.

    Features:
    - **Live progress**: Real-time dashboard via Rich showing ✅/❌/🔁 per step.
    - **Error diagnosis**: Classifies failures into categories (auth, time skew,
      network, etc.) and provides human-readable explanations.
    - **Retry logic**: Automatically retries transient failures (time skew,
      timeout, network) with exponential backoff.
    - **Time sync auto-fix**: Detects ``KRB_AP_ERR_SKEW`` and runs ``ntpdate``
      against the DC before retrying.
    - **Checkpoint/resume**: Saves progress after each step so failed paths
      can be resumed from the last successful step.
    """

    def __init__(
        self,
        config: PathStrikeConfig,
        cred_store: CredentialStore,
        rollback_mgr: RollbackManager,
        retry_policy: RetryPolicy | None = None,
        verbose: bool = False,
        checkpoint_mgr: CheckpointManager | None = None,
    ) -> None:
        self.config = config
        self.cred_store = cred_store
        self.rollback_mgr = rollback_mgr
        self.retry_policy = retry_policy or RetryPolicy()
        self.verbose = verbose
        self.checkpoint_mgr = checkpoint_mgr
        self._time_synced = False  # track whether we've already synced this run

    async def execute_path(self, path: AttackPath, mode: ExecutionMode) -> bool:
        """Execute an attack path end-to-end with progress tracking and retry.

        Args:
            path: The attack path to exploit.
            mode: Execution mode (interactive, auto, or dry_run).

        Returns:
            True if the final target was reached successfully.
        """
        # ---- Pre-flight check ----
        unsupported = self._preflight_check(path)
        if unsupported:
            console.print(
                f"[bold red]Pre-flight failed:[/] unsupported edge types: "
                f"{', '.join(unsupported)}"
            )
            logger.error("Pre-flight: unsupported edges: %s", unsupported)
            return False

        console.print(
            f"\n[bold cyan]⚔️  Executing attack path[/] "
            f"({path.total_cost} step(s)): "
            f"[green]{path.source.name}[/] → [red]{path.target.name}[/]\n"
        )

        # ---- Initialize checkpoint ----
        if self.checkpoint_mgr is not None:
            self.checkpoint_mgr.start_path(path)

        # ---- Build progress tracker ----
        tracker = AttackProgressTracker(console)
        for step in path.steps:
            tracker.add_step(
                index=step.index,
                edge_type=step.edge.edge_type,
                source=step.edge.source.name,
                target=step.edge.target.name,
                max_retries=self.retry_policy.max_retries,
            )

        # ---- Execute with live progress ----
        success = False
        with tracker.live():
            success = await self._execute_steps(path, mode, tracker)

        # ---- Mark checkpoint complete on success ----
        if success and self.checkpoint_mgr is not None:
            self.checkpoint_mgr.mark_complete()

        # ---- Print summary ----
        tracker.print_summary()
        return success

    async def execute_path_from_checkpoint(
        self,
        path: AttackPath,
        mode: ExecutionMode,
        resume_index: int,
    ) -> bool:
        """Execute an attack path, skipping steps before *resume_index*.

        This is used to resume a previously failed attack path from the last
        successful step.  Steps with ``index < resume_index`` are marked as
        already completed and skipped.

        Args:
            path: The attack path to exploit.
            mode: Execution mode (interactive, auto, or dry_run).
            resume_index: The step index to resume from (first step that was
                NOT completed in the previous run).

        Returns:
            True if the final target was reached successfully.
        """
        # ---- Pre-flight check ----
        unsupported = self._preflight_check(path)
        if unsupported:
            console.print(
                f"[bold red]Pre-flight failed:[/] unsupported edge types: "
                f"{', '.join(unsupported)}"
            )
            logger.error("Pre-flight: unsupported edges: %s", unsupported)
            return False

        console.print(
            f"\n[bold cyan]⚔️  Resuming attack path from step {resume_index}[/] "
            f"({path.total_cost} step(s)): "
            f"[green]{path.source.name}[/] → [red]{path.target.name}[/]\n"
        )

        # ---- Initialize checkpoint for resumed path ----
        if self.checkpoint_mgr is not None:
            self.checkpoint_mgr.start_path(path)

        # ---- Build progress tracker ----
        tracker = AttackProgressTracker(console)
        for step in path.steps:
            tracker.add_step(
                index=step.index,
                edge_type=step.edge.edge_type,
                source=step.edge.source.name,
                target=step.edge.target.name,
                max_retries=self.retry_policy.max_retries,
            )

        # ---- Execute with live progress, skipping completed steps ----
        success = False
        with tracker.live():
            success = await self._execute_steps(
                path, mode, tracker, resume_index=resume_index
            )

        # ---- Mark checkpoint complete on success ----
        if success and self.checkpoint_mgr is not None:
            self.checkpoint_mgr.mark_complete()

        # ---- Print summary ----
        tracker.print_summary()
        return success

    async def _execute_steps(
        self,
        path: AttackPath,
        mode: ExecutionMode,
        tracker: AttackProgressTracker,
        resume_index: int = 0,
    ) -> bool:
        """Inner loop: iterate steps with retry and progress updates.

        Args:
            path: The attack path.
            mode: Execution mode.
            tracker: Progress tracker.
            resume_index: Skip steps with index < this value (used for resume).
        """
        for step in path.steps:
            step_progress = tracker.get_step(step.index)
            assert step_progress is not None

            # ---- Skip already-completed steps when resuming ----
            if step.index < resume_index:
                step.status = "skipped_resume"
                step.result = "Completed in previous run"
                step_progress.complete("Skipped (completed in previous run)")
                tracker.add_message(
                    f"Step {step.index}: Skipped (completed in previous run)",
                    "dim green",
                )
                tracker.refresh()
                # Record the skip in checkpoint as well
                if self.checkpoint_mgr is not None:
                    self.checkpoint_mgr.record_step_success(step)
                continue

            # ---- Interactive prompt ----
            if mode == ExecutionMode.interactive:
                # Temporarily pause live display for user input
                tracker._live.stop() if tracker._live else None  # type: ignore[union-attr]
                if not self._prompt_user(step):
                    step_progress.skip("User aborted")
                    console.print(
                        f"[yellow]User aborted at step {step.index}[/]"
                    )
                    logger.info("User aborted at step %d", step.index)
                    tracker._live.start() if tracker._live else None  # type: ignore[union-attr]
                    tracker.refresh()
                    return False
                tracker._live.start() if tracker._live else None  # type: ignore[union-attr]

            handler_cls = get_handler(step.edge.edge_type)
            if handler_cls is None:
                step.status = "error"
                step.result = f"No handler for edge type: {step.edge.edge_type}"
                step_progress.fail(step.result)
                tracker.refresh()
                logger.error(step.result)
                if self.checkpoint_mgr is not None:
                    self.checkpoint_mgr.record_step_failure(step, step.result)
                return False

            # Instantiate the handler
            handler = handler_cls(
                config=self.config,
                credential_store=self.cred_store,
            )
            step.handler_name = handler.__class__.__name__

            # ---- Check prerequisites ----
            step_progress.start()
            tracker.add_message(
                f"Step {step.index}: Checking prerequisites for {step.edge.edge_type}...",
                "dim cyan",
            )
            tracker.refresh()

            prereq_ok, prereq_msg = await handler.check_prerequisites(step.edge)
            if not prereq_ok:
                step.status = "error"
                step.result = f"Prerequisites not met: {prereq_msg}"
                step_progress.fail(step.result)
                tracker.add_message(
                    f"Step {step.index}: ❌ Prerequisites failed — {prereq_msg}",
                    "bold red",
                )
                tracker.refresh()
                logger.error(
                    "Step %d prerequisites failed: %s", step.index, prereq_msg
                )
                if self.checkpoint_mgr is not None:
                    self.checkpoint_mgr.record_step_failure(step, step.result)
                return False

            # ---- Dry-run mode ----
            is_dry_run = mode == ExecutionMode.dry_run
            if is_dry_run:
                success, result_msg, _ = await handler.exploit(
                    step.edge, dry_run=True
                )
                step.status = "dry_run"
                step.result = result_msg
                step_progress.mark_dry_run(result_msg)
                tracker.add_message(
                    f"Step {step.index}: 📝 [DRY RUN] {result_msg}",
                    "dim cyan",
                )
                tracker.refresh()
                logger.info("Step %d dry-run: %s", step.index, result_msg)
                continue

            # ---- Execute with retry ----
            tracker.add_message(
                f"Step {step.index}: Exploiting {step.edge.edge_type}...",
                "bold cyan",
            )
            tracker.refresh()

            step_success = await self._execute_with_retry(
                step, handler, step_progress, tracker
            )

            if not step_success:
                # Record failure in checkpoint
                if self.checkpoint_mgr is not None:
                    self.checkpoint_mgr.record_step_failure(
                        step, step.result or "Unknown failure"
                    )
                return False

            # ---- Record rollback action ----
            rollback_action = handler.get_rollback_action(step.edge)
            if rollback_action is not None:
                rollback_action.step_index = step.index
                self.rollback_mgr.record(rollback_action)

        # ---- All steps completed ----
        if mode == ExecutionMode.dry_run:
            console.print(
                "\n[bold yellow]Dry-run complete.[/] No changes were made."
            )
        else:
            console.print(
                f"\n[bold green]🏆 Attack path complete![/] "
                f"Reached target: [red]{path.target.name}[/]"
            )
        return True

    async def _execute_with_retry(
        self,
        step: PathStep,
        handler: object,  # BaseEdgeHandler — avoid circular import
        step_progress: object,  # StepProgress
        tracker: AttackProgressTracker,
    ) -> bool:
        """Execute a single step with retry logic and error diagnosis.

        Returns True on success, False on permanent failure.
        """
        from pathstrike.handlers.base import BaseEdgeHandler

        assert isinstance(handler, BaseEdgeHandler)
        sp = step_progress  # type: ignore[assignment]

        for attempt in range(self.retry_policy.max_retries + 1):
            if attempt > 0:
                sp.retry(attempt, f"Retry {attempt}/{self.retry_policy.max_retries}")  # type: ignore[attr-defined]
                tracker.refresh()

            # ---- Execute ----
            try:
                success, result_msg, new_creds = await handler.exploit(
                    step.edge, dry_run=False
                )
            except Exception as exc:
                # Catch unexpected exceptions from handlers
                success = False
                result_msg = f"Unexpected error: {exc}"
                new_creds = []
                logger.exception(
                    "Step %d raised unexpected exception", step.index
                )

            if success:
                # ---- SUCCESS ----
                step.status = "completed"
                step.result = result_msg
                sp.complete(result_msg)  # type: ignore[attr-defined]
                tracker.add_message(
                    f"Step {step.index}: ✅ {result_msg}",
                    "bold green",
                )
                tracker.refresh()
                logger.info("Step %d completed: %s", step.index, result_msg)

                # Store newly obtained credentials
                for cred in new_creds:
                    self.cred_store.add_credential(cred)
                    tracker.add_message(
                        f"  💎 Credential captured: {cred.username} ({cred.cred_type})",
                        "bold yellow",
                    )
                    tracker.refresh()

                # ---- Record success in checkpoint ----
                if self.checkpoint_mgr is not None:
                    self.checkpoint_mgr.record_step_success(step, new_creds)

                return True

            # ---- FAILURE — diagnose ----
            # Build a result dict for the error handler
            error_result = {
                "success": False,
                "output": result_msg,
                "error": result_msg,
            }
            diagnosis = diagnose_error(error_result)

            self._log_failure(step, attempt, diagnosis, tracker)

            # ---- Time skew auto-fix ----
            if diagnosis.remediation == Remediation.SYNC_TIME:
                sync_result = await self._auto_time_sync(step, sp, tracker)
                if sync_result and sync_result.success:
                    # Time synced — retry immediately (don't count as backoff)
                    continue

            # ---- Check if we should retry ----
            if not should_retry(diagnosis, attempt, self.retry_policy):
                step.status = "failed"
                step.result = result_msg
                sp.fail(result_msg, diagnosis.category.value)  # type: ignore[attr-defined]
                tracker.add_message(
                    f"Step {step.index}: ❌ FAILED — {diagnosis.message}",
                    "bold red",
                )
                tracker.refresh()
                return False

            # ---- Backoff before retry ----
            backoff = get_backoff_seconds(attempt, self.retry_policy)
            tracker.add_message(
                f"Step {step.index}: ⏳ Waiting {backoff:.1f}s before retry "
                f"({diagnosis.category})...",
                "yellow",
            )
            tracker.refresh()
            await asyncio.sleep(backoff)

        # Exhausted all retries
        step.status = "failed"
        step.result = f"Failed after {self.retry_policy.max_retries + 1} attempts"
        sp.fail(step.result)  # type: ignore[attr-defined]
        tracker.refresh()
        return False

    async def _auto_time_sync(
        self,
        step: PathStep,
        step_progress: object,
        tracker: AttackProgressTracker,
    ) -> TimeSyncResult | None:
        """Detect and fix Kerberos clock skew automatically.

        Uses ``ntpdate`` (or fallback tools) to sync the local clock with
        the Domain Controller, then signals the caller to retry.
        """
        sp = step_progress  # type: ignore[assignment]

        if self._time_synced:
            tracker.add_message(
                f"Step {step.index}: ⚠️  Already synced time this session — skipping repeat sync",
                "yellow",
            )
            tracker.refresh()
            return None

        tracker.add_message(
            f"Step {step.index}: 🕐 Clock skew detected! Auto-syncing with DC...",
            "bold magenta",
        )
        sp.mark_time_sync()  # type: ignore[attr-defined]
        tracker.refresh()

        dc_host = self.config.domain.dc_host
        dc_fqdn = self.config.domain.dc_fqdn

        result = await sync_time_with_faketime_fallback(dc_host, dc_fqdn)

        if result.success:
            self._time_synced = True
            tracker.add_message(
                f"Step {step.index}: ✅ Time synced via {result.method}"
                f"{f' (offset was {result.offset_seconds:.1f}s)' if result.offset_seconds else ''}",
                "bold green",
            )
            tracker.refresh()
            logger.info("Time sync successful: %s", result.message)
        else:
            tracker.add_message(
                f"Step {step.index}: ❌ Time sync FAILED — {result.message}",
                "bold red",
            )
            tracker.add_message(
                "  💡 Try manually: sudo ntpdate " + (dc_fqdn or dc_host),
                "yellow",
            )
            tracker.refresh()
            logger.error("Time sync failed: %s", result.message)

        return result

    def _log_failure(
        self,
        step: PathStep,
        attempt: int,
        diagnosis: ErrorDiagnosis,
        tracker: AttackProgressTracker,
    ) -> None:
        """Log detailed failure information with verbosity-aware output."""
        prefix = f"Step {step.index} (attempt {attempt + 1})"

        # Always log the diagnosis
        logger.warning(
            "%s FAILED — [%s] %s",
            prefix,
            diagnosis.category,
            diagnosis.message,
        )

        # Verbose: show raw error details
        if self.verbose and diagnosis.raw_error:
            logger.debug("%s raw error: %s", prefix, diagnosis.raw_error[:500])

        # Show diagnosis in progress panel
        tracker.add_message(
            f"{prefix}: ⚠️  [{diagnosis.category}] {diagnosis.message}",
            "bold yellow" if diagnosis.retryable else "bold red",
        )

        if diagnosis.retryable:
            tracker.add_message(
                f"  💡 Remediation: {diagnosis.remediation} — will retry",
                "dim yellow",
            )
        else:
            tracker.add_message(
                f"  🛑 Non-retryable: {diagnosis.remediation}",
                "dim red",
            )

        tracker.refresh()

    def _preflight_check(self, path: AttackPath) -> list[str]:
        """Verify that every edge type in the path has a registered handler.

        Args:
            path: The attack path to validate.

        Returns:
            List of edge type strings that have no registered handler.
            An empty list means all edges are supported.
        """
        unsupported: list[str] = []
        seen: set[str] = set()

        for step in path.steps:
            et = step.edge.edge_type
            if et not in seen:
                seen.add(et)
                if get_handler(et) is None:
                    unsupported.append(et)

        return unsupported

    def _prompt_user(self, step: PathStep) -> bool:
        """Prompt the user for confirmation before executing a step.

        Args:
            step: The path step about to be executed.

        Returns:
            True if the user confirms, False to abort.
        """
        table = Table(
            title=f"Step {step.index}",
            show_header=False,
            border_style="cyan",
        )
        table.add_row("Edge Type", f"[bold]{step.edge.edge_type}[/]")
        table.add_row(
            "Source",
            f"{step.edge.source.name} ({step.edge.source.label})",
        )
        table.add_row(
            "Target",
            f"{step.edge.target.name} ({step.edge.target.label})",
        )
        console.print(table)

        return Confirm.ask(
            "[bold yellow]Proceed with this step?[/]", default=True
        )
