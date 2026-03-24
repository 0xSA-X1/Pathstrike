"""LIFO rollback manager for reversing exploitation actions.

Records :class:`RollbackAction` objects during an attack path execution
and can replay them in reverse order to undo changes made to the target
Active Directory environment.

Rollback state can be persisted to JSON for out-of-band / deferred cleanup.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import shlex
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pathstrike.config import PathStrikeConfig
from pathstrike.models import RollbackAction

logger = logging.getLogger("pathstrike.engine.rollback")


class RollbackManager:
    """Manages a LIFO stack of reversible actions recorded during exploitation.

    Actions are stored in insertion order and executed in reverse (LIFO)
    during rollback to ensure dependent changes are unwound correctly.
    """

    def __init__(self, config: PathStrikeConfig) -> None:
        self._actions: list[RollbackAction] = []
        self._failed_rollbacks: list[dict[str, Any]] = []
        self._config = config
        self.logger = logging.getLogger("pathstrike.engine.rollback")

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(self, action: RollbackAction) -> None:
        """Push a rollback action onto the stack.

        Args:
            action: The reversible action to record.
        """
        self._actions.append(action)
        self.logger.info(
            "Recorded rollback action [step %d]: %s",
            action.step_index,
            action.description,
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def rollback_all(self, force: bool = False) -> list[dict[str, Any]]:
        """Execute all recorded rollback actions in LIFO order.

        Args:
            force: If ``True``, continue executing remaining rollbacks even
                if one fails.  If ``False`` (default), stop on first failure.

        Returns:
            A list of result dicts, one per action, in the order they
            were executed (i.e. reverse of recording order).
        """
        results: list[dict[str, Any]] = []

        if not self._actions:
            self.logger.info("No rollback actions recorded; nothing to do")
            return results

        self.logger.info(
            "Starting rollback of %d action(s) in LIFO order (force=%s)",
            len(self._actions),
            force,
        )

        # Process in reverse (LIFO)
        for action in reversed(self._actions):
            success = await self._execute_rollback(action)
            results.append(
                {
                    "step_index": action.step_index,
                    "description": action.description,
                    "success": success,
                    "command": action.command,
                }
            )
            if not success and not force:
                self.logger.error(
                    "Rollback failed at step %d and force=False; stopping",
                    action.step_index,
                )
                break

        succeeded = sum(1 for r in results if r["success"])
        self.logger.info(
            "Rollback complete: %d/%d succeeded", succeeded, len(results)
        )

        return results

    async def rollback_step(self, step_index: int) -> list[dict[str, Any]]:
        """Rollback all actions associated with a specific step index.

        Args:
            step_index: The attack path step index to roll back.

        Returns:
            A list of result dicts for the rolled-back actions.
        """
        results: list[dict[str, Any]] = []
        step_actions = [a for a in self._actions if a.step_index == step_index]

        if not step_actions:
            self.logger.warning(
                "No rollback actions found for step %d", step_index
            )
            return results

        self.logger.info(
            "Rolling back %d action(s) for step %d", len(step_actions), step_index
        )

        # Process in reverse order within this step
        for action in reversed(step_actions):
            success = await self._execute_rollback(action)
            results.append(
                {
                    "step_index": action.step_index,
                    "description": action.description,
                    "success": success,
                    "command": action.command,
                }
            )

        return results

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def get_actions(self) -> list[RollbackAction]:
        """Return a copy of all recorded rollback actions (insertion order)."""
        return list(self._actions)

    def get_pending_actions(self) -> list[RollbackAction]:
        """Return all actions that are reversible and not yet executed, in LIFO order."""
        return [
            action
            for action in reversed(self._actions)
            if action.reversible and not action.executed
        ]

    def __len__(self) -> int:
        return len(self._actions)

    def __repr__(self) -> str:
        pending = sum(1 for a in self._actions if not a.executed and a.reversible)
        return f"<RollbackManager total={len(self._actions)} pending={pending}>"

    def get_failed_rollbacks(self) -> list[dict[str, Any]]:
        """Return details of rollback actions that failed during execution."""
        return list(self._failed_rollbacks)

    def dry_run_rollback(self) -> list[dict[str, Any]]:
        """Preview rollback actions without executing them.

        Returns a list of dicts describing each pending action in LIFO order.
        """
        pending = self.get_pending_actions()
        return [
            {
                "step_index": action.step_index,
                "description": action.description,
                "command": action.command,
                "action_type": action.action_type,
            }
            for action in pending
        ]

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def register_signal_handlers(self) -> None:
        """Register SIGINT/SIGTERM handlers to prompt for rollback on exit."""
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, functools.partial(self._signal_handler, sig))
        self.logger.debug("Registered signal handlers for graceful rollback")

    def _signal_handler(self, sig: signal.Signals) -> None:
        """Handle interruption signals by logging pending rollback actions."""
        pending = self.get_pending_actions()
        if pending:
            self.logger.warning(
                "Received %s with %d pending rollback action(s). "
                "Run 'pathstrike rollback <log_file>' to undo changes.",
                sig.name,
                len(pending),
            )
        raise SystemExit(128 + sig.value)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_to_file(self, path: Path) -> None:
        """Serialize all rollback actions to a JSON file.

        Args:
            path: Filesystem path for the output JSON file.
        """
        output_path = Path(path).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "domain": self._config.domain.name,
            "dc_host": self._config.domain.dc_host,
            "actions": [action.model_dump(mode="json") for action in self._actions],
        }

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

        self.logger.info(
            "Saved %d rollback action(s) to %s", len(self._actions), output_path
        )

    @classmethod
    def load_from_file(
        cls, path: Path, config: PathStrikeConfig
    ) -> RollbackManager:
        """Restore a RollbackManager from a previously saved JSON file.

        Args:
            path: Path to the JSON file.
            config: Active PathStrike configuration (needed for executing
                rollback commands that require DC host, domain, and auth).

        Returns:
            A new :class:`RollbackManager` with the loaded actions.

        Raises:
            FileNotFoundError: If the JSON file does not exist.
            json.JSONDecodeError: If the file is not valid JSON.
            pydantic.ValidationError: If action data fails validation.
        """
        file_path = Path(path).expanduser().resolve()

        if not file_path.exists():
            raise FileNotFoundError(f"Rollback file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        manager = cls(config)

        for action_data in data.get("actions", []):
            action = RollbackAction.model_validate(action_data)
            manager._actions.append(action)

        logger.info(
            "Loaded %d rollback action(s) from %s", len(manager._actions), file_path
        )

        return manager

    # ------------------------------------------------------------------
    # Internal: execute a single rollback action
    # ------------------------------------------------------------------

    async def _execute_rollback(self, action: RollbackAction, verify: bool = False) -> bool:
        """Execute a single rollback action by running its command.

        The command string is split into arguments and executed as a
        subprocess.  The action's ``executed`` flag is set on success.

        Args:
            action: The rollback action to execute.
            verify: If ``True``, attempt to verify the rollback succeeded
                by re-reading the affected attribute (bloodyAD commands only).

        Returns:
            ``True`` if the command succeeded (exit code 0), ``False`` otherwise.
        """
        if action.executed:
            self.logger.warning(
                "Action already executed, skipping: %s", action.description
            )
            return True

        if not action.reversible:
            self.logger.warning(
                "Action marked non-reversible, skipping: %s", action.description
            )
            return False

        self.logger.info("Executing rollback: %s", action.description)
        self.logger.debug("Rollback command: %s", action.command)

        try:
            cmd_parts = self._build_rollback_command(action.command)

            proc = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=self._config.execution.timeout,
            )

            stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
            stderr = stderr_bytes.decode("utf-8", errors="replace").strip()

            if proc.returncode == 0:
                action.executed = True
                self.logger.info("Rollback succeeded: %s", action.description)
                if stdout:
                    self.logger.debug("Rollback output: %s", stdout[:500])

                # Verification step
                if verify:
                    if cmd_parts and cmd_parts[0].lower() == "bloodyad":
                        self.logger.info(
                            "Verification requested for bloodyAD rollback: %s "
                            "(verification not yet implemented)",
                            action.description,
                        )
                    else:
                        self.logger.info(
                            "Verification is not yet implemented for non-bloodyAD "
                            "commands: %s",
                            action.description,
                        )

                return True

            error_msg = stderr[:500] if stderr else f"exit code {proc.returncode}"
            self.logger.error(
                "Rollback failed (rc=%d): %s | stderr: %s",
                proc.returncode,
                action.description,
                stderr[:500],
            )
            self._failed_rollbacks.append(
                {
                    "step_index": action.step_index,
                    "description": action.description,
                    "command": action.command,
                    "error": error_msg,
                }
            )
            return False

        except asyncio.TimeoutError:
            error_msg = f"Timed out after {self._config.execution.timeout}s"
            self.logger.error(
                "Rollback timed out after %ds: %s",
                self._config.execution.timeout,
                action.description,
            )
            self._failed_rollbacks.append(
                {
                    "step_index": action.step_index,
                    "description": action.description,
                    "command": action.command,
                    "error": error_msg,
                }
            )
            return False
        except FileNotFoundError:
            error_msg = f"Tool not found for command: {action.command}"
            self.logger.error(
                "Rollback tool not found for command: %s", action.command
            )
            self._failed_rollbacks.append(
                {
                    "step_index": action.step_index,
                    "description": action.description,
                    "command": action.command,
                    "error": error_msg,
                }
            )
            return False
        except OSError as exc:
            error_msg = str(exc)
            self.logger.error(
                "Rollback OS error: %s -- %s", action.description, exc
            )
            self._failed_rollbacks.append(
                {
                    "step_index": action.step_index,
                    "description": action.description,
                    "command": action.command,
                    "error": error_msg,
                }
            )
            return False

    def _build_rollback_command(self, raw_command: str) -> list[str]:
        """Parse the stored command and inject connection arguments.

        If the command starts with ``bloodyAD``, inject ``--host`` and
        ``-d`` from the current configuration plus authentication args
        from the config credentials.

        Args:
            raw_command: The raw command string stored in the rollback action.

        Returns:
            A list of command arguments ready for ``create_subprocess_exec``.
        """
        parts = shlex.split(raw_command)

        if not parts:
            return parts

        if parts[0].lower() == "bloodyad":
            # Inject connection and auth arguments after the binary name.
            # Use both --host (FQDN for Kerberos) and --dc-ip (IP for
            # connectivity), matching the wrapper's _build_command().
            connection_args = [
                "--host",
                self._config.domain.dc_fqdn or self._config.domain.dc_host,
                "-d",
                self._config.domain.name,
                "--dc-ip",
                self._config.domain.dc_host,
            ]

            auth_args = self._build_config_auth_args()

            # Reconstruct: bloodyAD [connection] [auth] [action args...]
            return [parts[0]] + connection_args + auth_args + parts[1:]

        return parts

    def _build_config_auth_args(self) -> list[str]:
        """Build authentication arguments from the static config for rollback."""
        cfg = self._config.credentials
        args: list[str] = ["-u", cfg.username]

        if cfg.ccache_path:
            args.extend(["-k", "--dc-ip", self._config.domain.dc_host])
        elif cfg.nt_hash:
            # bloodyAD uses -p for both passwords and NTLM hashes;
            # the :NTHASH format signals pass-the-hash authentication.
            args.extend(["-p", f":{cfg.nt_hash}"])
        elif cfg.password:
            args.extend(["-p", cfg.password])

        return args
