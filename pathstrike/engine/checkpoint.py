"""Attack path checkpoint and resume system.

Saves progress after each successful step so that failed attack paths
can be resumed from the last successful step instead of starting over.

Checkpoints are stored as JSON files in ``~/.pathstrike/checkpoints/``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pathstrike.models import AttackPath, Credential, PathStep

logger = logging.getLogger("pathstrike.engine.checkpoint")

CHECKPOINT_DIR = Path("~/.pathstrike/checkpoints").expanduser()


class CheckpointManager:
    """Manages attack path checkpoints for resume capability."""

    def __init__(self, checkpoint_dir: Path | None = None) -> None:
        self._dir = (checkpoint_dir or CHECKPOINT_DIR).expanduser().resolve()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._current_path: str | None = None
        self._current_file: Path | None = None

    def start_path(self, path: AttackPath) -> Path:
        """Initialize a new checkpoint for an attack path.

        Creates a checkpoint file with the path metadata and empty step results.
        Returns the checkpoint file path.
        """
        # Generate a path key from source->target
        path_key = f"{path.source.name}_to_{path.target.name}".replace("@", "_at_").replace(".", "_")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{path_key}_{timestamp}.json"
        self._current_file = self._dir / filename
        self._current_path = path_key

        checkpoint = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "source": path.source.model_dump(mode="json"),
            "target": path.target.model_dump(mode="json"),
            "total_steps": path.total_cost,
            "completed_steps": 0,
            "last_completed_index": -1,
            "status": "in_progress",
            "steps": [],
            "credentials_captured": [],
        }

        self._write(checkpoint)
        logger.info("Checkpoint created: %s", self._current_file)
        return self._current_file

    def record_step_success(
        self,
        step: PathStep,
        credentials: list[Credential] | None = None,
    ) -> None:
        """Record a successfully completed step."""
        if not self._current_file:
            return

        checkpoint = self._read()
        if checkpoint is None:
            return

        step_data = {
            "index": step.index,
            "edge_type": step.edge.edge_type,
            "source": step.edge.source.name,
            "target": step.edge.target.name,
            "status": "completed",
            "result": step.result,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

        checkpoint["steps"].append(step_data)
        checkpoint["completed_steps"] = len(checkpoint["steps"])
        checkpoint["last_completed_index"] = step.index
        checkpoint["updated_at"] = datetime.now(timezone.utc).isoformat()

        if credentials:
            for cred in credentials:
                checkpoint["credentials_captured"].append(cred.model_dump(mode="json"))

        self._write(checkpoint)
        logger.debug("Checkpoint updated: step %d completed", step.index)

    def record_step_failure(self, step: PathStep, error: str) -> None:
        """Record a failed step."""
        if not self._current_file:
            return

        checkpoint = self._read()
        if checkpoint is None:
            return

        step_data = {
            "index": step.index,
            "edge_type": step.edge.edge_type,
            "source": step.edge.source.name,
            "target": step.edge.target.name,
            "status": "failed",
            "error": error,
            "failed_at": datetime.now(timezone.utc).isoformat(),
        }

        checkpoint["steps"].append(step_data)
        checkpoint["status"] = "failed"
        checkpoint["updated_at"] = datetime.now(timezone.utc).isoformat()

        self._write(checkpoint)
        logger.info("Checkpoint updated: step %d failed", step.index)

    def mark_complete(self) -> None:
        """Mark the current checkpoint as completed."""
        if not self._current_file:
            return
        checkpoint = self._read()
        if checkpoint:
            checkpoint["status"] = "completed"
            checkpoint["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._write(checkpoint)

    @staticmethod
    def find_latest_checkpoint(source: str, target: str, checkpoint_dir: Path | None = None) -> Path | None:
        """Find the most recent incomplete checkpoint for a source->target path.

        Returns the checkpoint file path or None if no resumable checkpoint exists.
        """
        search_dir = (checkpoint_dir or CHECKPOINT_DIR).expanduser().resolve()
        if not search_dir.exists():
            return None

        path_key = f"{source}_to_{target}".replace("@", "_at_").replace(".", "_")
        candidates = sorted(search_dir.glob(f"{path_key}_*.json"), reverse=True)

        for candidate in candidates:
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
                if data.get("status") == "failed":
                    return candidate
            except (json.JSONDecodeError, OSError):
                continue
        return None

    @staticmethod
    def load_checkpoint(path: Path) -> dict[str, Any]:
        """Load a checkpoint file and return its data."""
        data = json.loads(path.read_text(encoding="utf-8"))
        return data

    def get_resume_index(self, checkpoint_data: dict[str, Any]) -> int:
        """Get the step index to resume from (the one after the last success)."""
        return checkpoint_data.get("last_completed_index", -1) + 1

    def list_checkpoints(self) -> list[dict[str, Any]]:
        """List all checkpoints with summary info."""
        results = []
        for f in sorted(self._dir.glob("*.json"), reverse=True):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                results.append({
                    "file": str(f),
                    "source": data.get("source", {}).get("name", "?"),
                    "target": data.get("target", {}).get("name", "?"),
                    "status": data.get("status", "?"),
                    "completed_steps": data.get("completed_steps", 0),
                    "total_steps": data.get("total_steps", 0),
                    "updated_at": data.get("updated_at", "?"),
                })
            except (json.JSONDecodeError, OSError):
                continue
        return results

    def cleanup_expired(self, max_age_hours: int = 72) -> int:
        """Remove checkpoint files older than the specified age.

        Args:
            max_age_hours: Maximum age in hours before a checkpoint is
                considered expired and eligible for cleanup.

        Returns:
            Number of checkpoint files removed.
        """
        removed = 0
        cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        checkpoint_dir = self._dir

        if not checkpoint_dir.exists():
            return removed

        for cp_file in checkpoint_dir.glob("checkpoint_*.json"):
            try:
                with open(cp_file, "r") as fh:
                    data = json.load(fh)
                updated = data.get("updated_at", data.get("started_at", ""))
                if updated:
                    cp_time = datetime.fromisoformat(updated)
                    if cp_time < cutoff:
                        cp_file.unlink()
                        removed += 1
                        logger.info("Removed expired checkpoint: %s", cp_file.name)
            except (json.JSONDecodeError, ValueError, OSError) as exc:
                logger.warning("Could not process checkpoint %s: %s", cp_file.name, exc)

        if removed:
            logger.info("Cleaned up %d expired checkpoint(s)", removed)
        return removed

    def _read(self) -> dict[str, Any] | None:
        if not self._current_file or not self._current_file.exists():
            return None
        try:
            return json.loads(self._current_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def _write(self, data: dict[str, Any]) -> None:
        if self._current_file:
            self._current_file.write_text(
                json.dumps(data, indent=2, default=str),
                encoding="utf-8",
            )
