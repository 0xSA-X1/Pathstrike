"""JSON export for PathStrike attack results."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pathstrike.models import AttackPath, Credential, RollbackAction

logger = logging.getLogger("pathstrike.reporting")


class AttackReport:
    """Collects attack execution data for export."""

    def __init__(self, path: AttackPath, mode: str) -> None:
        self.path = path
        self.mode = mode
        self.started_at = datetime.now(timezone.utc)
        self.completed_at: datetime | None = None
        self.success = False
        self.step_results: list[dict[str, Any]] = []
        self.credentials_captured: list[dict[str, Any]] = []
        self.rollback_actions: list[dict[str, Any]] = []
        self.messages: list[dict[str, Any]] = []

    def record_step(
        self,
        index: int,
        edge_type: str,
        source: str,
        target: str,
        status: str,
        message: str,
        duration_seconds: float | None = None,
    ) -> None:
        """Record the result of a single step."""
        self.step_results.append({
            "index": index,
            "edge_type": edge_type,
            "source": source,
            "target": target,
            "status": status,
            "message": message,
            "duration_seconds": duration_seconds,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def record_credential(self, cred: Credential) -> None:
        """Record a captured credential."""
        self.credentials_captured.append({
            "type": cred.cred_type.value,
            "username": cred.username,
            "domain": cred.domain,
            "obtained_from": cred.obtained_from,
            "obtained_at": cred.obtained_at.isoformat() if cred.obtained_at else None,
            # NOTE: Never include the actual credential value in reports
            "value_preview": f"{cred.value[:4]}...{cred.value[-4:]}" if len(cred.value) > 8 else "***",
        })

    def record_rollback(self, action: RollbackAction) -> None:
        """Record a rollback action."""
        self.rollback_actions.append(action.model_dump(mode="json"))

    def add_message(self, message: str, level: str = "info") -> None:
        """Add a log message."""
        self.messages.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
        })

    def finalize(self, success: bool) -> None:
        """Mark the report as complete."""
        self.success = success
        self.completed_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serializable dictionary."""
        duration = None
        if self.completed_at and self.started_at:
            duration = (self.completed_at - self.started_at).total_seconds()

        return {
            "pathstrike_version": "0.1.0",
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "execution": {
                "mode": self.mode,
                "started_at": self.started_at.isoformat(),
                "completed_at": self.completed_at.isoformat() if self.completed_at else None,
                "duration_seconds": duration,
                "success": self.success,
            },
            "path": {
                "source": self.path.source.name,
                "target": self.path.target.name,
                "total_steps": self.path.total_cost,
            },
            "steps": self.step_results,
            "credentials_captured": self.credentials_captured,
            "rollback_actions": self.rollback_actions,
            "messages": self.messages,
        }

    def export_json(self, output_path: Path) -> None:
        """Write the report as JSON."""
        path = Path(output_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        logger.info("JSON report saved to %s", path)
