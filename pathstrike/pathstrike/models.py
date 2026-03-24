"""Pydantic v2 domain models for PathStrike."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, computed_field


class CredentialType(StrEnum):
    """Supported credential types for AD authentication."""

    password = "password"
    nt_hash = "nt_hash"
    aes_key = "aes_key"
    ccache = "ccache"
    certificate = "certificate"


class Credential(BaseModel):
    """A captured or provided credential for use in the attack chain."""

    cred_type: CredentialType
    value: str
    username: str
    domain: str
    obtained_from: str | None = None
    obtained_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NodeInfo(BaseModel):
    """BloodHound graph node representing an AD object."""

    object_id: str
    name: str
    label: str  # Node type: User, Group, Computer, Domain, GPO, OU, etc.
    domain: str
    properties: dict[str, Any] = Field(default_factory=dict)


class EdgeInfo(BaseModel):
    """BloodHound graph edge representing a relationship between AD objects."""

    edge_type: str
    source: NodeInfo
    target: NodeInfo
    properties: dict[str, Any] = Field(default_factory=dict)


class PathStep(BaseModel):
    """A single step in an attack path, linking an edge to its exploitation handler."""

    index: int
    edge: EdgeInfo
    handler_name: str | None = None
    status: str = "pending"
    result: str | None = None


class AttackPath(BaseModel):
    """An ordered sequence of steps from source node to target node."""

    steps: list[PathStep]
    source: NodeInfo
    target: NodeInfo

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_cost(self) -> int:
        """Cost is the number of exploitation steps required."""
        return len(self.steps)


class RollbackAction(BaseModel):
    """A reversible action recorded during exploitation for later cleanup."""

    step_index: int
    action_type: str
    description: str
    command: str
    reversible: bool = True
    executed: bool = False


class ExecutionMode(StrEnum):
    """Execution modes controlling user interaction during attack."""

    interactive = "interactive"
    auto = "auto"
    dry_run = "dry_run"
