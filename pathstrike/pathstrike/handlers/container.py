"""OU containment handler for organizational unit traversal.

Handles the ``Contains`` BloodHound edge, which represents OU membership
(objects within an Organizational Unit).  This is primarily an
informational/traversal edge -- it indicates containment rather than a
direct exploitation opportunity.

The handler operates as a pass-through: it always succeeds and logs the
containment relationship for the orchestrator to use when building attack
paths through OU hierarchies.
"""

from __future__ import annotations

from pathstrike.engine.edge_registry import register_handler
from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.models import (
    Credential,
    EdgeInfo,
    RollbackAction,
)


@register_handler("Contains")
class ContainsHandler(BaseEdgeHandler):
    """Handle ``Contains`` edges representing OU membership.

    The ``Contains`` edge indicates that an AD object (user, computer,
    group, or nested OU) resides within a parent OU.  No exploitation
    is performed; the handler logs the relationship and passes through
    successfully so the orchestrator can continue along the attack path.
    """

    # ------------------------------------------------------------------
    # Prerequisites
    # ------------------------------------------------------------------

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        """Always passes -- Contains is an informational traversal edge.

        Args:
            edge: The ``Contains`` edge to evaluate.

        Returns:
            ``(True, message)`` -- always succeeds.
        """
        return (
            True,
            f"Contains: '{edge.source.name}' contains '{edge.target.name}' "
            f"(informational traversal edge).",
        )

    # ------------------------------------------------------------------
    # Exploitation
    # ------------------------------------------------------------------

    async def exploit(
        self,
        edge: EdgeInfo,
        dry_run: bool = False,
    ) -> tuple[bool, str, list[Credential]]:
        """Pass-through: log the containment relationship.

        No actual exploitation is needed for ``Contains`` edges.  The
        handler simply records that the target object is contained within
        the source OU and returns success.

        Args:
            edge: The ``Contains`` edge.
            dry_run: Irrelevant for pass-through edges.

        Returns:
            ``(True, message, [])`` -- always succeeds with no new credentials.
        """
        source = edge.source.name
        target = edge.target.name
        target_type = edge.target.label

        self.logger.info(
            "Contains pass-through: %s (%s) is contained within OU '%s'",
            target, target_type, source,
        )

        return (
            True,
            f"Contains: '{target}' ({target_type}) is a member of OU '{source}'. "
            "No exploitation required -- traversal edge.",
            [],
        )

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        """No rollback needed -- no changes made."""
        return None
