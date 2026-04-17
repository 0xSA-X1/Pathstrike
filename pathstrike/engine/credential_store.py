"""Credential management across the attack chain."""

from __future__ import annotations

import ctypes
import logging
import os
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

from pathstrike.models import Credential, CredentialType

logger = logging.getLogger("pathstrike")


class CredentialStore:
    """Credential store that tracks credentials obtained during exploitation.

    Credentials are keyed by ``username@domain`` (case-insensitive) and each key
    can hold multiple credential types. The store maintains insertion order so
    that :meth:`get_initial_credential` always returns the first credential added
    (typically the one provided in the configuration).
    """

    # Priority order: higher index = preferred.  ccache > certificate > nt_hash > aes_key > password
    PRIORITY: list[CredentialType] = [
        CredentialType.password,
        CredentialType.aes_key,
        CredentialType.nt_hash,
        CredentialType.certificate,
        CredentialType.ccache,
    ]

    # Default TTLs per credential type.  ``None`` means no expiration.
    DEFAULT_TTL: dict[CredentialType, timedelta | None] = {
        CredentialType.ccache: timedelta(hours=10),
        CredentialType.certificate: timedelta(days=365),
        CredentialType.password: None,
        CredentialType.nt_hash: None,
        CredentialType.aes_key: None,
    }

    # Per-tool credential priority (highest-priority first).
    TOOL_PRIORITY: dict[str, list[CredentialType]] = {
        "bloodyAD": [
            CredentialType.ccache,
            CredentialType.certificate,
            CredentialType.nt_hash,
            CredentialType.password,
        ],
        "impacket": [
            CredentialType.ccache,
            CredentialType.aes_key,
            CredentialType.nt_hash,
            CredentialType.password,
        ],
        "certipy": [
            CredentialType.certificate,
            CredentialType.ccache,
            CredentialType.password,
        ],
        "netexec": [
            CredentialType.ccache,
            CredentialType.nt_hash,
            CredentialType.password,
        ],
    }

    def __init__(self) -> None:
        # OrderedDict preserves insertion order for get_initial_credential
        self._credentials: OrderedDict[str, list[Credential]] = OrderedDict()

    @staticmethod
    def _key(username: str, domain: str) -> str:
        """Normalize the store key to lowercase ``user@domain``."""
        return f"{username.strip().lower()}@{domain.strip().lower()}"

    def add_credential(self, cred: Credential) -> None:
        """Add a credential to the store.

        Duplicate (same type + value for the same user) are silently ignored.

        Args:
            cred: The credential to store.
        """
        key = self._key(cred.username, cred.domain)

        if key not in self._credentials:
            self._credentials[key] = []

        # Avoid exact duplicates
        for existing in self._credentials[key]:
            if existing.cred_type == cred.cred_type and existing.value == cred.value:
                logger.debug(
                    "Duplicate credential skipped: %s/%s for %s",
                    cred.cred_type,
                    cred.username,
                    cred.domain,
                )
                return

        self._credentials[key].append(cred)
        logger.info(
            "Stored %s credential for %s@%s (source: %s)",
            cred.cred_type.value,
            cred.username,
            cred.domain,
            cred.obtained_from or "initial",
        )

    # ------------------------------------------------------------------
    # Expiration helpers
    # ------------------------------------------------------------------

    @classmethod
    def is_expired(cls, cred: Credential) -> bool:
        """Check whether a credential has exceeded its TTL based on ``obtained_at``.

        Credential types with no TTL (password, nt_hash, aes_key) never expire.

        Args:
            cred: The credential to check.

        Returns:
            ``True`` if the credential is expired, ``False`` otherwise.
        """
        ttl = cls.DEFAULT_TTL.get(cred.cred_type)
        if ttl is None:
            return False
        expires_at = cred.obtained_at + ttl
        return datetime.now(timezone.utc) >= expires_at

    # ------------------------------------------------------------------
    # Credential selection
    # ------------------------------------------------------------------

    def get_best_credential(self, username: str, domain: str) -> Credential | None:
        """Return the highest-priority **non-expired** credential for an identity.

        Priority order (highest to lowest):
            ccache > certificate > nt_hash > aes_key > password

        Expired credentials are filtered out and a warning is logged for each.

        Args:
            username: Target username.
            domain: Target domain.

        Returns:
            The best credential available, or None if none exist.
        """
        creds = self.get_credentials_for(username, domain)
        if not creds:
            return None

        # Filter out expired credentials
        valid_creds: list[Credential] = []
        for cred in creds:
            if self.is_expired(cred):
                logger.warning(
                    "Skipping expired %s credential for %s@%s (obtained %s)",
                    cred.cred_type.value,
                    cred.username,
                    cred.domain,
                    cred.obtained_at.isoformat(),
                )
            else:
                valid_creds.append(cred)

        if not valid_creds:
            return None

        # Build a lookup of cred_type -> priority index
        priority_map = {ct: idx for idx, ct in enumerate(self.PRIORITY)}

        return max(valid_creds, key=lambda c: priority_map.get(c.cred_type, -1))

    def get_best_credential_for_tool(
        self, username: str, domain: str, tool: str
    ) -> Credential | None:
        """Return the best **non-expired** credential for a specific tool.

        Each tool has its own preferred priority order reflecting which
        credential types it natively supports.

        If the *tool* is not recognised, falls back to the generic
        :meth:`get_best_credential` priority.

        Args:
            username: Target username.
            domain: Target domain.
            tool: Tool name (e.g. ``"bloodyAD"``, ``"impacket"``, ``"certipy"``,
                  ``"netexec"``).  Matching is case-insensitive.

        Returns:
            The best credential for the tool, or ``None``.
        """
        # Resolve tool priority list (case-insensitive lookup)
        tool_key = next(
            (k for k in self.TOOL_PRIORITY if k.lower() == tool.lower()),
            None,
        )
        tool_prio = self.TOOL_PRIORITY.get(tool_key) if tool_key else None  # type: ignore[arg-type]

        if tool_prio is None:
            logger.debug(
                "No tool-specific priority for '%s'; using default priority", tool
            )
            return self.get_best_credential(username, domain)

        creds = self.get_credentials_for(username, domain)
        if not creds:
            return None

        # Filter out expired and non-supported types
        valid_creds: list[Credential] = []
        supported_types = set(tool_prio)
        for cred in creds:
            if self.is_expired(cred):
                logger.warning(
                    "Skipping expired %s credential for %s@%s (tool=%s)",
                    cred.cred_type.value,
                    cred.username,
                    cred.domain,
                    tool,
                )
                continue
            if cred.cred_type not in supported_types:
                logger.debug(
                    "Credential type %s not supported by %s; skipping",
                    cred.cred_type.value,
                    tool,
                )
                continue
            valid_creds.append(cred)

        if not valid_creds:
            return None

        # Higher index in tool_prio = lower priority (list is best-first),
        # so we want the MINIMUM index.
        prio_map = {ct: idx for idx, ct in enumerate(tool_prio)}
        return min(valid_creds, key=lambda c: prio_map.get(c.cred_type, len(tool_prio)))

    # ------------------------------------------------------------------
    # Auto-refresh helpers
    # ------------------------------------------------------------------

    def get_refreshable_credentials(self) -> list[Credential]:
        """Return credentials that are within 10% of their TTL remaining.

        These credentials are approaching expiration and should be refreshed
        proactively by the orchestrator (e.g. re-requesting a TGT).

        Credential types with no TTL are never returned.

        Returns:
            List of credentials nearing expiration.
        """
        now = datetime.now(timezone.utc)
        approaching: list[Credential] = []

        for cred_list in self._credentials.values():
            for cred in cred_list:
                ttl = self.DEFAULT_TTL.get(cred.cred_type)
                if ttl is None:
                    continue

                expires_at = cred.obtained_at + ttl
                remaining = (expires_at - now).total_seconds()
                threshold = ttl.total_seconds() * 0.10

                if 0 < remaining <= threshold:
                    approaching.append(cred)

        return approaching

    # ------------------------------------------------------------------
    # Credential retrieval (existing)
    # ------------------------------------------------------------------

    def get_credentials_for(self, username: str, domain: str) -> list[Credential]:
        """Return all credentials stored for a given identity.

        Args:
            username: Target username.
            domain: Target domain.

        Returns:
            List of credentials (may be empty).
        """
        key = self._key(username, domain)
        return list(self._credentials.get(key, []))

    def get_initial_credential(self) -> Credential | None:
        """Return the very first credential that was added to the store.

        This is typically the credential from the configuration file used to
        start the attack chain.

        Returns:
            The first credential, or None if the store is empty.
        """
        for cred_list in self._credentials.values():
            if cred_list:
                return cred_list[0]
        return None

    def all_credentials(self) -> list[Credential]:
        """Return a flat list of every credential in the store.

        Returns:
            All stored credentials in insertion order.
        """
        return [
            cred
            for cred_list in self._credentials.values()
            for cred in cred_list
        ]

    # ------------------------------------------------------------------
    # Secure wipe
    # ------------------------------------------------------------------

    def secure_wipe(self) -> None:
        """Overwrite credential values in memory and clear all data structures.

        Best-effort approach:
        1. For each credential, overwrite the ``value`` field's underlying
           bytes in memory with random data (via ``ctypes`` if available).
        2. Replace each credential's ``value`` attribute with an empty string.
        3. Clear internal collections.
        """
        wiped_count = 0

        for cred_list in self._credentials.values():
            for cred in cred_list:
                self._overwrite_string(cred.value)
                # Pydantic v2 models are mutable by default (model_config
                # doesn't freeze).  Replace the value with an empty string.
                try:
                    cred.value = ""
                except Exception:
                    pass
                wiped_count += 1

        self._credentials.clear()
        logger.debug("Secure wipe completed: %d credential(s) overwritten", wiped_count)

    @staticmethod
    def _overwrite_string(s: str) -> None:
        """Best-effort overwrite of a Python string's internal buffer.

        CPython stores string data in a C-level buffer.  We attempt to write
        random bytes over it using ``ctypes``.  This is NOT guaranteed across
        all Python implementations but provides defence-in-depth on CPython.
        """
        if not s:
            return
        try:
            # CPython compact ASCII/latin-1 strings store data right after
            # the PyUnicodeObject header.  id(s) gives the object address.
            # We compute the data offset as the size of the object minus the
            # string length (each ASCII char = 1 byte + null terminator).
            buf_size = len(s)
            # Write random bytes over the string buffer.  The exact offset
            # depends on the CPython version; using the documented
            # PyUnicode_DATA macro offset is fragile, so we simply use
            # ctypes.memset on the address of the buffer content obtained via
            # ctypes.  For safety, wrap in a try/except.
            addr = id(s)
            # Compact ASCII: data starts at offset sys.getsizeof(s) - len(s) - 1
            import sys

            data_offset = sys.getsizeof(s) - buf_size - 1
            if data_offset > 0:
                ctypes.memset(addr + data_offset, 0, buf_size)
                # Overwrite with random bytes for extra paranoia
                random_bytes = os.urandom(buf_size)
                ctypes.memmove(addr + data_offset, random_bytes, buf_size)
        except Exception:
            # Silently fail — this is a best-effort hardening measure
            pass

    def __del__(self) -> None:
        """Safety net: wipe credentials when the store is garbage collected."""
        try:
            self.secure_wipe()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return sum(len(v) for v in self._credentials.values())

    def __repr__(self) -> str:
        total = len(self)
        identities = len(self._credentials)
        return f"<CredentialStore identities={identities} credentials={total}>"
