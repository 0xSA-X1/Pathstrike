"""Abstract base class for all BloodHound edge exploitation handlers.

Every concrete handler must subclass :class:`BaseEdgeHandler` and implement:

* :meth:`check_prerequisites` -- verify the edge can be exploited.
* :meth:`exploit` -- perform (or simulate) the exploitation.
* :meth:`get_rollback_action` -- describe how to undo the exploit, if possible.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from pathstrike.config import PathStrikeConfig
from pathstrike.engine.credential_store import CredentialStore
from pathstrike.models import (
    Credential,
    CredentialType,
    EdgeInfo,
    RollbackAction,
)


class BaseEdgeHandler(ABC):
    """Base class every edge handler must inherit from.

    Handlers are instantiated by the orchestrator with the active config
    and credential store, then invoked for a specific :class:`EdgeInfo`.
    """

    def __init__(
        self,
        config: PathStrikeConfig,
        credential_store: CredentialStore,
    ) -> None:
        self.config = config
        self.cred_store = credential_store
        self.logger = logging.getLogger(
            f"pathstrike.handlers.{self.__class__.__name__}"
        )

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        """Validate that all prerequisites are met before exploitation.

        Returns:
            A ``(ok, message)`` tuple.  *ok* is ``True`` when the handler
            believes exploitation will succeed; *message* provides context.
        """
        ...

    @abstractmethod
    async def exploit(
        self,
        edge: EdgeInfo,
        dry_run: bool = False,
    ) -> tuple[bool, str, list[Credential]]:
        """Execute the exploitation logic for this edge.

        Args:
            edge: The BloodHound edge to exploit.
            dry_run: If ``True``, log what would happen but take no action.

        Returns:
            ``(success, message, new_credentials)`` -- any credentials
            harvested during exploitation are returned in the list.
        """
        ...

    @abstractmethod
    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        """Return a :class:`RollbackAction` describing how to undo the exploit.

        Handlers that perform non-destructive / read-only operations may
        return ``None``.
        """
        ...

    # ------------------------------------------------------------------
    # Authentication helpers (bloodyAD style)
    # ------------------------------------------------------------------

    def _get_auth_args(self, principal: str | None = None) -> list[str]:
        """Build bloodyAD-compatible authentication arguments.

        Looks up the best available credential for *principal* (or the
        initial configured credential) and returns CLI fragments such as
        ``["-u", "jdoe", "-p", "P@ss"]`` or
        ``["-u", "jdoe", "-p", ":abc..."]`` (NTLM hash via ``-p``) or
        ``["-u", "jdoe", "-k"]`` for Kerberos ccache.

        Args:
            principal: ``sAMAccountName`` to authenticate as.  Falls back to
                ``config.credentials.username`` when ``None``.

        Returns:
            A list of string arguments suitable for extending a command list.
        """
        domain = self.config.domain.name
        user = principal or self.config.credentials.username

        # Try credential store first
        cred = self.cred_store.get_best_credential(user, domain)

        if cred is not None:
            return self._auth_args_from_credential(cred)

        # Fall back to initial config credentials
        return self._auth_args_from_config(user)

    def _auth_args_from_credential(self, cred: Credential) -> list[str]:
        """Convert a :class:`Credential` to bloodyAD CLI arguments."""
        args: list[str] = ["-u", cred.username]

        match cred.cred_type:
            case CredentialType.password:
                args.extend(["-p", cred.value])

            case CredentialType.nt_hash:
                # bloodyAD uses -p for both passwords and NTLM hashes;
                # the :NTHASH format signals pass-the-hash authentication.
                args.extend(["-p", f":{cred.value}"])

            case CredentialType.aes_key:
                # bloodyAD Kerberos mode — requires TGT to be pre-acquired
                # and KRB5CCNAME set in the environment.
                args.extend(["-k", "--dc-ip", self.config.domain.dc_host])

            case CredentialType.ccache:
                # Kerberos ticket cache — bloodyAD uses ``-k`` plus
                # KRB5CCNAME environment variable.
                args.extend(["-k", "--dc-ip", self.config.domain.dc_host])

            case CredentialType.certificate:
                # Certificate-based auth (PKINIT / Schannel).
                # bloodyAD uses ``-c`` / ``--certificate`` for PFX/PEM paths.
                args.extend(["-c", cred.value])

            case _:
                self.logger.warning(
                    "Unknown credential type %s; falling back to config",
                    cred.cred_type,
                )
                return self._auth_args_from_config(cred.username)

        return args

    def _auth_args_from_config(self, username: str | None = None) -> list[str]:
        """Build auth args from the static YAML configuration."""
        cfg = self.config.credentials
        user = username or cfg.username
        args: list[str] = ["-u", user]

        if cfg.ccache_path:
            args.extend(["-k", "--dc-ip", self.config.domain.dc_host])
            return args

        if cfg.nt_hash:
            args.extend(["-p", f":{cfg.nt_hash}"])
            return args

        if cfg.password:
            args.extend(["-p", cfg.password])
            return args

        self.logger.warning(
            "No usable credential for %s; auth args may be incomplete", user
        )
        return args

    # ------------------------------------------------------------------
    # Impacket authentication helpers
    # ------------------------------------------------------------------

    def _get_impacket_auth(
        self, principal: str | None = None
    ) -> tuple[str, list[str]]:
        """Build Impacket-style authentication components.

        Returns:
            ``(target_string, auth_flags)`` — *target_string* is the
            ``DOMAIN/user:password`` portion; *auth_flags* are additional
            CLI flags like ``-hashes``, ``-k``, ``-aesKey``, etc.
        """
        from pathstrike.tools.impacket_wrapper import (
            build_impacket_auth,
            build_target_string,
        )

        domain = self.config.domain.name
        user = principal or self.config.credentials.username
        dc_ip = self.config.domain.dc_host

        cred = self.cred_store.get_best_credential(user, domain)

        if cred is not None:
            password = cred.value if cred.cred_type == CredentialType.password else None
            nt_hash = cred.value if cred.cred_type == CredentialType.nt_hash else None
            aes_key = cred.value if cred.cred_type == CredentialType.aes_key else None
            ccache = cred.value if cred.cred_type == CredentialType.ccache else None

            target_str = build_target_string(domain, user, password, nt_hash)
            auth_flags = build_impacket_auth(
                domain, user, password, nt_hash, aes_key, ccache, dc_ip
            )
            return target_str, auth_flags

        # Fall back to config
        cfg = self.config.credentials
        target_str = build_target_string(domain, user, cfg.password, cfg.nt_hash)
        auth_flags = build_impacket_auth(
            domain,
            user,
            cfg.password,
            cfg.nt_hash,
            None,
            cfg.ccache_path,
            dc_ip,
        )
        return target_str, auth_flags

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _resolve_principal(self, edge: EdgeInfo) -> str:
        """Extract the sAMAccountName from the source node.

        Strips the ``@domain`` suffix if present (BloodHound stores
        ``user@DOMAIN.LOCAL`` in the *name* field).
        """
        name = edge.source.name
        return name.split("@")[0] if "@" in name else name

    def _resolve_target(self, edge: EdgeInfo) -> str:
        """Resolve the target identity for use with AD tools.

        For Users, Groups, and Computers the sAMAccountName (the part
        before ``@``) works.  For GPOs bloodyAD cannot look up by
        sAMAccountName, so we build the Distinguished Name from the
        GUID (``CN={GUID},CN=Policies,CN=System,DC=...``).  For OUs,
        Containers, and Domains we also build an appropriate DN.
        """
        node = edge.target
        sam_types = {"User", "Group", "Computer"}
        if node.label in sam_types:
            name = node.name
            return name.split("@")[0] if "@" in name else name

        # Build domain DN components from the node's domain field.
        domain = node.domain or self.config.domain.name
        domain_dn = ",".join(f"DC={part}" for part in domain.split("."))

        if node.label == "GPO":
            # GPO DN: CN={GUID},CN=Policies,CN=System,DC=...
            guid = node.object_id
            return f"CN={{{guid}}},CN=Policies,CN=System,{domain_dn}"

        if node.label == "OU":
            # OU name is e.g. "SERVERS@DOMAIN.LOCAL" -> OU=SERVERS,...
            ou_name = node.name.split("@")[0] if "@" in node.name else node.name
            return f"OU={ou_name},{domain_dn}"

        if node.label == "Container":
            cn_name = node.name.split("@")[0] if "@" in node.name else node.name
            return f"CN={cn_name},{domain_dn}"

        if node.label == "Domain":
            return domain_dn

        # Fallback: try sAMAccountName style
        name = node.name
        return name.split("@")[0] if "@" in name else name

    # Aliases for compatibility with linter-generated names
    _source_username = _resolve_principal
    _target_username = _resolve_target

    def _get_dc_host(self) -> str:
        """Return the domain controller host from config."""
        return self.config.domain.dc_host

    def _get_domain(self) -> str:
        """Return the domain name from config."""
        return self.config.domain.name

    def _domain_dn(self) -> str:
        """Convert the domain name to an LDAP distinguished name.

        ``corp.local`` -> ``DC=corp,DC=local``
        """
        parts = self.config.domain.name.split(".")
        return ",".join(f"DC={p}" for p in parts)
