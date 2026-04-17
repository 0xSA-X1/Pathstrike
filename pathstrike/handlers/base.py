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

    def _get_certipy_auth_args(self, principal: str | None = None) -> list[str]:
        """Build certipy-compatible authentication arguments.

        Certipy uses a slightly different CLI surface than bloodyAD:
        ``-u user@domain``, ``-p password``, ``-hashes :NTHASH``, ``-k``
        for Kerberos, ``-dc-ip`` for explicit DC targeting.  This helper
        inspects the credential store for *principal* (or falls back to
        the configured credential) and returns ready-to-append args.
        """
        domain = self.config.domain.name
        user = principal or self.config.credentials.username
        dc_ip = self.config.domain.dc_host

        args: list[str] = ["-u", f"{user}@{domain}", "-dc-ip", dc_ip]

        cred = self.cred_store.get_best_credential(user, domain)
        if cred is not None:
            match cred.cred_type:
                case CredentialType.password:
                    args.extend(["-p", cred.value])
                case CredentialType.nt_hash:
                    args.extend(["-hashes", f":{cred.value}"])
                case CredentialType.aes_key:
                    args.extend(["-aes", cred.value])
                case CredentialType.ccache:
                    args.append("-k")
                case CredentialType.certificate:
                    args.extend(["-pfx", cred.value])
                case _:
                    pass  # fall through to config below
            if len(args) > 4:  # something beyond -u/-dc-ip was added
                return args

        # Fall back to initial config credentials
        cfg = self.config.credentials
        if cfg.ccache_path:
            args.append("-k")
        elif cfg.nt_hash:
            args.extend(["-hashes", f":{cfg.nt_hash}"])
        elif cfg.password:
            args.extend(["-p", cfg.password])
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
        """Determine who to authenticate as for this edge.

        For User/Computer source nodes, returns the sAMAccountName.
        For non-principal sources (GPO, Domain, OU, Container) the source
        is an object, not a user — fall back to the configured credential
        username since that user should already have control from a
        preceding step.
        """
        node = edge.source
        if node.label in {"User", "Computer"}:
            name = node.name
            return name.split("@")[0] if "@" in name else name
        # Non-user source: use the config credential (the user driving the chain)
        return self.config.credentials.username

    def _resolve_target(self, edge: EdgeInfo) -> str:
        """Resolve the target identity for use with AD tools.

        For Users, Groups, and Computers the sAMAccountName (the part
        before ``@``) works.  For other types we return a placeholder
        that :meth:`_resolve_target_dn` can replace with the real DN.
        """
        name = edge.target.name
        return name.split("@")[0] if "@" in name else name

    async def _resolve_target_dn(
        self, edge: EdgeInfo, auth_args: list[str]
    ) -> str | None:
        """For non-sAMAccountName objects (GPOs, OUs, …), resolve the DN via LDAP.

        Returns the Distinguished Name, or ``None`` if resolution fails.
        """
        from pathstrike.tools import bloodyad_wrapper as bloody

        node = edge.target
        display_name = node.name.split("@")[0] if "@" in node.name else node.name

        if node.label == "GPO":
            ldap_filter = f"(displayName={display_name})"
        elif node.label in ("OU", "Container"):
            ldap_filter = f"(name={display_name})"
        else:
            return None

        return await bloody.resolve_dn(self.config, auth_args, ldap_filter)

    def _target_needs_dn(self, edge: EdgeInfo) -> bool:
        """Return True if the target node type requires DN-based resolution."""
        return edge.target.label in {"GPO", "OU", "Container"}

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
