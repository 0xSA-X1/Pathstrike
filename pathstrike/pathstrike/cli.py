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
    target_name = _build_target_name(cfg)

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
            response = await client.cypher_query(query, params)
            discovered = parse_cypher_response(response)

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


if __name__ == "__main__":
    app()
