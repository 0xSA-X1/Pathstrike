"""Typer CLI application for PathStrike."""

from __future__ import annotations

import asyncio
import atexit
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from pathstrike.bloodhound.client import BloodHoundClient
from pathstrike.config import PathStrikeConfig, find_config, load_config
from pathstrike.engine.checkpoint import CheckpointManager
from pathstrike.engine.credential_store import CredentialStore
from pathstrike.engine.edge_registry import get_supported_edges, list_handlers
from pathstrike.engine.error_handler import RetryPolicy
from pathstrike.engine.rollback import RollbackManager
from pathstrike.logging_setup import print_log_summary, setup_logging
from pathstrike.models import Credential, CredentialType, ExecutionMode

# Importing the handlers package runs every @register_handler decorator,
# populating the edge registry.  Done at CLI import time so that read-only
# commands like `pathstrike edges` see the full registry without first
# having to load the orchestrator/campaign modules.
import pathstrike.handlers  # noqa: F401, E402

app = typer.Typer(
    name="pathstrike",
    help="AD Attack Path Automation via BloodHound CE",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()

# Print a single end-of-run hint (if any warnings/errors were logged) when
# the process exits, regardless of which subcommand ran or how it exited
# (normal return, typer.Exit, or KeyboardInterrupt).  The handler is a no-op
# when no warnings were recorded or when setup_logging wasn't called.
atexit.register(lambda: print_log_summary(console))

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


# ---------------------------------------------------------------------------
# Rollback log auto-save
# ---------------------------------------------------------------------------

ROLLBACK_LOG_DIR = Path("rollback_logs")


def _save_rollback_log(rollback_mgr: RollbackManager, label: str) -> Path | None:
    """Save rollback actions to a timestamped JSON file if any exist.

    Returns the path to the saved file, or ``None`` if there were no actions.
    """
    if len(rollback_mgr) == 0:
        return None

    ROLLBACK_LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"rollback_{label}_{ts}.json"
    log_path = ROLLBACK_LOG_DIR / filename
    rollback_mgr.save_to_file(log_path)
    console.print(
        f"\n[bold cyan]Rollback log saved:[/] {log_path}\n"
        f"[dim]Run 'pathstrike rollback {log_path}' to undo changes.[/]"
    )
    return log_path


def _find_latest_rollback_log() -> Path | None:
    """Find the most recent rollback log file in the rollback_logs directory."""
    if not ROLLBACK_LOG_DIR.exists():
        return None
    logs = sorted(ROLLBACK_LOG_DIR.glob("rollback_*.json"), key=lambda p: p.stat().st_mtime)
    return logs[-1] if logs else None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

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
        "faketime (skew fallback)": "faketime",
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
        Optional[Path],
        typer.Argument(
            help="Path to the rollback JSON log file. If omitted, uses the most recent log from rollback_logs/.",
        ),
    ] = None,
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

    If no LOG_FILE is given, the most recent log from ``rollback_logs/``
    is used automatically.

    Use ``--dry-run`` to preview what commands would be executed.
    Use ``--force`` to continue even if individual rollback actions fail.
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    # Resolve log file: explicit argument or auto-discover latest
    if log_file is None:
        log_file = _find_latest_rollback_log()
        if log_file is None:
            console.print(
                "[bold red]No rollback log specified and no logs found in "
                "rollback_logs/.[/]\n"
                "[dim]Run an attack first, or pass a log file explicitly: "
                "pathstrike rollback <log_file>[/]"
            )
            raise typer.Exit(code=1)
        console.print(f"[dim]Using latest rollback log:[/] {log_file}\n")
    elif not log_file.exists():
        console.print(f"[bold red]Rollback log not found:[/] {log_file}")
        raise typer.Exit(code=1)

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
def auto(
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
        typer.Option("--max-targets", help="Max reachable targets to pursue per round"),
    ] = 10,
    max_depth: Annotated[
        int,
        typer.Option("--max-depth", help="Maximum path depth when enumerating reachable targets"),
    ] = 10,
    no_time_sync: Annotated[
        bool,
        typer.Option("--no-time-sync", help="Disable automatic ntpdate clock sync"),
    ] = False,
    verbose: VerboseOption = False,
) -> None:
    """Greedy reachable-targets exploitation — escalate as far as possible.

    Enumerates every exploitable node reachable from the source (users,
    groups, computers, domains) via handler-backed edges, [bold]without[/]
    restricting to high-value principals.  This lets PathStrike pivot
    through intermediate targets — e.g. a non-admin group that has
    GenericWrite over a service account, which in turn owns the DC.

    After each successful escalation, re-queries from the new identity
    to discover additional reachable nodes, chaining opportunistically
    until nothing new is exploitable.

    Use [bold]pathstrike campaign[/] instead when you specifically want
    to drive toward Domain Admin / Enterprise Admin / Tier Zero.
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
        f"[bold]Auto Mode (reachable-targets):[/] {mode.value}\n"
        f"[bold]Source:[/] {source_name}\n"
        f"[bold]Max targets per round:[/] {max_targets}\n"
        f"[bold]Max path depth:[/] {max_depth}\n"
        f"[bold]Max retries:[/] {retry_policy.max_retries}\n"
        f"[bold]Auto time sync:[/] {'disabled' if no_time_sync else 'enabled'}\n"
    )

    async def _run():
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            cred_store = _seed_credential_store(cfg)
            rollback_mgr = RollbackManager(cfg)

            from pathstrike.engine.campaign import CampaignOrchestrator

            auto_orch = CampaignOrchestrator(
                config=cfg,
                bh_client=client,
                cred_store=cred_store,
                rollback_mgr=rollback_mgr,
                retry_policy=retry_policy,
                mode=mode,
                verbose=verbose,
                max_targets=max_targets,
                reachable_mode=True,
                max_depth=max_depth,
            )

            result = await auto_orch.run_campaign()
            _save_rollback_log(rollback_mgr, "auto")

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
        typer.Option("--max-targets", help="Max targets to pursue per round"),
    ] = 10,
    max_depth: Annotated[
        int,
        typer.Option("--max-depth", help="Maximum path depth when enumerating reachable targets"),
    ] = 10,
    high_value_only: Annotated[
        bool,
        typer.Option(
            "--high-value-only",
            help="Restrict discovery to Domain Admins / Enterprise Admins / Tier Zero / Domain nodes (old behavior)",
        ),
    ] = False,
    no_time_sync: Annotated[
        bool,
        typer.Option("--no-time-sync", help="Disable automatic ntpdate clock sync"),
    ] = False,
    verbose: VerboseOption = False,
) -> None:
    """Interactive step-through attack campaign — exploit, requery, repeat.

    Enumerates every reachable exploitable node from your owned
    identities (users, groups, computers, domains) via handler-backed
    edges.  After each successful step, re-queries BH CE from the new
    position to surface additional paths — letting you step through
    an environment one compromise at a time.

    [bold yellow]Note:[/] BH CE is a static snapshot. If exploiting a
    step changes AD state (e.g. WriteOwner grants new ACLs), you must
    [bold]re-collect and re-upload[/] bloodhound-ce-python data between
    steps to see the newly-created edges in subsequent queries.

    Use [bold]--high-value-only[/] to restrict discovery to privileged
    targets (Domain Admins, Enterprise Admins, Tier Zero, Domain nodes)
    when you specifically want to drive toward final DA compromise.

    Use [bold]pathstrike auto[/] for greedy non-interactive escalation
    that chases the deepest reachable target without prompting.

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

    discovery_desc = "high-value targets only" if high_value_only else "all reachable targets"
    console.print(
        f"[bold]Campaign Mode:[/] {mode.value}\n"
        f"[bold]Source:[/] {source_name}\n"
        f"[bold]Discovery:[/] {discovery_desc}\n"
        f"[bold]Max targets per round:[/] {max_targets}\n"
        f"[bold]Max path depth:[/] {max_depth}\n"
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
                reachable_mode=not high_value_only,
                max_depth=max_depth,
            )

            result = await campaign_orch.run_campaign()
            _save_rollback_log(rollback_mgr, "campaign")

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
