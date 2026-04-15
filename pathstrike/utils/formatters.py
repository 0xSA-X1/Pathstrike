"""Output formatters for PathStrike CLI using Rich."""

import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.text import Text
from rich import box

from pathstrike.models import AttackPath, PathStep, EdgeInfo, Credential, CredentialType, RollbackAction

console = Console()

def format_attack_path(path: AttackPath, index: int = 0) -> Panel:
    """Format an attack path as a Rich panel with step table."""
    table = Table(
        title=f"Attack Path #{index + 1}",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold red",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Source", style="cyan")
    table.add_column("Edge", style="bold yellow")
    table.add_column("Target", style="green")
    table.add_column("Handler", style="magenta")
    table.add_column("Status", style="bold")

    for step in path.steps:
        status_style = {
            "pending": "[dim]⏳ pending[/dim]",
            "in_progress": "[yellow]⚡ running[/yellow]",
            "success": "[green]✅ success[/green]",
            "failed": "[red]❌ failed[/red]",
            "skipped": "[dim]⏭ skipped[/dim]",
            "dry_run": "[blue]🔍 dry-run[/blue]",
        }.get(step.status, step.status)

        table.add_row(
            str(step.index),
            step.edge.source.name,
            step.edge.edge_type,
            step.edge.target.name,
            step.handler_name or "[dim]none[/dim]",
            status_style,
        )

    return Panel(
        table,
        title=f"[bold]{path.source.name} → {path.target.name}[/bold]",
        subtitle=f"[dim]{path.total_cost} steps[/dim]",
        border_style="red",
    )

def format_paths_summary(paths: list[AttackPath]) -> None:
    """Print a summary of all discovered paths."""
    console.print(f"\n[bold green]📍 Discovered {len(paths)} attack path(s)[/bold green]\n")
    for i, path in enumerate(paths):
        console.print(format_attack_path(path, i))
        console.print()

def format_edge_table(handlers: dict[str, str]) -> Table:
    """Format supported edge types as a Rich table."""
    table = Table(
        title="Supported Edge Types",
        box=box.ROUNDED,
        show_lines=False,
        title_style="bold cyan",
    )
    table.add_column("Edge Type", style="yellow", min_width=25)
    table.add_column("Handler", style="magenta")

    for edge_type in sorted(handlers.keys()):
        table.add_row(edge_type, handlers[edge_type])

    return table

def format_credentials(creds: list[Credential]) -> Table:
    """Format collected credentials as a Rich table."""
    table = Table(
        title="Collected Credentials",
        box=box.ROUNDED,
        title_style="bold green",
    )
    table.add_column("Username", style="cyan")
    table.add_column("Domain", style="blue")
    table.add_column("Type", style="yellow")
    table.add_column("Value", style="dim")
    table.add_column("Obtained From", style="magenta")
    table.add_column("Time", style="dim")

    for cred in creds:
        # Mask sensitive values for display
        display_value = _mask_credential(cred)
        table.add_row(
            cred.username,
            cred.domain,
            cred.cred_type.value,
            display_value,
            cred.obtained_from or "initial",
            cred.obtained_at.strftime("%H:%M:%S"),
        )

    return table

def _mask_credential(cred: Credential) -> str:
    """Mask credential value for safe display."""
    if cred.cred_type == CredentialType.password:
        if len(cred.value) <= 4:
            return "****"
        return cred.value[:2] + "*" * (len(cred.value) - 4) + cred.value[-2:]
    elif cred.cred_type in (CredentialType.nt_hash, CredentialType.aes_key):
        return cred.value[:8] + "..." + cred.value[-8:]
    elif cred.cred_type == CredentialType.ccache:
        return f"[file] {cred.value}"
    elif cred.cred_type == CredentialType.certificate:
        return f"[cert] {cred.value}"
    return cred.value

def format_step_preview(step: PathStep, index: int) -> Panel:
    """Format a single step for interactive mode preview."""
    content = Text()
    content.append(f"Step {index + 1}: ", style="bold")
    content.append(f"{step.edge.source.name}", style="cyan")
    content.append(f" —[{step.edge.edge_type}]→ ", style="yellow")
    content.append(f"{step.edge.target.name}", style="green")
    content.append(f"\nHandler: ", style="dim")
    content.append(f"{step.handler_name or 'unknown'}", style="magenta")
    content.append(f"\nTarget Type: ", style="dim")
    content.append(f"{step.edge.target.label}", style="blue")

    return Panel(content, title="[bold yellow]Next Step[/bold yellow]", border_style="yellow")

def format_rollback_actions(actions: list[RollbackAction]) -> Table:
    """Format rollback actions as a Rich table."""
    table = Table(
        title="Rollback Actions (LIFO Order)",
        box=box.ROUNDED,
        title_style="bold yellow",
    )
    table.add_column("Step", style="dim", width=6)
    table.add_column("Type", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Reversible", style="green")
    table.add_column("Executed", style="yellow")

    for action in reversed(actions):
        table.add_row(
            str(action.step_index),
            action.action_type,
            action.description,
            "✅" if action.reversible else "❌",
            "✅" if action.executed else "⏳",
        )

    return table

def format_verification_result(name: str, available: bool, details: str = "") -> Text:
    """Format a tool verification result."""
    text = Text()
    icon = "✅" if available else "❌"
    style = "green" if available else "red"
    text.append(f"  {icon} ", style=style)
    text.append(f"{name:<20}", style="bold")
    if details:
        text.append(f" — {details}", style="dim")
    return text

def format_path_tree(path: AttackPath) -> Tree:
    """Format an attack path as a Rich tree visualization."""
    tree = Tree(
        f"[bold cyan]{path.source.name}[/bold cyan] [dim]({path.source.label})[/dim]",
        guide_style="dim",
    )

    current = tree
    for step in path.steps:
        branch = current.add(
            f"[yellow]—[{step.edge.edge_type}]→[/yellow] "
            f"[green]{step.edge.target.name}[/green] "
            f"[dim]({step.edge.target.label})[/dim]"
        )
        if step.handler_name:
            branch.add(f"[dim magenta]handler: {step.handler_name}[/dim magenta]")
        current = branch

    return tree

def export_json(paths: list[AttackPath], output_path: Path) -> None:
    """Export attack paths to JSON file."""
    data = {
        "generated_at": datetime.now().isoformat(),
        "path_count": len(paths),
        "paths": [p.model_dump(mode="json") for p in paths],
    }
    output_path.write_text(json.dumps(data, indent=2, default=str))
    console.print(f"[green]✅ Exported to {output_path}[/green]")

def format_timeline(path: AttackPath) -> Panel:
    """Format attack path as a timeline view."""
    lines: list[Text] = []
    for i, step in enumerate(path.steps):
        line = Text()
        # Timeline connector
        if i == 0:
            line.append("  ┌─ ", style="dim")
        elif i == len(path.steps) - 1:
            line.append("  └─ ", style="dim")
        else:
            line.append("  ├─ ", style="dim")

        # Step info
        line.append(f"[{step.edge.edge_type}]", style="bold yellow")
        line.append(f" {step.edge.source.name} → {step.edge.target.name}", style="white")

        if step.result:
            line.append(f" ({step.result})", style="dim")

        lines.append(line)

    group = Text("\n").join(lines)
    return Panel(
        group,
        title=f"[bold]Attack Timeline: {path.source.name} → {path.target.name}[/bold]",
        border_style="blue",
    )
