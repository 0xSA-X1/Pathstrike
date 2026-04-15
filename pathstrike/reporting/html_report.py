"""Self-contained HTML report generator for PathStrike attack results.

Generates a single HTML file with inline CSS styling (dark theme).
No external dependencies such as Jinja2 are required.
"""

from __future__ import annotations

import html
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("pathstrike.reporting")

# ---------------------------------------------------------------------------
# CSS / Template constants
# ---------------------------------------------------------------------------

_CSS = """\
:root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --text-muted: #484f58;
    --border: #30363d;
    --accent-green: #3fb950;
    --accent-red: #f85149;
    --accent-yellow: #d29922;
    --accent-blue: #58a6ff;
    --accent-purple: #bc8cff;
    --accent-cyan: #39d2c0;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2rem;
}

.container { max-width: 1100px; margin: 0 auto; }

h1 {
    font-size: 1.8rem;
    margin-bottom: 0.5rem;
    color: var(--accent-cyan);
}

h2 {
    font-size: 1.3rem;
    margin: 2rem 0 1rem;
    color: var(--accent-blue);
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.4rem;
}

.subtitle {
    color: var(--text-secondary);
    font-size: 0.9rem;
    margin-bottom: 2rem;
}

/* Summary cards */
.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}

.card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem;
}

.card-label {
    font-size: 0.8rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.card-value {
    font-size: 1.5rem;
    font-weight: 600;
    margin-top: 0.3rem;
}

.card-value.success { color: var(--accent-green); }
.card-value.failure { color: var(--accent-red); }
.card-value.neutral { color: var(--text-primary); }

/* Tables */
table {
    width: 100%;
    border-collapse: collapse;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    margin-bottom: 1.5rem;
}

th {
    background: var(--bg-tertiary);
    text-align: left;
    padding: 0.75rem 1rem;
    font-size: 0.85rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    border-bottom: 1px solid var(--border);
}

td {
    padding: 0.65rem 1rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.9rem;
}

tr:last-child td { border-bottom: none; }
tr:hover { background: var(--bg-tertiary); }

/* Status badges */
.badge {
    display: inline-block;
    padding: 0.15rem 0.6rem;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
}

.badge-success { background: rgba(63,185,80,0.15); color: var(--accent-green); }
.badge-failed  { background: rgba(248,81,73,0.15); color: var(--accent-red); }
.badge-pending { background: rgba(139,148,158,0.15); color: var(--text-secondary); }
.badge-dry-run { background: rgba(88,166,255,0.15); color: var(--accent-blue); }
.badge-skipped { background: rgba(210,153,34,0.15); color: var(--accent-yellow); }

/* Log section */
.log-container {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
    max-height: 400px;
    overflow-y: auto;
    font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    font-size: 0.82rem;
    line-height: 1.8;
}

.log-entry { padding: 0.1rem 0; }
.log-time { color: var(--text-muted); margin-right: 0.5rem; }
.log-info { color: var(--accent-blue); }
.log-warning { color: var(--accent-yellow); }
.log-error { color: var(--accent-red); }
.log-debug { color: var(--text-secondary); }

.empty-state {
    color: var(--text-secondary);
    font-style: italic;
    padding: 1rem;
    text-align: center;
}

footer {
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--text-muted);
    font-size: 0.8rem;
    text-align: center;
}
"""


def _esc(value: Any) -> str:
    """HTML-escape a value."""
    return html.escape(str(value)) if value is not None else ""


def _status_badge(status: str) -> str:
    """Return an HTML badge span for a step status string."""
    css_class = {
        "completed": "badge-success",
        "success": "badge-success",
        "failed": "badge-failed",
        "error": "badge-failed",
        "pending": "badge-pending",
        "dry_run": "badge-dry-run",
        "skipped": "badge-skipped",
    }.get(status, "badge-pending")
    return f'<span class="badge {css_class}">{_esc(status)}</span>'


def _duration_fmt(seconds: float | None) -> str:
    """Format a duration in human-readable form."""
    if seconds is None:
        return "-"
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.0f}s"


def _log_level_class(level: str) -> str:
    """Return a CSS class for a log level string."""
    level_lower = level.lower()
    if level_lower in ("error", "critical"):
        return "log-error"
    if level_lower == "warning":
        return "log-warning"
    if level_lower == "debug":
        return "log-debug"
    return "log-info"


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_summary_section(data: dict[str, Any]) -> str:
    """Build the executive summary cards."""
    execution = data.get("execution", {})
    path_info = data.get("path", {})

    success = execution.get("success", False)
    result_text = "SUCCESS" if success else "FAILED"
    result_class = "success" if success else "failure"

    return f"""\
<div class="summary-grid">
    <div class="card">
        <div class="card-label">Result</div>
        <div class="card-value {result_class}">{result_text}</div>
    </div>
    <div class="card">
        <div class="card-label">Source</div>
        <div class="card-value neutral">{_esc(path_info.get("source", "N/A"))}</div>
    </div>
    <div class="card">
        <div class="card-label">Target</div>
        <div class="card-value neutral">{_esc(path_info.get("target", "N/A"))}</div>
    </div>
    <div class="card">
        <div class="card-label">Mode</div>
        <div class="card-value neutral">{_esc(execution.get("mode", "N/A"))}</div>
    </div>
    <div class="card">
        <div class="card-label">Steps</div>
        <div class="card-value neutral">{_esc(path_info.get("total_steps", "0"))}</div>
    </div>
    <div class="card">
        <div class="card-label">Duration</div>
        <div class="card-value neutral">{_duration_fmt(execution.get("duration_seconds"))}</div>
    </div>
</div>
"""


def _build_steps_section(steps: list[dict[str, Any]]) -> str:
    """Build the step-by-step results table."""
    if not steps:
        return '<div class="empty-state">No step data recorded.</div>'

    rows = []
    for step in steps:
        rows.append(
            f"<tr>"
            f"<td>{_esc(step.get('index', ''))}</td>"
            f"<td>{_esc(step.get('edge_type', ''))}</td>"
            f"<td>{_esc(step.get('source', ''))}</td>"
            f"<td>{_esc(step.get('target', ''))}</td>"
            f"<td>{_status_badge(step.get('status', 'pending'))}</td>"
            f"<td>{_esc(step.get('message', ''))}</td>"
            f"<td>{_duration_fmt(step.get('duration_seconds'))}</td>"
            f"</tr>"
        )

    return f"""\
<table>
    <thead>
        <tr>
            <th>#</th>
            <th>Edge Type</th>
            <th>Source</th>
            <th>Target</th>
            <th>Status</th>
            <th>Message</th>
            <th>Duration</th>
        </tr>
    </thead>
    <tbody>
        {"".join(rows)}
    </tbody>
</table>
"""


def _build_credentials_section(credentials: list[dict[str, Any]]) -> str:
    """Build the captured credentials table."""
    if not credentials:
        return '<div class="empty-state">No credentials captured during this execution.</div>'

    rows = []
    for cred in credentials:
        rows.append(
            f"<tr>"
            f"<td>{_esc(cred.get('username', ''))}</td>"
            f"<td>{_esc(cred.get('domain', ''))}</td>"
            f"<td>{_esc(cred.get('type', ''))}</td>"
            f"<td><code>{_esc(cred.get('value_preview', '***'))}</code></td>"
            f"<td>{_esc(cred.get('obtained_from', ''))}</td>"
            f"<td>{_esc(cred.get('obtained_at', ''))}</td>"
            f"</tr>"
        )

    return f"""\
<table>
    <thead>
        <tr>
            <th>Username</th>
            <th>Domain</th>
            <th>Type</th>
            <th>Value (masked)</th>
            <th>Obtained From</th>
            <th>Obtained At</th>
        </tr>
    </thead>
    <tbody>
        {"".join(rows)}
    </tbody>
</table>
"""


def _build_rollback_section(actions: list[dict[str, Any]]) -> str:
    """Build the rollback actions table."""
    if not actions:
        return '<div class="empty-state">No rollback actions recorded.</div>'

    rows = []
    for action in actions:
        reversible = "Yes" if action.get("reversible", False) else "No"
        executed = "Yes" if action.get("executed", False) else "No"
        rows.append(
            f"<tr>"
            f"<td>{_esc(action.get('step_index', ''))}</td>"
            f"<td>{_esc(action.get('action_type', ''))}</td>"
            f"<td>{_esc(action.get('description', ''))}</td>"
            f"<td>{_esc(action.get('command', ''))}</td>"
            f"<td>{_esc(reversible)}</td>"
            f"<td>{_esc(executed)}</td>"
            f"</tr>"
        )

    return f"""\
<table>
    <thead>
        <tr>
            <th>Step</th>
            <th>Action Type</th>
            <th>Description</th>
            <th>Command</th>
            <th>Reversible</th>
            <th>Executed</th>
        </tr>
    </thead>
    <tbody>
        {"".join(rows)}
    </tbody>
</table>
"""


def _build_messages_section(messages: list[dict[str, Any]]) -> str:
    """Build the execution log/messages section."""
    if not messages:
        return '<div class="empty-state">No log messages recorded.</div>'

    entries = []
    for msg in messages:
        level = msg.get("level", "info")
        css_class = _log_level_class(level)
        timestamp = msg.get("timestamp", "")
        # Trim the timestamp to just time portion if ISO format
        if "T" in str(timestamp):
            timestamp = str(timestamp).split("T")[1][:12]
        text = _esc(msg.get("message", ""))
        entries.append(
            f'<div class="log-entry">'
            f'<span class="log-time">{_esc(timestamp)}</span>'
            f'<span class="{css_class}">[{_esc(level.upper())}]</span> '
            f'{text}'
            f'</div>'
        )

    return f"""\
<div class="log-container">
    {"".join(entries)}
</div>
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_html(report_data: dict[str, Any]) -> str:
    """Render a complete self-contained HTML report from report data.

    Args:
        report_data: Dictionary from ``AttackReport.to_dict()``.

    Returns:
        Complete HTML document as a string.
    """
    execution = report_data.get("execution", {})
    path_info = report_data.get("path", {})
    generated = report_data.get("report_generated", "")
    version = report_data.get("pathstrike_version", "0.1.0")

    source = _esc(path_info.get("source", "unknown"))
    target = _esc(path_info.get("target", "unknown"))
    title = f"PathStrike Report: {source} -> {target}"

    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>{_CSS}</style>
</head>
<body>
<div class="container">
    <h1>PathStrike Attack Report</h1>
    <p class="subtitle">
        Generated: {_esc(generated)} | Version: {_esc(version)}
    </p>

    <h2>Executive Summary</h2>
    {_build_summary_section(report_data)}

    <h2>Step-by-Step Results</h2>
    {_build_steps_section(report_data.get("steps", []))}

    <h2>Credentials Captured</h2>
    {_build_credentials_section(report_data.get("credentials_captured", []))}

    <h2>Rollback Actions</h2>
    {_build_rollback_section(report_data.get("rollback_actions", []))}

    <h2>Execution Log</h2>
    {_build_messages_section(report_data.get("messages", []))}

    <footer>
        PathStrike v{_esc(version)} &mdash; AD Attack Path Automation via BloodHound CE
    </footer>
</div>
</body>
</html>
"""


def export_html(report: Any, output_path: Path) -> None:
    """Write an HTML report to disk.

    Args:
        report: An ``AttackReport`` instance (from ``json_export.py``) with a
            ``to_dict()`` method, or a plain dict of report data.
        output_path: Filesystem path for the output HTML file.
    """
    if hasattr(report, "to_dict"):
        data = report.to_dict()
    else:
        data = report

    html_content = render_html(data)

    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_content, encoding="utf-8")
    logger.info("HTML report saved to %s", path)
