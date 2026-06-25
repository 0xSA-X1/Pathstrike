"""Async wrapper for roadtx (ROADtools) + Microsoft Graph mutations.

Azure/Entra is token-based, not Kerberos/NTLM, so this is the Azure analogue
of the bloodyAD/certipy wrappers: a ``run_roadtx`` core runner that is
emit-aware (``command_emitter``), a ROPC token helper, and a Graph request
helper.  Graph writes go out as HTTP (httpx, already a project dep) but are
still **recorded** so ``learn`` mode emits a runnable ``roadtx graphrequest``
equivalent.

Every public helper returns a standardised result dict::

    {"success": bool, "output": str, "parsed": dict | None,
     "error": str | None, "tool": str, "command": str}

Note: ``roadtx`` lives in the PS_AzureHound venv, not the PathStrike venv, so
callers pass ``roadtx_bin`` (config.azure.roadtx_path) — default ``"roadtx"``
assumes it is on PATH.
"""

from __future__ import annotations

import asyncio
import json
import shlex
from typing import Any

import httpx

from pathstrike.engine.command_emitter import (
    emitting,
    placeholder_result,
    record_command,
)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_SENSITIVE = {"-p", "--password", "--secret", "-d", "--data"}


def _redact_cmd(cmd: list[str]) -> str:
    """Redact sensitive arguments from a command list for logging/learn."""
    out: list[str] = []
    skip = False
    for i, arg in enumerate(cmd):
        if skip:
            out.append("***REDACTED***")
            skip = False
        elif arg in _SENSITIVE and i + 1 < len(cmd):
            out.append(arg)
            skip = True
        else:
            out.append(arg)
    return " ".join(shlex.quote(c) for c in out)


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------


async def run_roadtx(
    args: list[str],
    *,
    roadtx_bin: str = "roadtx",
    timeout: int = 60,
) -> dict[str, Any]:
    """Run a ``roadtx`` subcommand and return a standardised result dict."""
    cmd = [roadtx_bin, *args]

    if record_command("roadtx", cmd, redacted=_redact_cmd(cmd)):
        return placeholder_result("roadtx", cmd, subcommand=args[0] if args else None)

    result: dict[str, Any] = {
        "success": False,
        "output": "",
        "parsed": None,
        "error": None,
        "tool": "roadtx",
        "command": _redact_cmd(cmd),
    }
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        result["output"] = out_b.decode("utf-8", errors="replace").strip()
        result["error"] = err_b.decode("utf-8", errors="replace").strip() or None
        result["return_code"] = proc.returncode
        result["success"] = proc.returncode == 0
    except asyncio.TimeoutError:
        result["error"] = f"roadtx timed out after {timeout}s"
        result["error_type"] = "timeout"
    except FileNotFoundError:
        result["error"] = (
            f"roadtx binary '{roadtx_bin}' not found — set config.azure.roadtx_path "
            "to the PS_AzureHound venv's roadtx, or add it to PATH."
        )
        result["error_type"] = "tool_not_found"
    except OSError as exc:
        result["error"] = f"OS error launching roadtx: {exc}"
        result["error_type"] = "os_error"
    return result


# ---------------------------------------------------------------------------
# Authentication: ROPC username/password -> MS Graph access token
# ---------------------------------------------------------------------------


async def get_graph_token(
    *,
    auth_mode: str = "ropc",
    username: str | None = None,
    password: str | None = None,
    tenant: str | None = None,
    client_id: str | None = None,
    roadtx_bin: str = "roadtx",
    token_file: str = ".roadtools_auth",
) -> str | None:
    """Acquire an MS Graph access token via roadtx.

    ``auth_mode``:
      * ``"ropc"`` — username/password (fails under MFA / Conditional Access).
      * ``"refresh"`` — redeem the refresh token cached in *token_file* (seeded
        once via an interactive ``roadtx gettokens --device-code`` login). Works
        with MFA and stays non-interactive for ``campaign``.

    Returns the access token string, a placeholder while emitting, or ``None``
    on failure. ``-r msgraph`` is the alias for ``https://graph.microsoft.com``.
    """
    if auth_mode == "refresh":
        args = ["gettokens", "--refresh-token", "file", "-r", "msgraph",
                "--tokenfile", token_file]
    else:  # ropc
        args = ["gettokens", "-u", f"{username}@{tenant}", "-p", password or "",
                "-r", "msgraph", "--tokenfile", token_file]
    if client_id:
        args += ["-c", client_id]

    res = await run_roadtx(args, roadtx_bin=roadtx_bin)
    # In emit/learn mode the subprocess never ran; keep the chain going so the
    # subsequent Graph commands are emitted too.
    if res.get("emitted"):
        return "<GRAPH_ACCESS_TOKEN>"
    if not res.get("success"):
        return None
    try:
        with open(token_file, encoding="utf-8") as fh:
            return json.load(fh).get("accessToken")
    except (OSError, KeyError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Microsoft Graph request helper
# ---------------------------------------------------------------------------


async def graph_request(
    method: str,
    path: str,
    token: str,
    *,
    body: dict[str, Any] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Make an MS Graph call. *path* is appended to ``GRAPH_BASE``.

    Records an equivalent ``roadtx graphrequest`` invocation so ``learn`` mode
    emits a runnable command instead of an opaque HTTP call.
    """
    # roadtx graphrequest takes the URL as a positional arg (after options).
    learn_argv = ["roadtx", "graphrequest", "-m", method]
    if body is not None:
        learn_argv += ["-d", json.dumps(body)]
    learn_argv.append(f"{GRAPH_BASE}{path}")

    if record_command("roadtx", learn_argv, redacted=" ".join(learn_argv)):
        return placeholder_result("roadtx", learn_argv, subcommand="graphrequest")

    result: dict[str, Any] = {
        "success": False,
        "output": "",
        "parsed": None,
        "error": None,
        "tool": "roadtx+graph",
        "command": f"{method} {GRAPH_BASE}{path}",
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.request(
                method,
                f"{GRAPH_BASE}{path}",
                headers={"Authorization": f"Bearer {token}"},
                json=body,
            )
        result["status"] = resp.status_code
        result["output"] = resp.text
        result["parsed"] = resp.json() if resp.content else None
        result["success"] = resp.status_code < 300
        if not result["success"]:
            result["error"] = resp.text[:300]
    except httpx.HTTPError as exc:
        result["error"] = f"Graph request error: {exc}"
    return result
