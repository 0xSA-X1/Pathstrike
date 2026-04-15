"""Automatic Kerberos time synchronisation with the Domain Controller.

Kerberos authentication requires the client clock to be within 5 minutes
of the KDC (Domain Controller).  When PathStrike detects a clock-skew
error (``KRB_AP_ERR_SKEW``, ``Clock skew too great``, etc.), this module
can automatically resync the attacker's system clock.

Supported methods (tried in order):

1. ``ntpdate <dc_host>`` — classic one-shot NTP sync (requires sudo).
2. ``chronyd -q 'server <dc_host> iburst'`` — chrony single query.
3. ``net time set -S <dc_host>`` — Samba net time (less common).
4. ``rdate -n <dc_host>`` — rdate fallback.

References from vault:
  - HackTheWorld/Purple Team/Red Team/Training/OSCP Training/Random Important/Time Skew.md
    → ``sudo ntpdate IP``
  - HackTheWorld/Commands/HackTricks/network-services-pentesting/pentesting-kerberos-88.md
    → ``sudo ntpdate <dc.fqdn> || sudo chronyd -q 'server <dc.fqdn> iburst'``
  - Multiple HTB writeups (Tombwatcher, TheFrizz, Scepter)
    → Always ``sudo ntpdate <dc_fqdn>`` before Kerberos operations.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass

logger = logging.getLogger("pathstrike.engine.time_sync")


@dataclass
class TimeSyncResult:
    """Outcome of a time synchronisation attempt."""

    success: bool
    method: str  # e.g. "ntpdate", "chronyd"
    message: str
    offset_seconds: float | None = None  # detected offset if available


# ---------------------------------------------------------------------------
# Sync methods (tried in priority order)
# ---------------------------------------------------------------------------

_SYNC_METHODS: list[tuple[str, str, list[str]]] = [
    # (display_name, binary_name, arg_template)
    # {host} will be replaced with the DC host/FQDN
    ("ntpdate", "ntpdate", ["sudo", "ntpdate", "{host}"]),
    ("chronyd", "chronyd", ["sudo", "chronyd", "-q", "server {host} iburst"]),
    ("net time", "net", ["sudo", "net", "time", "set", "-S", "{host}"]),
    ("rdate", "rdate", ["sudo", "rdate", "-n", "{host}"]),
]


async def sync_time(
    dc_host: str,
    dc_fqdn: str | None = None,
    timeout: int = 30,
) -> TimeSyncResult:
    """Attempt to synchronise the local clock with the Domain Controller.

    Tries each available sync method in order until one succeeds.

    Args:
        dc_host: Domain Controller IP address.
        dc_fqdn: Domain Controller FQDN (preferred for NTP/Kerberos).
        timeout: Maximum seconds per sync attempt.

    Returns:
        A :class:`TimeSyncResult` indicating success/failure and the method used.
    """
    target = dc_fqdn or dc_host
    errors: list[str] = []

    for display_name, binary, arg_template in _SYNC_METHODS:
        # Check if the binary is available
        if not shutil.which(binary):
            logger.debug("%s binary not found, skipping", binary)
            continue

        # Build the command
        cmd = [
            arg.replace("{host}", target) for arg in arg_template
        ]

        logger.info(
            "Attempting time sync via %s: %s",
            display_name,
            " ".join(cmd),
        )

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

            if proc.returncode == 0:
                offset = _parse_ntpdate_offset(stdout) if display_name == "ntpdate" else None
                msg = (
                    f"Time sync successful via {display_name}"
                    f"{f' (offset: {offset:.3f}s)' if offset is not None else ''}"
                )
                logger.info(msg)
                return TimeSyncResult(
                    success=True,
                    method=display_name,
                    message=msg,
                    offset_seconds=offset,
                )

            error_msg = stderr or stdout or f"exit code {proc.returncode}"
            errors.append(f"{display_name}: {error_msg}")
            logger.warning("%s sync failed: %s", display_name, error_msg)

        except asyncio.TimeoutError:
            errors.append(f"{display_name}: timed out after {timeout}s")
            logger.warning("%s sync timed out", display_name)

        except FileNotFoundError:
            errors.append(f"{display_name}: binary not found")
            logger.debug("%s binary not found at runtime", display_name)

        except OSError as exc:
            errors.append(f"{display_name}: {exc}")
            logger.warning("%s OS error: %s", display_name, exc)

    # All methods failed
    combined_errors = "; ".join(errors) if errors else "No sync tools available"
    return TimeSyncResult(
        success=False,
        method="none",
        message=f"Time sync FAILED — tried all methods. Errors: {combined_errors}",
    )


async def check_time_offset(
    dc_host: str,
    dc_fqdn: str | None = None,
    timeout: int = 10,
) -> float | None:
    """Probe the time offset between this host and the DC without changing anything.

    Uses ``ntpdate -q`` (query-only mode) to measure the offset.

    Returns:
        Offset in seconds (positive = we're ahead), or ``None`` if unable to check.
    """
    target = dc_fqdn or dc_host

    if not shutil.which("ntpdate"):
        logger.debug("ntpdate not available for offset check")
        return None

    try:
        proc = await asyncio.create_subprocess_exec(
            "ntpdate", "-q", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )

        stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
        return _parse_ntpdate_offset(stdout)

    except (asyncio.TimeoutError, FileNotFoundError, OSError) as exc:
        logger.debug("Time offset check failed: %s", exc)
        return None


def _parse_ntpdate_offset(output: str) -> float | None:
    """Extract the time offset from ntpdate output.

    ntpdate output format includes lines like::

        server 10.10.10.10, stratum 3, offset -14402.948451, delay 0.02580
        19 Mar 12:34:56 ntpdate[1234]: adjust time server 10.10.10.10 offset -14402.948451 sec
    """
    import re

    match = re.search(r"offset\s+(-?[\d.]+)", output)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            pass
    return None


async def ensure_time_sync(
    dc_host: str,
    dc_fqdn: str | None = None,
    max_offset: float = 300.0,
    timeout: int = 30,
) -> TimeSyncResult:
    """Check time offset and sync only if needed.

    First queries the offset; if it's within *max_offset* seconds (default
    300s = 5 min, the Kerberos maximum), returns success without syncing.
    Otherwise, performs a full sync.

    Args:
        dc_host: Domain Controller IP.
        dc_fqdn: Domain Controller FQDN.
        max_offset: Maximum acceptable offset in seconds.
        timeout: Timeout per operation.

    Returns:
        TimeSyncResult indicating what happened.
    """
    offset = await check_time_offset(dc_host, dc_fqdn, timeout=timeout)

    if offset is not None and abs(offset) <= max_offset:
        msg = f"Clock offset is {offset:.1f}s — within Kerberos tolerance ({max_offset:.0f}s)"
        logger.info(msg)
        return TimeSyncResult(
            success=True,
            method="check_only",
            message=msg,
            offset_seconds=offset,
        )

    if offset is not None:
        logger.warning(
            "Clock offset is %.1fs — exceeds Kerberos tolerance. Syncing...",
            offset,
        )
    else:
        logger.info("Could not measure offset. Attempting sync proactively...")

    return await sync_time(dc_host, dc_fqdn, timeout=timeout)
