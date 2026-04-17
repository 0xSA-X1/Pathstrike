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


# ---------------------------------------------------------------------------
# Faketime fallback — wrap subprocesses when system clock sync isn't possible
# ---------------------------------------------------------------------------

# Module-level prefix consulted by every subprocess wrapper (bloodyAD,
# certipy, impacket, etc.).  Populated by set_faketime_prefix() when
# system clock sync fails and a DC offset has been measured.
_faketime_prefix: list[str] = []


def get_faketime_prefix() -> list[str]:
    """Return the current faketime command prefix, or an empty list.

    Subprocess wrappers prepend this to their argv so every tool run
    happens against a clock matching the Domain Controller, without
    requiring root to change the system clock.
    """
    return list(_faketime_prefix)


def set_faketime_prefix(offset_seconds: float | None) -> bool:
    """Enable (or disable) the faketime prefix.

    Args:
        offset_seconds: Seconds of offset to apply to subprocess clocks
            (positive = shift forward, negative = shift back).
            Pass ``None`` to clear the prefix.

    Returns:
        True if the prefix was set successfully, False if faketime is
        unavailable on PATH (in which case the prefix stays empty).
    """
    global _faketime_prefix

    if offset_seconds is None:
        if _faketime_prefix:
            logger.debug("Clearing faketime prefix")
        _faketime_prefix = []
        return True

    if not shutil.which("faketime"):
        logger.warning(
            "faketime binary not found — install libfaketime "
            "(https://github.com/wolfcw/libfaketime) to let PathStrike "
            "compensate Kerberos clock skew without requiring root"
        )
        _faketime_prefix = []
        return False

    # Faketime supports relative offsets like "+3600s" or "-1h".
    # Round to whole seconds — sub-second precision isn't needed for KRB5.
    seconds = int(round(offset_seconds))
    sign = "+" if seconds >= 0 else "-"
    offset_arg = f"{sign}{abs(seconds)}s"
    _faketime_prefix = ["faketime", offset_arg]
    logger.info(
        "Enabled faketime prefix (%s) — subprocesses will run with clock "
        "offset %ds to match the DC", offset_arg, seconds,
    )
    return True


async def sync_time_with_faketime_fallback(
    dc_host: str,
    dc_fqdn: str | None = None,
    timeout: int = 30,
) -> TimeSyncResult:
    """Sync the system clock, or fall back to faketime wrapping on failure.

    Order:
      1. Try :func:`sync_time` (ntpdate / chronyd / net time / rdate).
         Requires sudo; modifies the real system clock.
      2. If system sync fails: query the DC offset via ``ntpdate -q``
         (non-invasive) and enable the faketime prefix.  Subsequent
         subprocess calls will run with a corrected clock without
         touching the real system clock.

    Returns a TimeSyncResult where ``method="faketime"`` when the
    fallback was used.
    """
    result = await sync_time(dc_host, dc_fqdn, timeout=timeout)
    if result.success:
        # Real clock is good now; make sure we don't also apply faketime.
        set_faketime_prefix(None)
        return result

    logger.info(
        "System clock sync failed (%s); attempting faketime fallback",
        result.message,
    )

    offset = await check_time_offset(dc_host, dc_fqdn, timeout=timeout)
    if offset is None:
        return TimeSyncResult(
            success=False,
            method="none",
            message=(
                f"Could not sync system clock AND could not measure DC offset "
                f"via ntpdate -q.  Original error: {result.message}"
            ),
        )

    if set_faketime_prefix(offset):
        return TimeSyncResult(
            success=True,
            method="faketime",
            message=(
                f"System clock sync failed; wrapping subprocesses with "
                f"faketime to compensate {offset:+.1f}s DC skew (install "
                f"libfaketime if you see errors — see "
                f"https://github.com/wolfcw/libfaketime)"
            ),
            offset_seconds=offset,
        )

    # faketime isn't installed
    return TimeSyncResult(
        success=False,
        method="none",
        message=(
            f"System clock sync failed AND faketime is not installed.  "
            f"DC offset is {offset:+.1f}s.  Install libfaketime or run "
            f"with sudo to enable auto-sync."
        ),
        offset_seconds=offset,
    )


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
