"""Error classification, diagnosis, and retry logic for tool execution failures.

Every tool wrapper returns a standardised result dict with ``success``,
``output``, ``error``, and optionally ``parsed`` keys.  This module inspects
those dicts (plus any raw exception info) to determine:

1. **What went wrong** — categorised into an :class:`ErrorCategory`.
2. **Why it failed** — a human-readable diagnostic message.
3. **What to try next** — an optional :class:`Remediation` action.
4. **Whether to retry** — respecting a configurable :class:`RetryPolicy`.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger("pathstrike.engine.error_handler")


# ---------------------------------------------------------------------------
# Error categories
# ---------------------------------------------------------------------------


class ErrorCategory(StrEnum):
    """Broad classification of tool execution failures."""

    TIME_SKEW = "time_skew"
    AUTH_FAILURE = "auth_failure"
    PERMISSION_DENIED = "permission_denied"
    TOOL_NOT_FOUND = "tool_not_found"
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"
    LDAP_ERROR = "ldap_error"
    KERBEROS_ERROR = "kerberos_error"
    CERTIFICATE_ERROR = "certificate_error"
    TARGET_NOT_FOUND = "target_not_found"
    UNKNOWN = "unknown"


class Remediation(StrEnum):
    """Auto-fixable remediation actions."""

    SYNC_TIME = "sync_time"
    RETRY_PLAIN = "retry_plain"
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    CHECK_TOOL_INSTALLED = "check_tool_installed"
    SKIP = "skip"
    ABORT = "abort"


# ---------------------------------------------------------------------------
# Error diagnosis result
# ---------------------------------------------------------------------------


@dataclass
class ErrorDiagnosis:
    """Result of analysing a tool failure."""

    category: ErrorCategory
    message: str
    raw_error: str
    remediation: Remediation = Remediation.ABORT
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Retry policy
# ---------------------------------------------------------------------------


@dataclass
class RetryPolicy:
    """Configurable retry behaviour for step execution."""

    max_retries: int = 3
    backoff_base: float = 2.0  # seconds — exponential backoff multiplier
    retry_on: frozenset[ErrorCategory] = frozenset(
        {
            ErrorCategory.TIME_SKEW,
            ErrorCategory.TIMEOUT,
            ErrorCategory.NETWORK_ERROR,
            ErrorCategory.KERBEROS_ERROR,
        }
    )


# ---------------------------------------------------------------------------
# Pattern database — maps regex patterns → (category, remediation, retryable)
# ---------------------------------------------------------------------------

# Each tuple: (compiled_regex, ErrorCategory, Remediation, retryable, description)
_ERROR_PATTERNS: list[
    tuple[re.Pattern[str], ErrorCategory, Remediation, bool, str]
] = [
    # ---- Time skew / clock ----
    (
        re.compile(r"KRB_AP_ERR_SKEW", re.IGNORECASE),
        ErrorCategory.TIME_SKEW,
        Remediation.SYNC_TIME,
        True,
        "Kerberos clock skew detected — attacker clock is out of sync with the DC",
    ),
    (
        re.compile(r"Clock skew too great", re.IGNORECASE),
        ErrorCategory.TIME_SKEW,
        Remediation.SYNC_TIME,
        True,
        "Kerberos clock skew too great — time difference exceeds 5 minutes",
    ),
    (
        re.compile(r"KRB_AP_ERR_TKT_NYV", re.IGNORECASE),
        ErrorCategory.TIME_SKEW,
        Remediation.SYNC_TIME,
        True,
        "Ticket not yet valid — clock may be behind the DC",
    ),
    (
        re.compile(r"KRB_AP_ERR_TKT_EXPIRED", re.IGNORECASE),
        ErrorCategory.TIME_SKEW,
        Remediation.SYNC_TIME,
        True,
        "Ticket expired — clock may be ahead of the DC or ticket genuinely expired",
    ),
    (
        re.compile(r"time.?skew", re.IGNORECASE),
        ErrorCategory.TIME_SKEW,
        Remediation.SYNC_TIME,
        True,
        "Generic time skew error detected",
    ),
    # ---- Authentication failures ----
    (
        re.compile(r"KDC_ERR_PREAUTH_FAILED", re.IGNORECASE),
        ErrorCategory.AUTH_FAILURE,
        Remediation.ABORT,
        False,
        "Kerberos pre-authentication failed — bad password or hash",
    ),
    (
        re.compile(r"KDC_ERR_CLIENT_REVOKED", re.IGNORECASE),
        ErrorCategory.AUTH_FAILURE,
        Remediation.ABORT,
        False,
        "Account is locked or disabled",
    ),
    (
        re.compile(r"STATUS_LOGON_FAILURE", re.IGNORECASE),
        ErrorCategory.AUTH_FAILURE,
        Remediation.ABORT,
        False,
        "Authentication failed — invalid credentials",
    ),
    (
        re.compile(r"STATUS_ACCOUNT_DISABLED", re.IGNORECASE),
        ErrorCategory.AUTH_FAILURE,
        Remediation.ABORT,
        False,
        "Target account is disabled",
    ),
    (
        re.compile(r"STATUS_PASSWORD_EXPIRED", re.IGNORECASE),
        ErrorCategory.AUTH_FAILURE,
        Remediation.ABORT,
        False,
        "Password has expired",
    ),
    (
        re.compile(r"LOGON_FAILURE|logon failure", re.IGNORECASE),
        ErrorCategory.AUTH_FAILURE,
        Remediation.ABORT,
        False,
        "Authentication failed — credentials rejected",
    ),
    (
        re.compile(r"\[-\].*Authentication", re.IGNORECASE),
        ErrorCategory.AUTH_FAILURE,
        Remediation.ABORT,
        False,
        "Tool reported authentication failure",
    ),
    # ---- Permission / access denied ----
    (
        re.compile(r"STATUS_ACCESS_DENIED|Access.?denied", re.IGNORECASE),
        ErrorCategory.PERMISSION_DENIED,
        Remediation.ABORT,
        False,
        "Access denied — insufficient privileges",
    ),
    (
        re.compile(r"Insufficient access rights", re.IGNORECASE),
        ErrorCategory.PERMISSION_DENIED,
        Remediation.ABORT,
        False,
        "LDAP insufficient access rights — missing required AD permissions",
    ),
    (
        re.compile(r"LDAP_INSUFFICIENT_ACCESS", re.IGNORECASE),
        ErrorCategory.PERMISSION_DENIED,
        Remediation.ABORT,
        False,
        "LDAP insufficient access rights",
    ),
    # ---- Tool not found ----
    (
        re.compile(r"not found|No such file|FileNotFoundError", re.IGNORECASE),
        ErrorCategory.TOOL_NOT_FOUND,
        Remediation.CHECK_TOOL_INSTALLED,
        False,
        "Tool binary not found on PATH",
    ),
    # ---- Network errors ----
    (
        re.compile(
            r"Connection refused|ECONNREFUSED|ConnectionRefusedError",
            re.IGNORECASE,
        ),
        ErrorCategory.NETWORK_ERROR,
        Remediation.RETRY_WITH_BACKOFF,
        True,
        "Connection refused — host may be down or port blocked",
    ),
    (
        re.compile(
            r"Connection timed out|ETIMEDOUT|TimeoutError",
            re.IGNORECASE,
        ),
        ErrorCategory.NETWORK_ERROR,
        Remediation.RETRY_WITH_BACKOFF,
        True,
        "Connection timed out — network or firewall issue",
    ),
    (
        re.compile(r"Network is unreachable|ENETUNREACH", re.IGNORECASE),
        ErrorCategory.NETWORK_ERROR,
        Remediation.ABORT,
        False,
        "Network unreachable — check routing",
    ),
    (
        re.compile(r"Name or service not known|NXDOMAIN", re.IGNORECASE),
        ErrorCategory.NETWORK_ERROR,
        Remediation.ABORT,
        False,
        "DNS resolution failed — check hostname and /etc/resolv.conf",
    ),
    # ---- Timeout ----
    (
        re.compile(r"timed out after \d+s", re.IGNORECASE),
        ErrorCategory.TIMEOUT,
        Remediation.RETRY_WITH_BACKOFF,
        True,
        "Tool execution exceeded timeout — increase timeout or investigate latency",
    ),
    # ---- Kerberos-specific ----
    (
        re.compile(r"KDC_ERR_S_PRINCIPAL_UNKNOWN", re.IGNORECASE),
        ErrorCategory.KERBEROS_ERROR,
        Remediation.ABORT,
        False,
        "Kerberos SPN not found — target service principal does not exist",
    ),
    (
        re.compile(r"KDC_ERR_C_PRINCIPAL_UNKNOWN", re.IGNORECASE),
        ErrorCategory.KERBEROS_ERROR,
        Remediation.ABORT,
        False,
        "Kerberos client principal not found — user may not exist",
    ),
    (
        re.compile(r"KRB_ERR_GENERIC", re.IGNORECASE),
        ErrorCategory.KERBEROS_ERROR,
        Remediation.RETRY_PLAIN,
        True,
        "Generic Kerberos error — may be transient",
    ),
    # ---- LDAP errors ----
    (
        re.compile(r"LDAP.*(error|fail)", re.IGNORECASE),
        ErrorCategory.LDAP_ERROR,
        Remediation.RETRY_WITH_BACKOFF,
        True,
        "LDAP operation error",
    ),
    (
        re.compile(r"referral|LDAP_REFERRAL", re.IGNORECASE),
        ErrorCategory.LDAP_ERROR,
        Remediation.RETRY_WITH_BACKOFF,
        True,
        "LDAP referral — may need to target correct DC",
    ),
    # ---- Certificate errors ----
    (
        re.compile(r"CERTSRV_E_TEMPLATE_DENIED", re.IGNORECASE),
        ErrorCategory.CERTIFICATE_ERROR,
        Remediation.ABORT,
        False,
        "Certificate template denied — insufficient enrollment permissions",
    ),
    (
        re.compile(r"certificate.*not found|no.+certificate", re.IGNORECASE),
        ErrorCategory.CERTIFICATE_ERROR,
        Remediation.ABORT,
        False,
        "Certificate not found or unavailable",
    ),
    # ---- Target not found ----
    (
        re.compile(r"object.+not found|no.+result|0 result", re.IGNORECASE),
        ErrorCategory.TARGET_NOT_FOUND,
        Remediation.ABORT,
        False,
        "Target AD object not found",
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def diagnose_error(result: dict[str, Any]) -> ErrorDiagnosis:
    """Analyse a tool result dict and return a structured diagnosis.

    The function inspects both ``result["error"]`` and ``result["output"]``
    for known error patterns.

    Args:
        result: Standardised tool result dict with at least ``success``,
            ``output``, and ``error`` keys.

    Returns:
        An :class:`ErrorDiagnosis` with category, message, remediation, etc.
    """
    error_text = result.get("error", "") or ""
    output_text = result.get("output", "") or ""

    # Combine both streams for pattern matching
    combined = f"{error_text}\n{output_text}"

    for pattern, category, remediation, retryable, description in _ERROR_PATTERNS:
        if pattern.search(combined):
            logger.debug(
                "Error classified as %s: %s (pattern: %s)",
                category,
                description,
                pattern.pattern,
            )
            return ErrorDiagnosis(
                category=category,
                message=description,
                raw_error=error_text or output_text[:500],
                remediation=remediation,
                retryable=retryable,
                details={"matched_pattern": pattern.pattern},
            )

    # Fallback — unknown error
    return ErrorDiagnosis(
        category=ErrorCategory.UNKNOWN,
        message="Unrecognised error — review raw output for details",
        raw_error=error_text or output_text[:500],
        remediation=Remediation.ABORT,
        retryable=False,
    )


def is_time_skew_error(result: dict[str, Any]) -> bool:
    """Quick check: does the result indicate a Kerberos clock skew error?

    This is a fast-path used by the orchestrator to trigger automatic
    time synchronisation without full diagnosis overhead.
    """
    combined = f"{result.get('error', '')}\n{result.get('output', '')}"
    return bool(
        re.search(
            r"KRB_AP_ERR_SKEW|Clock skew too great|KRB_AP_ERR_TKT_NYV|time.?skew",
            combined,
            re.IGNORECASE,
        )
    )


def should_retry(
    diagnosis: ErrorDiagnosis,
    attempt: int,
    policy: RetryPolicy,
) -> bool:
    """Determine whether the current step should be retried.

    Args:
        diagnosis: The error diagnosis from the last attempt.
        attempt: Current attempt number (0-indexed).
        policy: The active retry policy.

    Returns:
        ``True`` if another attempt should be made.
    """
    if attempt >= policy.max_retries:
        logger.info(
            "Max retries (%d) reached for %s — giving up",
            policy.max_retries,
            diagnosis.category,
        )
        return False

    if diagnosis.category not in policy.retry_on:
        logger.info(
            "Error category %s is not retryable under current policy",
            diagnosis.category,
        )
        return False

    if not diagnosis.retryable:
        logger.info(
            "Error diagnosis marked as non-retryable: %s", diagnosis.message
        )
        return False

    return True


def get_backoff_seconds(attempt: int, policy: RetryPolicy) -> float:
    """Calculate exponential backoff delay for the given attempt.

    Returns:
        Seconds to wait before the next retry.
    """
    return policy.backoff_base ** attempt
