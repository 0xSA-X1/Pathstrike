"""Tests for the error handler / diagnosis engine."""

from __future__ import annotations

import pytest

from pathstrike.engine.error_handler import (
    ErrorCategory,
    ErrorDiagnosis,
    Remediation,
    RetryPolicy,
    diagnose_error,
    get_backoff_seconds,
    is_time_skew_error,
    should_retry,
)


class TestDiagnoseError:
    """Tests for error classification via diagnose_error()."""

    def test_time_skew_detection(self):
        """Clock skew errors should be classified as TIME_SKEW."""
        result = {"success": False, "output": "", "error": "KRB_AP_ERR_SKEW: Clock skew too great"}
        diag = diagnose_error(result)
        assert diag.category == ErrorCategory.TIME_SKEW

    def test_time_skew_variant(self):
        """Various time skew messages should all be detected."""
        variants = [
            "clock skew too great",
            "KRB_AP_ERR_SKEW",
            "KRB_AP_ERR_TKT_NYV",
            "time skew detected",
        ]
        for msg in variants:
            result = {"success": False, "output": "", "error": msg}
            diag = diagnose_error(result)
            assert diag.category == ErrorCategory.TIME_SKEW, f"Failed for: {msg}"

    def test_auth_failure(self):
        """Authentication failures should be classified as AUTH_FAILURE."""
        result = {"success": False, "output": "", "error": "STATUS_LOGON_FAILURE: The user name or password is incorrect"}
        diag = diagnose_error(result)
        assert diag.category == ErrorCategory.AUTH_FAILURE

    def test_permission_denied(self):
        """Access denied errors should be classified as PERMISSION_DENIED."""
        result = {"success": False, "output": "", "error": "STATUS_ACCESS_DENIED"}
        diag = diagnose_error(result)
        assert diag.category == ErrorCategory.PERMISSION_DENIED

    def test_tool_not_found(self):
        """Missing tool errors should be classified as TOOL_NOT_FOUND."""
        result = {
            "success": False, "output": "",
            "error": "secretsdump.py not found. Ensure Impacket is installed and scripts are on PATH.",
        }
        diag = diagnose_error(result)
        assert diag.category == ErrorCategory.TOOL_NOT_FOUND

    def test_network_error(self):
        """Connection errors should be classified as NETWORK_ERROR."""
        result = {"success": False, "output": "", "error": "Connection refused to target host"}
        diag = diagnose_error(result)
        assert diag.category == ErrorCategory.NETWORK_ERROR

    def test_timeout_error(self):
        """Timeout messages should be classified as TIMEOUT."""
        result = {"success": False, "output": "", "error": "secretsdump.py timed out after 120s"}
        diag = diagnose_error(result)
        assert diag.category == ErrorCategory.TIMEOUT

    def test_unknown_error(self):
        """Unrecognized errors should be classified as UNKNOWN."""
        result = {"success": False, "output": "", "error": "Some completely unexpected error XYZ123"}
        diag = diagnose_error(result)
        assert diag.category == ErrorCategory.UNKNOWN

    def test_kerberos_error(self):
        """Kerberos protocol errors should be detected."""
        result = {"success": False, "output": "", "error": "KDC_ERR_PREAUTH_FAILED"}
        diag = diagnose_error(result)
        assert diag.category in (ErrorCategory.KERBEROS_ERROR, ErrorCategory.AUTH_FAILURE)

    def test_ldap_error(self):
        """LDAP errors should be detected."""
        result = {"success": False, "output": "", "error": "LDAP connection failed: Server is unavailable"}
        diag = diagnose_error(result)
        assert diag.category in (ErrorCategory.LDAP_ERROR, ErrorCategory.NETWORK_ERROR)


class TestIsTimeSkewError:
    """Tests for the is_time_skew_error convenience function."""

    def test_detects_skew(self):
        result = {"success": False, "output": "", "error": "KRB_AP_ERR_SKEW"}
        assert is_time_skew_error(result) is True

    def test_non_skew(self):
        result = {"success": False, "output": "", "error": "STATUS_LOGON_FAILURE"}
        assert is_time_skew_error(result) is False

    def test_empty_string(self):
        result = {"success": False, "output": "", "error": ""}
        assert is_time_skew_error(result) is False


class TestRetryPolicy:
    """Tests for RetryPolicy and retry decision logic."""

    def test_default_policy(self):
        """Default policy should allow retries on known transient errors."""
        policy = RetryPolicy()
        assert policy.max_retries >= 1

    def test_should_retry_time_skew(self):
        """TIME_SKEW should be retryable by default."""
        policy = RetryPolicy()
        diag = ErrorDiagnosis(
            category=ErrorCategory.TIME_SKEW,
            message="Clock skew",
            raw_error="KRB_AP_ERR_SKEW",
            remediation=Remediation.SYNC_TIME,
            retryable=True,
        )
        assert should_retry(diag, attempt=0, policy=policy) is True

    def test_should_retry_auth_failure(self):
        """AUTH_FAILURE should NOT be retryable by default."""
        policy = RetryPolicy()
        diag = ErrorDiagnosis(
            category=ErrorCategory.AUTH_FAILURE,
            message="Auth failed",
            raw_error="STATUS_LOGON_FAILURE",
            remediation=Remediation.ABORT,
            retryable=False,
        )
        assert should_retry(diag, attempt=0, policy=policy) is False

    def test_should_retry_exceeded_max(self):
        """Retry should be denied when max_retries is exceeded."""
        policy = RetryPolicy(max_retries=2)
        diag = ErrorDiagnosis(
            category=ErrorCategory.TIME_SKEW,
            message="Clock skew",
            raw_error="KRB_AP_ERR_SKEW",
            remediation=Remediation.SYNC_TIME,
            retryable=True,
        )
        assert should_retry(diag, attempt=2, policy=policy) is False

    def test_should_retry_within_limit(self):
        """Retry should be allowed within max_retries."""
        policy = RetryPolicy(max_retries=3)
        diag = ErrorDiagnosis(
            category=ErrorCategory.TIME_SKEW,
            message="Clock skew",
            raw_error="KRB_AP_ERR_SKEW",
            remediation=Remediation.SYNC_TIME,
            retryable=True,
        )
        assert should_retry(diag, attempt=1, policy=policy) is True


class TestBackoff:
    """Tests for exponential backoff calculation."""

    def test_backoff_increases(self):
        """Backoff time should increase with each attempt."""
        policy = RetryPolicy()
        b0 = get_backoff_seconds(0, policy)
        b1 = get_backoff_seconds(1, policy)
        b2 = get_backoff_seconds(2, policy)
        assert b1 > b0
        assert b2 > b1

    def test_backoff_first_attempt(self):
        """First attempt should have a small backoff."""
        policy = RetryPolicy()
        b = get_backoff_seconds(0, policy)
        assert 0 < b <= 5  # Should be small for first retry

    def test_backoff_positive(self):
        """All backoff values should be positive."""
        policy = RetryPolicy()
        for i in range(5):
            assert get_backoff_seconds(i, policy) > 0
