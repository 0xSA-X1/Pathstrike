"""HMAC-SHA256 request signing for BloodHound CE API authentication."""

from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime, timezone


class HMACAuth:
    """Generates HMAC-SHA256 signed headers for BloodHound CE API requests.

    BloodHound CE uses a three-layer HMAC construction:
        1. OperationKey = HMAC-SHA256(token_key_bytes, method + uri_path)
        2. DateKey      = HMAC-SHA256(OperationKey, datetime[:13])
        3. Signature    = base64(HMAC-SHA256(DateKey, body))

    The ``token_key`` provided at init is the API token string as displayed
    by BH CE.  It is used directly as UTF-8 bytes for the HMAC key (it is
    **not** base64-decoded first — this matches the official BH CE SDK).
    """

    def __init__(self, token_id: str, token_key: str) -> None:
        """Initialize with BH CE API token credentials.

        Args:
            token_id: The API token identifier.
            token_key: The API token secret string (used as-is, not decoded).
        """
        self.token_id = token_id
        self._token_key_bytes = token_key.encode("utf-8")

    def sign_request(
        self,
        method: str,
        uri: str,
        body: bytes = b"",
    ) -> dict[str, str]:
        """Produce signed headers for a single API request.

        Args:
            method: HTTP method (GET, POST, etc.).
            uri: The request URI path (e.g. ``/api/v2/graphs/cypher``).
            body: Raw request body bytes; empty for bodiless requests.

        Returns:
            A dict of headers to merge into the outgoing request.
        """
        now = datetime.now(timezone.utc)
        signature = self._compute_signature(method, uri, body, now)
        request_date = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        return {
            "Authorization": f"bhesignature {self.token_id}",
            "RequestDate": request_date,
            "Signature": signature,
            "Content-Type": "application/json",
        }

    def _compute_signature(
        self,
        method: str,
        uri: str,
        body: bytes,
        now: datetime,
    ) -> str:
        """Compute the three-layer HMAC-SHA256 signature.

        Args:
            method: HTTP verb uppercased by caller convention.
            uri: Request URI path component.
            body: Raw body bytes (may be empty).
            now: Current UTC timestamp for the DateKey layer.

        Returns:
            Base64-encoded HMAC signature string.
        """
        # Layer 1: OperationKey
        operation_payload = (method.upper() + uri).encode("utf-8")
        operation_key = hmac.new(
            self._token_key_bytes,
            operation_payload,
            hashlib.sha256,
        ).digest()

        # Layer 2: DateKey  (RFC3339 datetime truncated to first 13 chars = hour precision)
        datetime_str = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        date_payload = datetime_str[:13].encode("utf-8")
        date_key = hmac.new(
            operation_key,
            date_payload,
            hashlib.sha256,
        ).digest()

        # Layer 3: Signature
        raw_signature = hmac.new(
            date_key,
            body if body else b"",
            hashlib.sha256,
        ).digest()

        return base64.b64encode(raw_signature).decode("utf-8")
