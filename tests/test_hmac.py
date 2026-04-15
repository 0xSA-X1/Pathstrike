"""Tests for BloodHound CE HMAC authentication."""

import pytest
from datetime import datetime, timezone
from pathstrike.bloodhound.hmac_auth import HMACAuth

class TestHMACAuth:
    def setup_method(self):
        # Use a known test key (token_key is used as-is, not base64-decoded)
        self.token_id = "test-token-id"
        self.token_key = "dGVzdC1zZWNyZXQta2V5LXZhbHVl"
        self.auth = HMACAuth(self.token_id, self.token_key)

    def test_sign_request_returns_required_headers(self):
        headers = self.auth.sign_request("POST", "/api/v2/graphs/cypher", b'{"query": "MATCH (n) RETURN n"}')
        assert "Authorization" in headers
        assert "RequestDate" in headers
        assert "Signature" in headers
        assert "Content-Type" in headers

    def test_authorization_header_format(self):
        headers = self.auth.sign_request("GET", "/api/v2/self")
        assert headers["Authorization"].startswith(f"bhesignature {self.token_id}")

    def test_content_type_is_json(self):
        headers = self.auth.sign_request("POST", "/api/v2/graphs/cypher", b'{}')
        assert headers["Content-Type"] == "application/json"

    def test_different_methods_produce_different_signatures(self):
        headers_get = self.auth.sign_request("GET", "/api/v2/self")
        headers_post = self.auth.sign_request("POST", "/api/v2/self", b'{}')
        assert headers_get["Signature"] != headers_post["Signature"]

    def test_different_bodies_produce_different_signatures(self):
        headers1 = self.auth.sign_request("POST", "/api/v2/graphs/cypher", b'{"query": "a"}')
        headers2 = self.auth.sign_request("POST", "/api/v2/graphs/cypher", b'{"query": "b"}')
        assert headers1["Signature"] != headers2["Signature"]

    def test_empty_body_accepted(self):
        headers = self.auth.sign_request("GET", "/api/v2/self")
        assert "Signature" in headers

    def test_request_date_is_rfc3339(self):
        headers = self.auth.sign_request("GET", "/api/v2/self")
        date_str = headers["RequestDate"]
        # Should be parseable as RFC3339
        assert "T" in date_str
