"""Async REST client for the BloodHound CE API."""

from __future__ import annotations

import asyncio
import logging
import random
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import httpx

from pathstrike.bloodhound.hmac_auth import HMACAuth
from pathstrike.config import BloodHoundConfig

logger = logging.getLogger("pathstrike")


class BloodHoundClientError(Exception):
    """Raised when a BloodHound API request fails."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"BH API error {status_code}: {detail}")


class BloodHoundClient:
    """HMAC-authenticated async HTTP client for BloodHound Community Edition.

    Use as an async context manager to ensure proper lifecycle of the
    underlying ``httpx.AsyncClient``::

        async with BloodHoundClient.connect(config) as client:
            result = await client.cypher_query("MATCH (n) RETURN n LIMIT 1")
    """

    def __init__(self, config: BloodHoundConfig) -> None:
        self._base_url = config.base_url.rstrip("/")
        self._auth = HMACAuth(token_id=config.token_id, token_key=config.token_key)
        self._client: httpx.AsyncClient | None = None

    @classmethod
    @asynccontextmanager
    async def connect(cls, config: BloodHoundConfig) -> AsyncIterator[BloodHoundClient]:
        """Async context manager that manages the httpx client lifecycle.

        Args:
            config: BloodHound connection configuration.

        Yields:
            A ready-to-use BloodHoundClient instance.
        """
        instance = cls(config)
        instance._client = httpx.AsyncClient(
            base_url=instance._base_url,
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
        )
        try:
            yield instance
        finally:
            await instance._client.aclose()
            instance._client = None

    # ------------------------------------------------------------------
    # Rate-limit retry tunables
    # ------------------------------------------------------------------
    # BH CE returns 429 when its per-IP cypher rate limiter trips.  This
    # is normal during a campaign — every successful compromise fans
    # out into ~50 parallel path-discovery queries from the new owned
    # identity.  Without retry, those queries fail and we miss the
    # next round of attack paths.
    _RATE_LIMIT_MAX_RETRIES: int = 6
    _RATE_LIMIT_BASE_DELAY: float = 0.5   # seconds — first retry wait
    _RATE_LIMIT_MAX_DELAY: float = 30.0   # cap for any single retry

    async def _request(
        self,
        method: str,
        endpoint: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a signed request to the BH CE API.

        Args:
            method: HTTP method.
            endpoint: API endpoint path (e.g. ``/api/v2/graphs/cypher``).
            json_data: Optional JSON body payload.
            params: Optional query parameters.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            BloodHoundClientError: On non-2xx responses (after retry-eligible
                statuses like 429 have exhausted their retry budget).
            RuntimeError: If called outside the async context manager.

        Notes:
            **HTTP 429 (rate-limited) retry**: BH CE's per-IP rate
            limiter trips during the high-fanout discovery phase that
            kicks in after every compromise (round 2 of a campaign
            often issues 50+ parallel cypher queries from a newly
            owned identity).  This method transparently retries those
            with exponential backoff, honouring the ``Retry-After``
            response header when the server provides one.  See
            :attr:`_RATE_LIMIT_MAX_RETRIES` for the budget.
        """
        if self._client is None:
            raise RuntimeError(
                "BloodHoundClient must be used within an async context manager. "
                "Use 'async with BloodHoundClient.connect(config) as client:'"
            )

        # Build the URI for signing (include query string if present)
        uri = endpoint
        body = b""
        if json_data is not None:
            import json as _json

            body = _json.dumps(json_data).encode("utf-8")

        logger.debug("BH API %s %s", method, endpoint)

        response: httpx.Response | None = None
        delay = self._RATE_LIMIT_BASE_DELAY
        for attempt in range(self._RATE_LIMIT_MAX_RETRIES + 1):
            # Re-sign every attempt — the HMAC envelope embeds a fresh
            # timestamp, so reusing headers across retries would risk
            # the server rejecting subsequent attempts as stale.
            headers = self._auth.sign_request(method=method, uri=uri, body=body)

            response = await self._client.request(
                method=method,
                url=endpoint,
                headers=headers,
                content=body if body else None,
                params=params,
            )

            if response.status_code != 429:
                break

            # 429: rate-limited.  Honour ``Retry-After`` if the server
            # provides one (per RFC 7231 it's either a delta-seconds
            # integer or an HTTP-date — BH CE sends the integer form).
            # Otherwise back off exponentially with a small jitter so a
            # batch of concurrent callers don't synchronise on the
            # retry instant.
            if attempt >= self._RATE_LIMIT_MAX_RETRIES:
                # Exhausted — fall through to the error-handling block
                # so the caller sees a 429 BloodHoundClientError.
                break

            retry_after_hdr = response.headers.get("Retry-After")
            wait: float
            if retry_after_hdr is not None:
                try:
                    wait = float(retry_after_hdr)
                except ValueError:
                    wait = delay
            else:
                wait = delay

            wait = min(wait, self._RATE_LIMIT_MAX_DELAY)
            # Add up to 25% jitter so concurrent retriers desync.
            wait = wait + random.uniform(0, wait * 0.25)

            logger.debug(
                "BH API rate-limited (429) on %s %s — retry %d/%d in %.1fs",
                method, endpoint, attempt + 1,
                self._RATE_LIMIT_MAX_RETRIES, wait,
            )

            await asyncio.sleep(wait)
            delay = min(delay * 2, self._RATE_LIMIT_MAX_DELAY)

        # ``response`` is guaranteed non-None: every loop iteration
        # assigns it before any branch that might break.
        assert response is not None

        if response.status_code >= 400:
            detail = response.text[:500]
            # Log level matches severity: 5xx = real server problems;
            # 404 = routine empty-result or missing optional endpoint (callers
            # handle these); 429 = rate-limit exhaustion (worth seeing but
            # we already retried); other 4xx = auth/permission issues
            # worth flagging.
            if response.status_code >= 500:
                log_level = logging.ERROR
            elif response.status_code == 404:
                log_level = logging.DEBUG
            elif response.status_code == 429:
                log_level = logging.WARNING
            else:
                log_level = logging.WARNING
            logger.log(
                log_level,
                "BH API error: %s %s -> %d: %s",
                method,
                endpoint,
                response.status_code,
                detail,
            )
            raise BloodHoundClientError(
                status_code=response.status_code,
                detail=detail,
            )

        return response.json()

    async def cypher_query(
        self,
        query: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a Cypher query against the BH CE graph database.

        Args:
            query: Cypher query string.
            params: Optional parameterized query variables (note: BH CE
                    does not support user-specified parameters, so this
                    should normally be ``None``).

        Returns:
            Raw JSON response from the cypher endpoint.
        """
        payload: dict[str, Any] = {"query": query}
        if params:
            payload["parameters"] = params
        return await self._request("POST", "/api/v2/graphs/cypher", json_data=payload)

    async def get_entity(self, object_id: str) -> dict[str, Any]:
        """Look up a single entity by its object ID.

        Args:
            object_id: The BloodHound objectid of the entity.

        Returns:
            Search results from the BH CE API.
        """
        return await self._request("GET", "/api/v2/search", params={"q": object_id})

    async def check_connection(self) -> bool:
        """Verify connectivity to the BloodHound CE instance."""
        try:
            await self._request("GET", "/api/v2/self")
            return True
        except (BloodHoundClientError, httpx.HTTPError) as exc:
            logger.warning("BH CE connectivity check failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Domain discovery
    # ------------------------------------------------------------------

    async def get_available_domains(self) -> list[dict[str, Any]]:
        """List all AD domains discovered by BloodHound CE.

        Returns:
            List of domain objects with ``name``, ``id``, ``type``, etc.
        """
        response = await self._request("GET", "/api/v2/available-domains")
        return response.get("data", [])

    # ------------------------------------------------------------------
    # Attack path findings (BH CE pre-analyzed)
    # ------------------------------------------------------------------

    async def get_attack_path_types(self) -> list[dict[str, Any]]:
        """List all attack path types recognized by BH CE.

        Returns:
            List of attack path type descriptors.
        """
        response = await self._request("GET", "/api/v2/attack-path-types")
        return response.get("data", [])

    async def get_attack_path_findings(
        self,
        domain_id: str | None = None,
    ) -> dict[str, Any]:
        """Get all pre-analyzed attack path findings.

        Args:
            domain_id: Optional domain SID to scope findings.

        Returns:
            Attack path findings from BH CE's analysis engine.
        """
        if domain_id:
            return await self._request(
                "GET",
                f"/api/v2/domains/{domain_id}/attack-path-findings",
            )
        return await self._request("GET", "/api/v2/attack-paths/details")

    # ------------------------------------------------------------------
    # Entity detail endpoints
    # ------------------------------------------------------------------

    async def get_user(self, object_id: str) -> dict[str, Any]:
        """Get detailed user entity info."""
        return await self._request("GET", f"/api/v2/users/{object_id}")

    async def get_computer(self, object_id: str) -> dict[str, Any]:
        """Get detailed computer entity info."""
        return await self._request("GET", f"/api/v2/computers/{object_id}")

    async def get_group(self, object_id: str) -> dict[str, Any]:
        """Get detailed group entity info."""
        return await self._request("GET", f"/api/v2/groups/{object_id}")

    async def get_domain(self, object_id: str) -> dict[str, Any]:
        """Get detailed domain entity info."""
        return await self._request("GET", f"/api/v2/domains/{object_id}")

    async def get_gpo(self, object_id: str) -> dict[str, Any]:
        """Get detailed GPO entity info."""
        return await self._request("GET", f"/api/v2/gpos/{object_id}")

    async def get_computer_sessions(self, object_id: str) -> dict[str, Any]:
        """Get active sessions on a computer."""
        return await self._request("GET", f"/api/v2/computers/{object_id}/sessions")

    async def get_computer_admins(self, object_id: str) -> dict[str, Any]:
        """Get local admins on a computer."""
        return await self._request("GET", f"/api/v2/computers/{object_id}/admin-users")

    async def get_user_sessions(self, object_id: str) -> dict[str, Any]:
        """Get sessions for a user."""
        return await self._request("GET", f"/api/v2/users/{object_id}/sessions")

    async def get_user_memberships(self, object_id: str) -> dict[str, Any]:
        """Get group memberships for a user."""
        return await self._request("GET", f"/api/v2/users/{object_id}/memberships")

    async def get_user_admin_rights(self, object_id: str) -> dict[str, Any]:
        """Get computers where user has admin rights."""
        return await self._request("GET", f"/api/v2/users/{object_id}/admin-rights")

    async def get_group_members(self, object_id: str) -> dict[str, Any]:
        """Get members of a group."""
        return await self._request("GET", f"/api/v2/groups/{object_id}/members")

    async def get_domain_controllers(self, object_id: str) -> dict[str, Any]:
        """Get domain controllers for a domain."""
        return await self._request("GET", f"/api/v2/domains/{object_id}/controllers")

    # ------------------------------------------------------------------
    # Pathfinding (REST API)
    # ------------------------------------------------------------------

    async def get_shortest_path(
        self,
        start_node: str,
        end_node: str,
    ) -> dict[str, Any]:
        """Get shortest path between two nodes via the REST API.

        Args:
            start_node: Object ID of the start node.
            end_node: Object ID of the end node.

        Returns:
            Path data from BH CE.
        """
        return await self._request(
            "GET",
            "/api/v2/graphs/shortest-path",
            params={"start_node": start_node, "end_node": end_node},
        )

    # ------------------------------------------------------------------
    # Data quality
    # ------------------------------------------------------------------

    async def get_data_quality(self, domain_id: str) -> dict[str, Any]:
        """Get data quality stats for a domain.

        Returns collection freshness, object counts, etc.
        """
        return await self._request(
            "GET",
            f"/api/v2/ad-domains/{domain_id}/data-quality-stats",
        )
