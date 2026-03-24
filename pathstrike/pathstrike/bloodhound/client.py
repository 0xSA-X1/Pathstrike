"""Async REST client for the BloodHound CE API."""

from __future__ import annotations

import logging
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
            BloodHoundClientError: On non-2xx responses.
            RuntimeError: If called outside the async context manager.
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

        headers = self._auth.sign_request(method=method, uri=uri, body=body)

        logger.debug("BH API %s %s", method, endpoint)

        response = await self._client.request(
            method=method,
            url=endpoint,
            headers=headers,
            content=body if body else None,
            params=params,
        )

        if response.status_code >= 400:
            detail = response.text[:500]
            logger.error(
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
            params: Optional parameterized query variables.

        Returns:
            Raw JSON response from the cypher endpoint.
        """
        payload = {
            "query": query,
            "parameters": params or {},
        }
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
        """Verify connectivity to the BloodHound CE instance.

        Returns:
            True if the API responds successfully.
        """
        try:
            await self._request("GET", "/api/v2/self")
            return True
        except (BloodHoundClientError, httpx.HTTPError) as exc:
            logger.warning("BH CE connectivity check failed: %s", exc)
            return False
