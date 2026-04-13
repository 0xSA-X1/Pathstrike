"""Cypher query builders for BloodHound CE graph traversal.

BH CE does **not** support parameterised Cypher queries, so all values are
inlined into the query string.  Values are escaped with :func:`_escape` to
prevent Cypher injection.

Relationship traversals are filtered to only the edge types that have
registered handlers, keeping queries fast and results exploitable.
"""

from __future__ import annotations


def _escape(value: str) -> str:
    """Escape a string for safe inline use in a single-quoted Cypher literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _edge_type_filter() -> str:
    """Build a Cypher relationship-type filter from the handler registry.

    Returns a string like ``MemberOf|AdminTo|GenericAll|...`` containing
    every edge type that has a registered handler.  If the registry is
    empty (e.g. during testing), falls back to an unfiltered wildcard.
    """
    from pathstrike.engine.edge_registry import get_supported_edges

    edges = get_supported_edges()
    if not edges:
        return ""
    return ":" + "|".join(edges)


def build_shortest_path_query(
    source_name: str,
    target_group: str,
    domain: str,
) -> tuple[str, None]:
    """Build a Cypher shortestPath query from source to target.

    Only traverses relationship types that have registered handlers.

    Args:
        source_name: Fully qualified name of the source node (e.g. ``USER@DOMAIN.LOCAL``).
        target_group: Name of the target group (e.g. ``DOMAIN ADMINS@DOMAIN.LOCAL``).
        domain: Domain name used for scoping (currently embedded in target_group).

    Returns:
        Tuple of (cypher_query, None).
    """
    edge_filter = _edge_type_filter()
    query = (
        f"MATCH p=shortestPath("
        f"(s {{name: '{_escape(source_name)}'}})-[{edge_filter}*1..]->(t {{name: '{_escape(target_group)}'}})"
        f") RETURN p"
    )
    return query, None


def build_all_shortest_paths_query(
    source_name: str,
    target_group: str,
    domain: str,
) -> tuple[str, None]:
    """Build a Cypher allShortestPaths query from source to target.

    Returns all equally short paths rather than just one.  Only traverses
    relationship types that have registered handlers.

    Args:
        source_name: Fully qualified name of the source node.
        target_group: Name of the target group.
        domain: Domain name for scoping.

    Returns:
        Tuple of (cypher_query, None).
    """
    edge_filter = _edge_type_filter()
    query = (
        f"MATCH p=allShortestPaths("
        f"(s {{name: '{_escape(source_name)}'}})-[{edge_filter}*1..]->(t {{name: '{_escape(target_group)}'}})"
        f") RETURN p"
    )
    return query, None


def build_node_lookup_query(
    name: str,
    domain: str,
) -> tuple[str, None]:
    """Build a Cypher query to find a node by name within a domain.

    Args:
        name: The node name to search for (e.g. ``JSMITH@DOMAIN.LOCAL``).
        domain: Domain name for scoping the lookup.

    Returns:
        Tuple of (cypher_query, None).
    """
    query = (
        f"MATCH (n) "
        f"WHERE n.name = '{_escape(name)}' AND n.domain = '{_escape(domain)}' "
        f"RETURN n"
    )
    return query, None


# ---------------------------------------------------------------------------
# Kerberos attack discovery queries
# ---------------------------------------------------------------------------


def build_kerberoastable_users_query(domain: str) -> tuple[str, None]:
    """Find enabled users with SPNs configured (Kerberoastable).

    Args:
        domain: Domain to scope the search.

    Returns:
        Tuple of (cypher_query, None).
    """
    query = (
        f"MATCH (u:User) "
        f"WHERE u.domain = '{_escape(domain.upper())}' "
        f"AND u.hasspn = true AND u.enabled = true "
        f"RETURN u"
    )
    return query, None


def build_asrep_roastable_users_query(domain: str) -> tuple[str, None]:
    """Find enabled users with DontReqPreauth (AS-REP roastable).

    Args:
        domain: Domain to scope the search.

    Returns:
        Tuple of (cypher_query, None).
    """
    query = (
        f"MATCH (u:User) "
        f"WHERE u.domain = '{_escape(domain.upper())}' "
        f"AND u.dontreqpreauth = true AND u.enabled = true "
        f"RETURN u"
    )
    return query, None


# ---------------------------------------------------------------------------
# Trust enumeration queries
# ---------------------------------------------------------------------------


def build_trust_map_query() -> tuple[str, None]:
    """Find all domain trust relationships in the BH CE graph.

    Returns:
        Tuple of (cypher_query, None).
    """
    query = "MATCH p=(d1:Domain)-[:TrustedBy]->(d2:Domain) RETURN p"
    return query, None
