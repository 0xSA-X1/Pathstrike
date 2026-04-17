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
    query = "MATCH p=(d1:Domain)-[r]->(d2:Domain) RETURN p"
    return query, None


# ---------------------------------------------------------------------------
# Campaign discovery queries (multi-target)
# ---------------------------------------------------------------------------


def build_high_value_nodes_query(domain: str) -> tuple[str, None]:
    """Find all high-value nodes in a domain (targets for campaign discovery).

    Returns node names with admincount=true, isTierZero=true, or Domain type.

    Args:
        domain: Domain to scope.

    Returns:
        Tuple of (cypher_query, None).
    """
    query = (
        f"MATCH (t) "
        f"WHERE (t.admincount = true OR t.isTierZero = true OR t:Domain) "
        f"AND t.domain = '{_escape(domain.upper())}' "
        f"RETURN t.name AS name, t.objectid AS objectid, labels(t) AS labels"
    )
    return query, None


def build_shortest_path_to_target_query(
    source_name: str,
    target_name: str,
) -> tuple[str, None]:
    """Find the shortest path from source to a specific target.

    Uses the edge-type filter to only traverse exploitable edges.

    Args:
        source_name: Fully qualified source.
        target_name: Fully qualified target.

    Returns:
        Tuple of (cypher_query, None).
    """
    edge_filter = _edge_type_filter()
    query = (
        f"MATCH p=shortestPath("
        f"(s {{name: '{_escape(source_name)}'}})-[{edge_filter}*1..]->(t {{name: '{_escape(target_name)}'}})"
        f") RETURN p"
    )
    return query, None


def build_reachable_target_names_query(
    source_name: str,
    max_depth: int = 10,
) -> tuple[str, None]:
    """Find the NAMES of all reachable User/Group/Computer/Domain targets.

    Returns scalar literals (name/objectid/labels) instead of paths.
    This is the first half of the two-step reachable-targets discovery:
    first enumerate target names here, then call
    :func:`build_shortest_path_to_target_query` per target to get each
    concrete path as a separate Cypher query.

    Why two steps: BH CE's Cypher endpoint returns a single flat graph
    (one ``nodes`` dict + one ``edges`` array) regardless of how many
    paths match.  Individual path grouping is lost, so the parser can't
    reconstruct discrete paths from a ``RETURN p LIMIT 50`` response.
    Doing one-path-per-query sidesteps that entirely.

    Args:
        source_name: Fully qualified source.
        max_depth: Maximum path depth.

    Returns:
        Tuple of (cypher_query, None).
    """
    edge_filter = _edge_type_filter()
    src = _escape(source_name)
    query = (
        f"MATCH (t) "
        f"WHERE (t:Group OR t:Domain OR t:User OR t:Computer) "
        f"AND t.name <> '{src}' "
        f"WITH t "
        f"MATCH p=shortestPath("
        f"(s {{name: '{src}'}})-[{edge_filter}*1..{max_depth}]->(t)"
        f") "
        f"RETURN DISTINCT t.name AS name, t.objectid AS objectid, "
        f"labels(t) AS labels "
        f"LIMIT 50"
    )
    return query, None


def build_reachable_targets_query(
    source_name: str,
    max_depth: int = 10,
) -> tuple[str, None]:
    """Legacy alias — kept for backwards compatibility.

    Returns the same query as :func:`build_reachable_target_names_query`.
    New callers should use the names-only query plus per-target
    shortest-path queries for accurate path reconstruction.
    """
    return build_reachable_target_names_query(source_name, max_depth)


def build_outbound_edges_query(node_name: str) -> tuple[str, None]:
    """Count outbound edges by type for a node (used for dynamic scoring).

    Args:
        node_name: Fully qualified node name.

    Returns:
        Tuple of (cypher_query, None).
    """
    query = (
        f"MATCH (n {{name: '{_escape(node_name)}'}})-[r]->(m) "
        f"RETURN type(r) AS edge_type, count(*) AS cnt"
    )
    return query, None
