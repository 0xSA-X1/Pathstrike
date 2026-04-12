"""Cypher query builders for BloodHound CE graph traversal.

BH CE does **not** support parameterised Cypher queries, so all values are
inlined into the query string.  Values are escaped with :func:`_escape` to
prevent Cypher injection.
"""

from __future__ import annotations


def _escape(value: str) -> str:
    """Escape a string for safe inline use in a single-quoted Cypher literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def build_shortest_path_query(
    source_name: str,
    target_group: str,
    domain: str,
) -> tuple[str, None]:
    """Build a Cypher shortestPath query from source to target.

    Args:
        source_name: Fully qualified name of the source node (e.g. ``USER@DOMAIN.LOCAL``).
        target_group: Name of the target group (e.g. ``DOMAIN ADMINS@DOMAIN.LOCAL``).
        domain: Domain name used for scoping (currently embedded in target_group).

    Returns:
        Tuple of (cypher_query, None).
    """
    query = (
        f"MATCH p=shortestPath("
        f"(s {{name: '{_escape(source_name)}'}})-[*1..]->(t {{name: '{_escape(target_group)}'}})"
        f") RETURN p"
    )
    return query, None


def build_all_shortest_paths_query(
    source_name: str,
    target_group: str,
    domain: str,
) -> tuple[str, None]:
    """Build a Cypher allShortestPaths query from source to target.

    Returns all equally short paths rather than just one.

    Args:
        source_name: Fully qualified name of the source node.
        target_group: Name of the target group.
        domain: Domain name for scoping.

    Returns:
        Tuple of (cypher_query, None).
    """
    query = (
        f"MATCH p=allShortestPaths("
        f"(s {{name: '{_escape(source_name)}'}})-[*1..]->(t {{name: '{_escape(target_group)}'}})"
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
