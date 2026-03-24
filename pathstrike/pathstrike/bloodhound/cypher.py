"""Cypher query builders for BloodHound CE graph traversal."""

from __future__ import annotations


def build_shortest_path_query(
    source_name: str,
    target_group: str,
    domain: str,
) -> tuple[str, dict[str, str]]:
    """Build a Cypher shortestPath query from source to target.

    Args:
        source_name: Fully qualified name of the source node (e.g. ``USER@DOMAIN.LOCAL``).
        target_group: Name of the target group (e.g. ``DOMAIN ADMINS@DOMAIN.LOCAL``).
        domain: Domain name used for scoping (currently embedded in target_group).

    Returns:
        Tuple of (cypher_query, parameters) ready for ``BloodHoundClient.cypher_query``.
    """
    query = (
        "MATCH p=shortestPath("
        "(s {name: $source})-[*1..]->(t {name: $target})"
        ") RETURN p"
    )
    params = {
        "source": source_name,
        "target": target_group,
    }
    return query, params


def build_all_shortest_paths_query(
    source_name: str,
    target_group: str,
    domain: str,
) -> tuple[str, dict[str, str]]:
    """Build a Cypher allShortestPaths query from source to target.

    Returns all equally short paths rather than just one.

    Args:
        source_name: Fully qualified name of the source node.
        target_group: Name of the target group.
        domain: Domain name for scoping.

    Returns:
        Tuple of (cypher_query, parameters).
    """
    query = (
        "MATCH p=allShortestPaths("
        "(s {name: $source})-[*1..]->(t {name: $target})"
        ") RETURN p"
    )
    params = {
        "source": source_name,
        "target": target_group,
    }
    return query, params


def build_node_lookup_query(
    name: str,
    domain: str,
) -> tuple[str, dict[str, str]]:
    """Build a Cypher query to find a node by name within a domain.

    Args:
        name: The node name to search for (e.g. ``JSMITH@DOMAIN.LOCAL``).
        domain: Domain name for scoping the lookup.

    Returns:
        Tuple of (cypher_query, parameters).
    """
    query = (
        "MATCH (n) "
        "WHERE n.name = $name AND n.domain = $domain "
        "RETURN n"
    )
    params = {
        "name": name,
        "domain": domain,
    }
    return query, params
