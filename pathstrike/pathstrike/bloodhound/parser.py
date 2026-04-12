"""Parse BloodHound CE Cypher API responses into PathStrike domain models."""

from __future__ import annotations

import logging
from typing import Any

from pathstrike.models import AttackPath, EdgeInfo, NodeInfo, PathStep

logger = logging.getLogger("pathstrike")


def parse_cypher_response(response: dict[str, Any]) -> list[AttackPath]:
    """Parse a BH CE cypher endpoint response into AttackPath models.

    The expected response structure from BH CE::

        {
            "data": [
                {
                    "nodes": {
                        "<id>": {"label": "User", "kind": "User", "objectId": "...", "name": "...", ...},
                        ...
                    },
                    "edges": [
                        {"source": "<id>", "target": "<id>", "label": "MemberOf", "kind": "MemberOf", ...},
                        ...
                    ]
                },
                ...
            ]
        }

    Args:
        response: Raw JSON dict from the cypher API call.

    Returns:
        List of parsed AttackPath models (one per path result row).
    """
    raw_data = response.get("data", {})
    if not raw_data:
        logger.warning("Cypher response contained no data rows")
        return []

    # BH CE returns "data" as a single dict (nodes + edges) for path queries,
    # not a list of rows.  Normalise to a list so the rest of the parser works.
    if isinstance(raw_data, dict):
        data_rows: list[dict[str, Any]] = [raw_data]
    elif isinstance(raw_data, list):
        data_rows = raw_data
    else:
        logger.warning("Unexpected data type in cypher response: %s", type(raw_data))
        return []

    paths: list[AttackPath] = []

    for row in data_rows:
        try:
            nodes = _extract_nodes(row)
            edges = _extract_edges(row, nodes)
            built = _build_paths(nodes, edges, row)
            paths.extend(built)
        except (KeyError, ValueError) as exc:
            logger.warning("Failed to parse path row: %s", exc)
            continue

    logger.info("Parsed %d attack path(s) from cypher response", len(paths))
    return paths


def _extract_nodes(data: dict[str, Any]) -> dict[str, NodeInfo]:
    """Extract node information from a single data row.

    Args:
        data: A single element from the ``data`` array.

    Returns:
        Mapping of node ID strings to NodeInfo objects.
    """
    raw_nodes = data.get("nodes", {})
    nodes: dict[str, NodeInfo] = {}

    for node_id, props in raw_nodes.items():
        # BH CE uses "label" or "kind" for the node type
        label = props.get("label", props.get("kind", "Unknown"))
        name = props.get("name", "")
        object_id = props.get("objectId", props.get("objectid", node_id))
        domain = props.get("domain", "")

        # Collect remaining properties
        reserved_keys = {"label", "kind", "name", "objectId", "objectid", "domain"}
        extra_props = {k: v for k, v in props.items() if k not in reserved_keys}

        nodes[node_id] = NodeInfo(
            object_id=str(object_id),
            name=name,
            label=label,
            domain=domain,
            properties=extra_props,
        )

    return nodes


def _extract_edges(
    data: dict[str, Any],
    nodes: dict[str, NodeInfo],
) -> list[EdgeInfo]:
    """Extract edges from a single data row, linking to resolved NodeInfo objects.

    Args:
        data: A single element from the ``data`` array.
        nodes: Pre-resolved mapping of node IDs to NodeInfo.

    Returns:
        Ordered list of EdgeInfo objects.

    Raises:
        KeyError: If an edge references a node ID not found in the nodes map.
    """
    raw_edges = data.get("edges", [])
    edges: list[EdgeInfo] = []

    for edge in raw_edges:
        source_id = str(edge["source"])
        target_id = str(edge["target"])

        if source_id not in nodes:
            logger.warning("Edge references unknown source node: %s", source_id)
            continue
        if target_id not in nodes:
            logger.warning("Edge references unknown target node: %s", target_id)
            continue

        edge_type = edge.get("label", edge.get("kind", "Unknown"))

        reserved_keys = {"source", "target", "label", "kind"}
        extra_props = {k: v for k, v in edge.items() if k not in reserved_keys}

        edges.append(
            EdgeInfo(
                edge_type=edge_type,
                source=nodes[source_id],
                target=nodes[target_id],
                properties=extra_props,
            )
        )

    return edges


def _build_paths(
    nodes: dict[str, NodeInfo],
    edges: list[EdgeInfo],
    data: dict[str, Any],
) -> list[AttackPath]:
    """Assemble parsed nodes and edges into ordered AttackPath models.

    Each data row from BH CE represents one path. The edges are assumed to be
    in traversal order (source -> ... -> target).

    Args:
        nodes: Resolved node map from this row.
        edges: Ordered edge list from this row.
        data: The raw data row (for any additional context).

    Returns:
        A list containing a single AttackPath (one path per row),
        or an empty list if no edges exist.
    """
    if not edges:
        return []

    # The path source is the source of the first edge;
    # the path target is the target of the last edge.
    source = edges[0].source
    target = edges[-1].target

    steps = [
        PathStep(
            index=i,
            edge=edge,
            handler_name=None,
            status="pending",
            result=None,
        )
        for i, edge in enumerate(edges)
    ]

    return [
        AttackPath(
            steps=steps,
            source=source,
            target=target,
        )
    ]
