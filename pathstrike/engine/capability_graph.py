"""In-memory capability graph populated by live AD enumeration.

Pathstrike's primary path source is BloodHound CE — a static snapshot
of the AD ACL / relationship graph at ingest time.  Once a campaign
starts exploiting edges, BH's view becomes progressively stale: new
group memberships, newly-granted ACEs, and transitive rights created
by earlier steps are invisible until a fresh SharpHound run + re-ingest.

This module keeps an in-memory supplement to BH CE's graph.  Each time
Pathstrike successfully compromises a principal, the orchestrator
calls into ``tools/live_enum.py`` to enumerate what that principal
(with its *current* group memberships) can now write to or read — and
those discoveries are recorded here as :class:`CapabilityEdge`.

The graph is strictly additive: edges are stored, deduplicated, and
consulted by :meth:`CampaignOrchestrator._discover_reachable_paths`
alongside BH results.  No persistence — the graph lives only for the
duration of one ``pathstrike campaign`` / ``pathstrike auto`` run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable


@dataclass
class CapabilityEdge:
    """A single directed edge discovered via live enumeration.

    Attributes:
        source: Fully-qualified source principal name, upper-cased
            (e.g. ``"ALFRED@TOMBWATCHER.HTB"``).  This is the
            authenticated identity whose effective rights we queried.
        edge_type: The BloodHound-style edge label
            (``"GenericAll"``, ``"GenericWrite"``, ``"ReadGMSAPassword"``,
            ``"WriteDacl"``, ``"RestorableFrom"``, etc.).  Pathstrike
            exploitation handlers key off this string, so values must
            match existing handler edge-type registrations.
        target: Fully-qualified target name, upper-cased.
        discovered_at: UTC timestamp when the edge was observed.  Used
            for debugging / freshness reasoning, not for deduplication.
        source_method: Short tag indicating HOW the edge was discovered
            (``"bloodyad:get-writable"``, ``"ldap:recycle-bin"``, etc.).
            Purely informational.
        properties: Arbitrary per-edge metadata the handler needs at
            exploitation time — e.g. a deleted object's DN, last known
            parent OU, or pre-deletion sAMAccountName.  Excluded from
            dedup identity.
    """

    source: str
    edge_type: str
    target: str
    discovered_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    source_method: str = "unknown"
    properties: dict[str, str] = field(default_factory=dict)


class CapabilityGraph:
    """Deduplicated in-memory directed graph of principal capabilities.

    Not thread-safe.  Intended to be constructed once per campaign run
    and mutated from the orchestrator's single async loop.
    """

    def __init__(self) -> None:
        # Primary store keyed by the (source, edge_type, target) tuple
        # that defines edge identity.  Re-adding an existing edge is a
        # no-op so repeated enumerations don't duplicate.
        self._edges: dict[tuple[str, str, str], CapabilityEdge] = {}

        # Secondary index for fast outbound lookup during discovery.
        self._outbound: dict[str, list[CapabilityEdge]] = {}

    def add_edge(
        self,
        source: str,
        edge_type: str,
        target: str,
        source_method: str = "unknown",
        properties: dict[str, str] | None = None,
    ) -> bool:
        """Record an edge.  Returns ``True`` if it was new, ``False`` if duplicate.

        The edge is keyed by ``(source, edge_type, target)`` so re-adding
        with different ``properties`` is a no-op — mutation is intentional
        here: we want the first-captured properties to win (they reflect
        the state at the moment of discovery).
        """
        src = source.upper()
        tgt = target.upper()
        key = (src, edge_type, tgt)
        if key in self._edges:
            return False
        edge = CapabilityEdge(
            source=src,
            edge_type=edge_type,
            target=tgt,
            source_method=source_method,
            properties=dict(properties or {}),
        )
        self._edges[key] = edge
        self._outbound.setdefault(src, []).append(edge)
        return True

    def add_edges(self, edges: Iterable[CapabilityEdge]) -> int:
        """Bulk-add edges; returns the count of actually-new ones."""
        added = 0
        for e in edges:
            if self.add_edge(e.source, e.edge_type, e.target, e.source_method):
                added += 1
        return added

    def get_outbound(self, source: str) -> list[CapabilityEdge]:
        """Return all recorded outbound edges from *source* (upper-cased)."""
        return list(self._outbound.get(source.upper(), []))

    def has_edge(self, source: str, edge_type: str, target: str) -> bool:
        return (source.upper(), edge_type, target.upper()) in self._edges

    def all_edges(self) -> list[CapabilityEdge]:
        return list(self._edges.values())

    def __len__(self) -> int:
        return len(self._edges)

    def __repr__(self) -> str:
        return f"CapabilityGraph(edges={len(self._edges)})"
