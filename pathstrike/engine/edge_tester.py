"""Reusable core for exercising a single edge handler and collecting structured data.

This backs both ``pathstrike test-edge`` (one edge, pretty-printed) and
``pathstrike test-edges`` (batch runner that writes a JSONL log and updates the
coverage matrix).  The functions here never print or call ``sys.exit`` — they
return plain dicts so callers own presentation and control flow.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pathstrike.config import PathStrikeConfig
from pathstrike.engine.credential_store import CredentialStore
from pathstrike.engine.edge_registry import get_handler
from pathstrike.engine.error_handler import diagnose_error
from pathstrike.models import EdgeInfo, NodeInfo

logger = logging.getLogger("pathstrike.edge_tester")


# Outcome → coverage-matrix status symbol.  ``success`` maps differently for
# live vs dry-run runs, so that mapping lives in :func:`status_symbol`.
OUTCOME_SYMBOLS: dict[str, str] = {
    "failed": "❌",
    "exception": "❌",
    "prereq_failed": "🟡",
    "no_handler": "🚫",
}


def status_symbol(outcome: str, live: bool) -> str:
    """Map a result outcome to the EDGE_STATUS.md status emoji.

    A successful *live* exploit is verified (✅); a successful *dry-run* only
    proves prerequisites + planning, so it stays 🟡 (live not yet confirmed).
    """
    if outcome == "success":
        return "✅" if live else "🟡"
    return OUTCOME_SYMBOLS.get(outcome, "⬜")


async def resolve_node(
    client: Any | None,
    name: str,
    fallback_label: str,
    domain: str,
) -> tuple[NodeInfo, bool]:
    """Resolve a principal name into a full NodeInfo via BloodHound CE.

    Falls back to a synthesised node (empty ``object_id``) when *client* is
    ``None`` or BH cannot resolve the name — so a handler can still be
    exercised when the graph is stale or the node is absent.

    Returns ``(node, resolved)`` where *resolved* is True only when the node
    came from BloodHound.
    """
    if client is not None:
        from pathstrike.bloodhound.cypher import build_node_by_name_query
        from pathstrike.bloodhound.parser import _extract_nodes

        query, _ = build_node_by_name_query(name)
        try:
            resp = await client.cypher_query(query)
            data = resp.get("data", {})
            if isinstance(data, dict):
                nodes = _extract_nodes(data)
                if nodes:
                    return next(iter(nodes.values())), True
        except Exception as exc:  # noqa: BLE001 — best-effort resolution
            logger.debug("Node lookup for %s failed: %s", name, exc)

    return (
        NodeInfo(object_id="", name=name, label=fallback_label, domain=domain, properties={}),
        False,
    )


async def execute_edge_test(
    cfg: PathStrikeConfig,
    client: Any | None,
    cred_store: CredentialStore,
    *,
    edge_type: str,
    target: str,
    source: str | None = None,
    live: bool = False,
    force: bool = False,
    props: dict[str, Any] | None = None,
    source_label: str = "User",
    target_label: str = "Group",
) -> dict[str, Any]:
    """Run prereq + exploit for one edge and return a structured result dict.

    Mirrors what the orchestrator does per step, in isolation.  Never raises
    for handler/exploit failures — those are captured in the returned dict.

    Result schema (all JSON-serialisable)::

        {
          "edge_type", "handler", "timestamp", "mode",
          "source": {"name", "label", "resolved"},
          "target": {"name", "label", "resolved"},
          "properties": {...},
          "prereq_ok", "prereq_msg",
          "exploit_attempted", "success", "result_msg",
          "credentials": [{"username", "domain", "cred_type"}],
          "error_category", "remediation", "retryable", "exception",
          "duration_seconds", "outcome",
        }
    """
    props = props or {}
    src_name = source or f"{cfg.credentials.username}@{cfg.domain.name}".upper()
    started = time.monotonic()

    result: dict[str, Any] = {
        "edge_type": edge_type,
        "handler": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "live" if live else "dry_run",
        "source": {"name": src_name, "label": source_label, "resolved": False},
        "target": {"name": target, "label": target_label, "resolved": False},
        "properties": props,
        "prereq_ok": None,
        "prereq_msg": "",
        "exploit_attempted": False,
        "success": None,
        "result_msg": "",
        "credentials": [],
        "error_category": None,
        "remediation": None,
        "retryable": None,
        "exception": None,
        "duration_seconds": 0.0,
        "outcome": "no_handler",
    }

    handler_cls = get_handler(edge_type)
    if handler_cls is None:
        result["result_msg"] = f"No handler registered for edge type: {edge_type}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result

    result["handler"] = handler_cls.__name__

    # Resolve nodes and build the edge.
    src_node, src_ok = await resolve_node(client, src_name, source_label, cfg.domain.name)
    tgt_node, tgt_ok = await resolve_node(client, target, target_label, cfg.domain.name)
    result["source"] = {"name": src_node.name, "label": src_node.label, "resolved": src_ok}
    result["target"] = {"name": tgt_node.name, "label": tgt_node.label, "resolved": tgt_ok}

    edge = EdgeInfo(edge_type=edge_type, source=src_node, target=tgt_node, properties=props)
    handler = handler_cls(config=cfg, credential_store=cred_store)

    # ---- Prerequisites ----
    try:
        prereq_ok, prereq_msg = await handler.check_prerequisites(edge)
    except Exception as exc:  # noqa: BLE001 — surface a crashing prereq check
        result["exception"] = repr(exc)
        result["result_msg"] = f"check_prerequisites raised: {exc}"
        result["outcome"] = "exception"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        logger.debug("Prereq check raised for %s", edge_type, exc_info=True)
        return result

    result["prereq_ok"] = prereq_ok
    result["prereq_msg"] = prereq_msg

    if not prereq_ok and not force:
        result["outcome"] = "prereq_failed"
        result["result_msg"] = f"Prerequisites not met: {prereq_msg}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result

    # ---- Exploit ----
    result["exploit_attempted"] = True
    try:
        success, result_msg, new_creds = await handler.exploit(edge, dry_run=not live)
    except Exception as exc:  # noqa: BLE001 — capture any handler crash for triage
        result["exception"] = repr(exc)
        result["result_msg"] = f"exploit raised: {exc}"
        result["outcome"] = "exception"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        logger.debug("Exploit raised for %s", edge_type, exc_info=True)
        return result

    result["success"] = success
    result["result_msg"] = result_msg
    result["credentials"] = [
        {"username": c.username, "domain": c.domain, "cred_type": c.cred_type.value}
        for c in new_creds
    ]

    if success:
        result["outcome"] = "success"
    else:
        result["outcome"] = "failed"
        diagnosis = diagnose_error({"success": False, "error": result_msg, "output": result_msg})
        result["error_category"] = diagnosis.category.value
        result["remediation"] = diagnosis.remediation.value
        result["retryable"] = diagnosis.retryable

    result["duration_seconds"] = round(time.monotonic() - started, 3)
    return result


async def emit_edge_commands(
    cfg: PathStrikeConfig,
    client: Any | None,
    cred_store: CredentialStore,
    *,
    edge_type: str,
    target: str,
    source: str | None = None,
    props: dict[str, Any] | None = None,
    source_label: str = "User",
    target_label: str = "Domain",
    redact: bool = False,
) -> dict[str, Any]:
    """Run an edge's ``exploit()`` in emit mode and return the ordered commands.

    Reuses the same node-resolution + handler dispatch as
    :func:`execute_edge_test`, but records each tool command instead of running
    it (see :mod:`pathstrike.engine.command_emitter`).  ``check_prerequisites``
    and ``exploit`` are both run so recon/read commands are captured too; their
    pass/fail is ignored — the goal is the full command sequence.

    Returns ``{"edge_type", "handler", "source", "target", "resolved",
    "commands": [{"tool","line","note"}], "error"}``.
    """
    from pathstrike.engine.command_emitter import emit_mode

    props = props or {}
    src_name = source or f"{cfg.credentials.username}@{cfg.domain.name}".upper()
    out: dict[str, Any] = {
        "edge_type": edge_type, "handler": None, "source": src_name,
        "target": target, "resolved": False, "commands": [], "error": None,
    }

    handler_cls = get_handler(edge_type)
    if handler_cls is None:
        # Case-insensitive fallback so `learn genericall` resolves GenericAll.
        from pathstrike.engine.edge_registry import get_registry

        for name, cls in get_registry().items():
            if name.lower() == edge_type.lower():
                edge_type, handler_cls = name, cls
                break
    out["edge_type"] = edge_type
    if handler_cls is None:
        out["error"] = f"No handler registered for edge type: {edge_type}"
        return out
    out["handler"] = handler_cls.__name__

    src_node, src_ok = await resolve_node(client, src_name, source_label, cfg.domain.name)
    tgt_node, tgt_ok = await resolve_node(client, target, target_label, cfg.domain.name)
    out["source"], out["target"] = src_node.name, tgt_node.name
    out["resolved"] = bool(src_ok or tgt_ok)

    edge = EdgeInfo(edge_type=edge_type, source=src_node, target=tgt_node, properties=props)
    handler = handler_cls(config=cfg, credential_store=cred_store)

    with emit_mode(redact=redact) as em:
        try:
            await handler.check_prerequisites(edge)
        except Exception as exc:  # noqa: BLE001 — best-effort recon capture
            logger.debug("emit: prereq raised for %s: %s", edge_type, exc)
        try:
            await handler.exploit(edge, dry_run=False)
        except Exception as exc:  # noqa: BLE001 — capture what was emitted so far
            out["error"] = f"exploit raised mid-emit: {exc}"
            logger.debug("emit: exploit raised for %s", edge_type, exc_info=True)

    out["commands"] = [
        {"tool": c.tool, "line": c.render(em.redact), "note": c.note, "branch": c.branch}
        for c in em.commands
    ]
    return out


# ---------------------------------------------------------------------------
# Test-plan loading + coverage-matrix updating (used by the batch runner)
# ---------------------------------------------------------------------------

def load_test_plan(path: Path) -> dict[str, Any]:
    """Load a batch test plan from a YAML or JSON file.

    Expected shape::

        revert_cmd: "<shell command to restore the lab snapshot>"   # optional
        revert_settle_seconds: 60                                   # optional
        tests:
          - edge: GenericAll
            target: "DOMAIN ADMINS@NORTH.SEVENKINGDOMS.LOCAL"
            source: null            # optional; defaults to config credential
            live: false             # default false (dry-run)
            destructive: false      # if true, revert_cmd runs before this test
            props: {}               # optional extra edge properties
            source_label: User      # fallback node kind if BH can't resolve
            target_label: Group

    Returns the parsed mapping. Raises ValueError if the structure is invalid.
    """
    import json

    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        import yaml

        data = yaml.safe_load(text)

    if not isinstance(data, dict):
        raise ValueError("Test plan must be a mapping with a 'tests' key.")
    if not isinstance(data.get("tests"), list) or not data["tests"]:
        raise ValueError("Test plan must contain a non-empty 'tests' list.")
    for i, t in enumerate(data["tests"]):
        if not isinstance(t, dict) or "edge" not in t or "target" not in t:
            raise ValueError(f"tests[{i}] must have at least 'edge' and 'target'.")
    return data


def update_matrix_status(
    matrix_path: Path,
    edge_type: str,
    symbol: str,
    date_str: str,
) -> bool:
    """Update the Status + Last-tested cells for *edge_type* in EDGE_STATUS.md.

    Matches the markdown table row whose first cell equals *edge_type* exactly
    and rewrites column 4 (Status) and column 5 (Last tested), preserving the
    Handler / In GOAD? / Notes cells.

    Returns True if a row was updated, False if no matching row was found.
    """
    if not matrix_path.is_file():
        return False

    lines = matrix_path.read_text(encoding="utf-8").splitlines()
    updated = False
    for idx, line in enumerate(lines):
        if not line.lstrip().startswith("|"):
            continue
        parts = line.split("|")
        # A 6-column row produces 8 parts: ['', c1, c2, c3, c4, c5, c6, ''].
        if len(parts) < 8:
            continue
        if parts[1].strip() != edge_type:
            continue
        parts[4] = f" {symbol} "
        parts[5] = f" {date_str} "
        lines[idx] = "|".join(parts)
        updated = True
        break

    if updated:
        matrix_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return updated
