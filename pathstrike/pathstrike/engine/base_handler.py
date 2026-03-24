"""Backward-compatibility re-export.

The canonical ``BaseEdgeHandler`` lives in :mod:`pathstrike.handlers.base`.
This module simply re-exports it so that any code that references
``pathstrike.engine.base_handler.BaseEdgeHandler`` continues to work.
"""

from pathstrike.handlers.base import BaseEdgeHandler  # noqa: F401

__all__ = ["BaseEdgeHandler"]
