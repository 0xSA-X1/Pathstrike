"""Decorator-based handler registration for BloodHound edge types."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathstrike.handlers.base import BaseEdgeHandler

# Module-level registry mapping edge type strings to handler classes
_REGISTRY: dict[str, type[BaseEdgeHandler]] = {}


def register_handler(*edge_types: str):
    """Class decorator that registers a BaseEdgeHandler subclass for one or more edge types.

    Usage::

        @register_handler("GenericAll", "GenericWrite")
        class GenericAllHandler(BaseEdgeHandler):
            ...

    Args:
        *edge_types: One or more BloodHound edge type strings this handler can exploit.

    Returns:
        The decorated class, unmodified.

    Raises:
        ValueError: If an edge type is already registered to a different handler.
    """

    def decorator(cls: type[BaseEdgeHandler]) -> type[BaseEdgeHandler]:
        for edge_type in edge_types:
            normalized = edge_type.strip()
            if normalized in _REGISTRY and _REGISTRY[normalized] is not cls:
                raise ValueError(
                    f"Edge type '{normalized}' is already registered to "
                    f"{_REGISTRY[normalized].__name__}, cannot re-register to {cls.__name__}"
                )
            _REGISTRY[normalized] = cls
        return cls

    return decorator


def get_handler(edge_type: str) -> type[BaseEdgeHandler] | None:
    """Look up the handler class for a given edge type.

    Args:
        edge_type: BloodHound relationship type string (e.g. ``MemberOf``).

    Returns:
        The registered handler class, or None if no handler is registered.
    """
    return _REGISTRY.get(edge_type)


def list_handlers() -> dict[str, str]:
    """Return a mapping of registered edge types to their handler class names.

    Returns:
        Dict of {edge_type: handler_class_name}.
    """
    return {edge_type: cls.__name__ for edge_type, cls in sorted(_REGISTRY.items())}


def get_supported_edges() -> list[str]:
    """Return a sorted list of all edge types that have registered handlers.

    Returns:
        Sorted list of supported edge type strings.
    """
    return sorted(_REGISTRY.keys())
