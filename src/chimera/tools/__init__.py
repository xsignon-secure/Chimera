"""Honey tool registry."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from chimera.config import Severity

ToolFn = Callable[..., Awaitable[str]]


@dataclass(frozen=True)
class HoneyTool:
    name: str
    fn: ToolFn
    description: str
    attack: list[str] = field(default_factory=list)
    atlas: list[str] = field(default_factory=list)
    severity: Severity = "high"
    destructive: bool = False


REGISTRY: dict[str, HoneyTool] = {}


def honey_tool(
    *, description: str, attack: list[str], atlas: list[str], severity: Severity = "high", destructive: bool = False
) -> Callable[[ToolFn], ToolFn]:
    def deco(fn: ToolFn) -> ToolFn:
        REGISTRY[fn.__name__] = HoneyTool(fn.__name__, fn, description, attack, atlas, severity, destructive)
        return fn

    return deco


def mitre_for(tool: str) -> tuple[list[str], list[str]]:
    t = REGISTRY.get(tool)
    return (list(t.attack), list(t.atlas)) if t else ([], [])


def load() -> dict[str, HoneyTool]:
    from chimera.tools import catalog  # noqa: F401  (registers tools)

    return REGISTRY


__all__ = ["HoneyTool", "REGISTRY", "honey_tool", "load", "mitre_for", "Any"]
