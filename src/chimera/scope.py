"""Per-request scope shared between the sensor middleware and honey tools."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from chimera.engine import Engine


@dataclass
class RequestScope:
    engine: Engine
    session_id: str
    source_ip: str
    state: dict[str, Any]
    canary_ids: list[str] = field(default_factory=list)
    extra_urls: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    atlas: list[str] = field(default_factory=list)
    severity_floor: str | None = None
    summary: str | None = None
    persona: str | None = None
    tool_failed: bool = False


_current: ContextVar[RequestScope | None] = ContextVar("chimera_scope", default=None)


def current() -> RequestScope:
    scope = _current.get()
    if scope is None:
        raise RuntimeError("honey tool invoked outside a sensor scope")
    return scope


def set_scope(scope: RequestScope | None) -> object:
    return _current.set(scope)


def reset_scope(token: object) -> None:
    _current.reset(token)  # type: ignore[arg-type]
