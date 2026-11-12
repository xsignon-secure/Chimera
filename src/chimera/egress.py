"""Outbound network guard.

The honeypot must never become a pivot. Every outbound HTTP request goes
through :class:`EgressGuard`, which refuses any host not explicitly on the
allowlist, never follows redirects, and never sends attacker-supplied URLs
anywhere. Container-level network isolation (see ``deploy/``) enforces the
same rule a second time at the network layer.
"""

from __future__ import annotations

from typing import Any

import httpx


class EgressDenied(PermissionError):
    pass


class EgressGuard:
    def __init__(self, allowlist: list[str]) -> None:
        self.allowlist = {h.lower() for h in allowlist}

    def check(self, url: httpx.URL | str) -> None:
        host = (httpx.URL(url).host if isinstance(url, str) else url.host).lower()
        if host not in self.allowlist:
            raise EgressDenied(f"egress to {host!r} blocked: not on allowlist")

    def client(self, timeout: float = 5.0, **kwargs: Any) -> httpx.AsyncClient:
        async def _hook(request: httpx.Request) -> None:
            self.check(request.url)

        return httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,  # ignore ambient proxy variables
            event_hooks={"request": [_hook]},
            **kwargs,
        )
